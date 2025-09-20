import socket
import argparse
from threading import Thread

run = True


def receiveMsg(conn):
    global run
    while run:
        try:
            data = conn.recv(1024)
            if not data:
                # Peer closed connection
                print('Peer disconnected. Closing server...')
                run = False
                break
            text = data.decode(errors='ignore')
            if text.strip().lower() == 'exit':
                print("Peer requested to end chat. Closing server...")
                run = False
                break
            print('Message Received: {}'.format(text))

        except socket.error:
            run = False
            break
        except KeyboardInterrupt:
            run = False
            break

    try:
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    conn.close()


def sendMessage(conn):
    global run
    while run:
        try:
            msg = input("Type Message: ")
            if msg.strip().lower() == 'exit':
                # Tell peer we're done
                try:
                    conn.sendall(msg.encode())
                except Exception:
                    pass
                run = False
                break
            conn.sendall(msg.encode())
        except EOFError:
            run = False
            break
        except socket.error:
            run = False
            break
        except KeyboardInterrupt:
            run = False
            break


def listenConnection(host='0.0.0.0', port=8000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow quick restart
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print(f'Server listening on {host}:{port} ...')
    s.listen(1)
    conn, addr = s.accept()
    print(f'Server accepted client connection from {addr[0]}:{addr[1]}')
    return conn, addr, s


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('--host', default='192.168.0.113', help='Host/IP to bind (use 0.0.0.0 to accept from any)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    args = parser.parse_args()

    srv_sock = None
    conn = None
    try:
        conn, addr, srv_sock = listenConnection(args.host, args.port)
        rcv = Thread(target=receiveMsg, args=(conn,), daemon=True)
        rcv.start()
        sendMessage(conn)
        # Wait for receiver thread to finish
        rcv.join(timeout=1)
    finally:
        try:
            if conn:
                conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        try:
            if srv_sock:
                srv_sock.close()
        except Exception:
            pass