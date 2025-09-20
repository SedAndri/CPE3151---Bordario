import socket
from threading import Thread

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8000))
run = True
while run:
    try:
        msg = input("Type Message: ")
        s.sendall(msg.encode())
    except socket.error as err:
        run = False
    except KeyboardInterrupt: 
        run = False

def receiveMsg(conn):
    global run
    while run:
        try:
            data = conn.recv(1024)
            if not data:
                continue
            print('Message Received: {}'.format(data.decode()))

        except socket.error as msg:
            run = False
        except KeyboardInterrupt:
            run = False

    conn.close()
    

def sendMessage(conn):
    global run
    try:
        msg = input("Type Message: ")
        s.sendall(msg.encode())
    except socket.error as err:
        run = False
    except KeyboardInterrupt:
        run = False


def listenConnection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 8000))
    s.listen(1)
    conn, addr = s.accept()
    print('Server accepted client connection...')
    return conn, addr, s


if __name__ == '__main__':
    conn, addr, s = listenConnection()
    rcv = Thread(target=receiveMsg, args=(conn, ))
    rcv.start()
    sendMessage(conn)