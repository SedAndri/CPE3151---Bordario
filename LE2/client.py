import socket
import threading


def receive_messages(sock: socket.socket, stop_event: threading.Event):
    """Continuously receive and print messages from server until disconnected or stop requested."""
    while not stop_event.is_set():
        try:
            data = sock.recv(1024)
            if not data:
                print("Server disconnected.")
                stop_event.set()
                break
            print(f"Server: {data.decode()}")
        except KeyboardInterrupt:
            stop_event.set()
            break
        except OSError:
            stop_event.set()
            break


def send_messages(sock: socket.socket, stop_event: threading.Event):
    """Read input from console and send to server until 'exit' or stop requested."""
    try:
        while not stop_event.is_set():
            msg = input("You: ")
            if msg.strip().lower() in ("exit", "quit"):
                stop_event.set()
                break
            if not msg:
                continue
            sock.sendall(msg.encode())
    except KeyboardInterrupt:
        stop_event.set()
    except OSError:
        stop_event.set()


def main():
    
    try:
        server_ip = input("Enter server IP [127.0.0.1]: ").strip() or "127.0.0.1"
        port_input = input("Enter server port [8000]: ").strip()
        server_port = int(port_input) if port_input else 8000
    except ValueError:
        print("Invalid port. Using 8000.")
        server_port = 8000
        server_ip = server_ip if 'server_ip' in locals() and server_ip else "127.0.0.1"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"Connecting to {server_ip}:{server_port} ...")
        sock.connect((server_ip, server_port))
        print("Connected. Type messages and press Enter. Type 'exit' to quit.")
    except OSError as e:
        print(f"Failed to connect: {e}")
        sock.close()
        return

    stop_event = threading.Event()

    
    receiver = threading.Thread(target=receive_messages, args=(sock, stop_event), daemon=True)
    receiver.start()

    send_messages(sock, stop_event)

    
    try:
        stop_event.set()
        sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()