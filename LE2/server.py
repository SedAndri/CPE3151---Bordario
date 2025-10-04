# **********************************************************************
# File: server.py
# Authors: Bordario, Sid Andre P., Sasil, Korinne Margaret V.
# Class: CPE 3151
# Group/Schedule: Group 1 Sat 7:30-10:30 AM
# Description: Connects to the server and uses threads for concurrent message sending and receiving. Chat ends when 'exit' or 'quit' is entered.
# **********************************************************************

import socket
import threading


def receive_messages(conn: socket.socket, stop_event: threading.Event):
    """Continuously receive messages from the peer until disconnected or stop requested."""
    while not stop_event.is_set():
        try:
            data = conn.recv(1024)
            if not data:
                print("Peer disconnected.")
                stop_event.set()
                break
            print(f"Client: {data.decode()}")
        except KeyboardInterrupt:
            stop_event.set()
            break
        except OSError:
            
            stop_event.set()
            break


def send_messages(conn: socket.socket, stop_event: threading.Event):
    """Read input from console and send to peer until 'exit' or stop requested."""
    try:
        while not stop_event.is_set():
            msg = input("You: ")
            if msg.strip().lower() in ("exit", "quit"):  # local shutdown command
                stop_event.set()
                break
            if not msg:
                continue
            conn.sendall(msg.encode())
    except KeyboardInterrupt:
        stop_event.set()
    except OSError:
        stop_event.set()


def listen_connection(host: str = "127.0.0.1", port: int = 8000):
    """Bind and listen for a single client connection. Returns (conn, addr, server_socket)."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port} ...")
    conn, addr = server_socket.accept()
    print(f"Accepted connection from {addr[0]}:{addr[1]}")
    return conn, addr, server_socket


if __name__ == "__main__":
    
    conn, addr, server_socket = listen_connection()
    stop_event = threading.Event()

    
    receiver = threading.Thread(target=receive_messages, args=(conn, stop_event), daemon=True)
    receiver.start()

  
    send_messages(conn, stop_event)

   
    try:
        stop_event.set()
        conn.close()
    finally:
        server_socket.close()