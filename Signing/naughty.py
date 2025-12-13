import socket
import argparse
from threading import Thread, Event, Lock
import json
import base64

MAX_FRAME_SIZE = 1_048_576

def safe_close(sock):
    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except:
        pass
    try:
        if sock:
            sock.close()
    except:
        pass

def send_frame(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    if length == 0 or length > MAX_FRAME_SIZE:
        return None
    return recv_exact(sock, length)

def attack_process(data: bytes, direction: str, state, is_handshake: bool):
    """
    mode:
        '0' = do nothing (just forward)
        '1' = try to read (but cannot decrypt, only see ciphertext)
        '2' = tamper with ciphertext (should break integrity)
        '3' = drop messages
    """
    with state['lock']:
        mode = state['mode']

    if is_handshake:
        # Key exchange frames: always forward untouched
        print(f"[{direction}] Handshake frame ({len(data)} bytes) forwarded.")
        return data, False

    if mode == '0':
        # Do nothing: transparent forwarding
        print(f"[{direction}] FORWARD only ({len(data)} bytes).")
        return data, False

    if mode == '1':
        # Eavesdrop attempt (cannot decrypt)
        try:
            obj = json.loads(data.decode())
            c_bytes = base64.b64decode(obj.get('c', b''))
            print(f"[{direction}] EAVESDROP attempt:")
            print(f"    Ciphertext length: {len(c_bytes)} bytes")
            print(f"    Ciphertext (first 32 bytes b64): {base64.b64encode(c_bytes[:32]).decode()}")
        except Exception:
            print(f"[{direction}] EAVESDROP: non-JSON data ({len(data)} bytes), cannot parse.")
        return data, False

    if mode == '2':
        # Tamper: flip one bit in ciphertext to break integrity
        try:
            obj = json.loads(data.decode())
            c_bytes = bytearray(base64.b64decode(obj['c']))
            if c_bytes:
                c_bytes[0] ^= 0x01  # flip 1 bit
            obj['c'] = base64.b64encode(bytes(c_bytes)).decode()
            tampered = json.dumps(obj).encode()
            print(f"[{direction}] TAMPER: modified ciphertext; receiver should fail decryption/verification.")
            return tampered, False
        except Exception:
            # Fallback: flip a byte in raw data
            if data:
                b = bytearray(data)
                b[0] ^= 0x01
                print(f"[{direction}] TAMPER: raw flip on non-JSON data.")
                return bytes(b), False
            return data, False

    if mode == '3':
        # Drop message
        print(f"[{direction}] DROP: dropping message ({len(data)} bytes).")
        return data, True

    # Unknown mode -> just forward
    return data, False

def pump(src_sock, dst_sock, stop: Event, direction: str, state, handshake_done_evt: Event):
    while not stop.is_set():
        try:
            frame = recv_frame(src_sock)
            if not frame:
                print(f"[{direction}] peer disconnected")
                stop.set()
                break

            # Count frames to detect when key exchange is done (2 frames total: server pubkey + client pubkey)
            with state['lock']:
                is_handshake = state['frames_forwarded'] < 2
                if is_handshake:
                    state['frames_forwarded'] += 1
                    if state['frames_forwarded'] == 2:
                        # Key exchange completed
                        handshake_done_evt.set()

            frame_to_send, should_drop = attack_process(frame, direction, state, is_handshake)

            if should_drop:
                continue

            send_frame(dst_sock, frame_to_send)

        except Exception as e:
            print(f"[{direction}] error: {e}")
            stop.set()
            break

def main():
    parser = argparse.ArgumentParser(description="Passive MITM attacker between client and server.")
    parser.add_argument("--server-host", default="127.0.0.1", help="Real server host")
    parser.add_argument("--server-port", type=int, default=8000, help="Real server port")
    parser.add_argument("--listen-host", default="127.0.0.1", help="Host to listen for client")
    parser.add_argument("--listen-port", type=int, default=9000, help="Port to listen for client")
    args = parser.parse_args()

    # Shared state for both directions
    state = {
        'mode': '0',                 # start in "do nothing" mode
        'frames_forwarded': 0,       # count total frames (for key exchange detection)
        'lock': Lock(),
    }
    handshake_done = Event()

    print("=== Naughty MITM ===")
    print("[SETUP] Connecting to real server (will transparently forward key exchange)...")
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.connect((args.server_host, args.server_port))

    print(f"[SETUP] Listening for client on {args.listen_host}:{args.listen_port} ...")
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((args.listen_host, args.listen_port))
    listen_sock.listen(1)
    client_sock, client_addr = listen_sock.accept()
    print(f"[SETUP] Client connected from {client_addr}.")

    print("\n[INFO] Letting REAL server and REAL client exchange their public keys end-to-end.")
    print("       First 2 frames (key exchange) are only forwarded, not modified.\n")

    stop = Event()

    # Start bidirectional pumps
    t1 = Thread(
        target=pump,
        args=(client_sock, srv_sock, stop, "CLIENT->SERVER", state, handshake_done),
        daemon=True,
    )
    t2 = Thread(
        target=pump,
        args=(srv_sock, client_sock, stop, "SERVER->CLIENT", state, handshake_done),
        daemon=True,
    )

    t1.start()
    t2.start()

    # Wait until key exchange is done, then ask what to do
    handshake_done.wait()
    print("\n[INFO] Key exchange between server and client is complete.")
    print("       Now choose how naughty.py will behave for APPLICATION messages:\n")
    print("  0) Do nothing (just forward messages)")
    print("  1) Try to read messages (will only see ciphertext)")
    print("  2) Tamper with messages (should cause integrity/decryption failures)")
    print("  3) Drop messages (simple DoS demo)")
    choice = input("Select [0/1/2/3]: ").strip()
    if choice not in {"0", "1", "2", "3"}:
        print("Invalid choice, defaulting to '0' (do nothing).")
        choice = "0"

    with state['lock']:
        state['mode'] = choice

    print(f"\n[INFO] MITM active in mode {choice}. Start typing messages in client/server terminals.\n")

    try:
        while not stop.is_set():
            t1.join(timeout=0.5)
            t2.join(timeout=0.5)
            if not t1.is_alive() or not t2.is_alive():
                stop.set()
    finally:
        safe_close(client_sock)
        safe_close(srv_sock)
        safe_close(listen_sock)
        print("[INFO] MITM stopped.")

if __name__ == "__main__":
    main()