import socket                   # Low-level TCP networking
import argparse                 # Command-line argument parsing
from threading import Thread, Event  # Concurrency primitives for receiver/sender
import os, json, base64         # Random bytes, JSON packing, base64 encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  # RSA + OAEP padding
from cryptography.hazmat.primitives import serialization, hashes    # PEM serialization and hashing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM      # Authenticated symmetric cipher (AES-GCM)

MAX_FRAME_SIZE = 1_048_576  # Safety cap for message frames to prevent oversized allocations

def safe_close(sock):
    # Shutdown both directions; ignore errors if already closed
    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    # Close the socket handle safely
    try:
        if sock:
            sock.close()
    except Exception:
        pass

def send_frame(sock, data: bytes):
    # Prefix payload with 4-byte big-endian length for framing
    length = len(data).to_bytes(4, 'big')
    # Send length + data atomically using sendall
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    # Read exactly n bytes from the socket (handling short reads)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            # None indicates socket closed or error
            return None
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock):
    # Read 4-byte length header
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    # Reject zero-length or oversized frames (basic validation)
    if length == 0 or length > MAX_FRAME_SIZE:
        return None
    # Read the exact payload length
    return recv_exact(sock, length)

def generate_rsa_keypair():
    # Create a fresh 2048-bit RSA private key (public exponent 65537)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def serialize_public_key(pub):
    # Convert RSA public key to PEM (SubjectPublicKeyInfo) for wire exchange
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    # Parse a PEM-encoded public key back into an RSA key object
    return serialization.load_pem_public_key(pem_bytes)

def hash_message(data: bytes) -> str:
    # Compute SHA-256 hash and return hex string
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()

def encrypt_payload(peer_public_key, plaintext: bytes) -> bytes:
    # Generate a fresh AES-256 key and 12-byte nonce per message
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    # Encrypt plaintext with AES-GCM (provides confidentiality + integrity)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Compute hash of the plaintext (this will be visible in Wireshark)
    msg_hash = hash_message(plaintext)

    # Encrypt the AES key using the peer’s RSA public key with OAEP + SHA-256
    enc_key = peer_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Package encrypted key (k), nonce (n), ciphertext (c), and hash (h) as base64 JSON
    obj = {
        'k': base64.b64encode(enc_key).decode(),
        'n': base64.b64encode(nonce).decode(),
        'c': base64.b64encode(ciphertext).decode(),
        'h': msg_hash,  # <--- hash in hex, readable in Wireshark
    }
    # Return bytes suitable for framing
    return json.dumps(obj).encode()

def decrypt_payload(private_key, data_bytes: bytes) -> bytes:
    # Parse JSON and base64-decode components
    obj = json.loads(data_bytes.decode())
    enc_key = base64.b64decode(obj['k'])
    nonce = base64.b64decode(obj['n'])
    ciphertext = base64.b64decode(obj['c'])
    # Recover AES key with RSA private key (OAEP + SHA-256)
    aes_key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decrypt ciphertext with AES-GCM (verifies integrity)
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def receiveMsg(conn, stop, private_key):
    # Background thread: receive frames, decrypt, and display messages
    while not stop.is_set():
        try:
            frame = recv_frame(conn)
            if not frame:
                # Invalid frame or peer closed; stop server cleanly
                print('Peer disconnected or sent invalid frame. Closing server...')
                stop.set()
                break
            try:
                # Decrypt message with server private key and decode text
                plaintext = decrypt_payload(private_key, frame)
                msg_hash = hash_message(plaintext)
                text = plaintext.decode(errors='ignore')
                print(f'Message hash (SHA-256): {msg_hash}')
            except Exception:
                # Crypto or format error; terminate for safety
                print('Decryption failed. Closing server...')
                stop.set()
                break
            # Graceful shutdown command from peer
            if text.strip().lower() == 'exit':
                print('Peer requested to end chat. Closing server...')
                stop.set()
                break
            # Show received text
            print(f'\nMessage Received: {text}')
        except Exception:
            # Any unexpected error stops processing
            stop.set()
            break
    # Ensure the connection is closed after loop ends
    safe_close(conn)

def sendMessage(conn, stop, peer_public_key):
    # Main thread: read user input, encrypt with peer public key, send frames
    while not stop.is_set():
        try:
            msg = input('Type Message: ')
            msg_bytes = msg.encode()
            print(f'Message hash (SHA-256): {hash_message(msg_bytes)}')
            if msg.strip().lower() == 'exit':
                # Send exit, then request stop
                try:
                    send_frame(conn, encrypt_payload(peer_public_key, msg_bytes))
                except Exception:
                    pass
                stop.set()
                break
            # Normal message: encrypt and send
            send_frame(conn, encrypt_payload(peer_public_key, msg_bytes))
        except Exception:
            # On I/O or socket error, stop and exit
            stop.set()
            break

def listenConnection(host='127.0.0.1', port=8000):
    # Create TCP socket and allow quick restart (SO_REUSEADDR)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind to host:port and start listening for a single client
    s.bind((host, port))
    print(f'Server listening on {host}:{port} ...')
    s.listen(1)
    # Accept one incoming connection (blocking)
    conn, addr = s.accept()
    print(f'Server accepted client connection from {addr[0]}:{addr[1]}')
    # Return both the connection and the server socket so we can close both later
    return conn, addr, s


if __name__ == '__main__':
    # Parse CLI args for host and port
    parser = argparse.ArgumentParser(description='Simple chat server')
    parser.add_argument('--host', default='127.0.0.1', help='Host/IP to bind (use 127.0.0.1 for local-only)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    args = parser.parse_args()

    stop = Event()    # Shared stop flag for threads and loops
    srv_sock = None   # Server listening socket (to close on exit)
    conn = None       # Client connection socket
    try:
        # Wait for a client to connect
        conn, addr, srv_sock = listenConnection(args.host, args.port)
        # Generate server RSA keypair for this session
        server_priv = generate_rsa_keypair()
        server_pub = server_priv.public_key()
        # Send server public key (PEM) to client for encryption
        send_frame(conn, serialize_public_key(server_pub))
        # Receive client public key (PEM) for return traffic
        peer_pub_pem = recv_frame(conn)
        if not peer_pub_pem:
            # Abort if key exchange fails
            raise RuntimeError('Key exchange failed (no client public key).')
        # Load client public key to encrypt outbound messages
        peer_pub = load_public_key(peer_pub_pem)
        print('Secure channel established.')
        # Start receiver thread that decrypts incoming messages
        rcv = Thread(target=receiveMsg, args=(conn, stop, server_priv), daemon=True)
        rcv.start()
        # Main thread handles user input and sending encrypted messages
        sendMessage(conn, stop, peer_pub)
        # Wait briefly for receiver to finish
        rcv.join(timeout=1)
    finally:
        # Cleanly close sockets on exit
        safe_close(conn)
        safe_close(srv_sock)