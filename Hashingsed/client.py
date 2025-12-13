import socket                           # TCP networking primitives
import argparse                         # Command-line parsing
from threading import Thread, Event     # Concurrency for receive loop
import os                               # Secure random bytes
import json                             # Message packaging
import base64                           # Binary-to-text encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  # RSA + OAEP
from cryptography.hazmat.primitives import serialization, hashes                    # Key (de)serialization + hashing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM                      # AES-GCM (authenticated encryption)

MAX_FRAME_SIZE = 1_048_576  # 1 MB safety cap for inbound frames

def safe_close(sock):
    # Attempt a full shutdown; ignore errors if already closed
    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    # Close the socket handle
    try:
        if sock:
            sock.close()
    except Exception:
        pass

def send_frame(sock, data: bytes):
    # Length-prefix the payload with 4-byte big-endian size for framing
    length = len(data).to_bytes(4, 'big')
    # Send header + payload as one stream
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    # Read exactly n bytes, handling short reads
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            # None indicates remote closed or error
            return None
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock):
    # Read 4-byte length header
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    # Basic validation: reject zero or oversized frames
    if length == 0 or length > MAX_FRAME_SIZE:
        return None
    # Read exactly 'length' bytes of payload
    return recv_exact(sock, length)

def generate_rsa_keypair():
    # Create a 2048-bit RSA private key (public exponent 65537)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def serialize_public_key(pub):
    # Convert public key to PEM (SubjectPublicKeyInfo) for wire exchange
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    # Parse PEM-encoded public key into an RSA key object
    return serialization.load_pem_public_key(pem_bytes)

def hash_message(data: bytes) -> str:
    # Compute SHA-256 hash and return hex string
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()

def encrypt_payload(peer_public_key, plaintext: bytes) -> bytes:
    # Per-message AES-256 key and 12-byte nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    # Encrypt plaintext with AES-GCM (confidentiality + integrity)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Compute hash of the plaintext (this will be visible in Wireshark)
    msg_hash = hash_message(plaintext)

    # Wrap AES key with peer RSA public key using OAEP(SHA-256)
    enc_key = peer_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Package encrypted key(k), nonce(n), ciphertext(c), hash(h) as base64 JSON
    obj = {
        'k': base64.b64encode(enc_key).decode(),
        'n': base64.b64encode(nonce).decode(),
        'c': base64.b64encode(ciphertext).decode(),
        'h': msg_hash,  # <--- hash in hex, readable in Wireshark
    }
    # Return UTF-8 bytes ready for framing
    return json.dumps(obj).encode()

def decrypt_payload(private_key, data_bytes: bytes) -> bytes:
    # Parse JSON and base64-decode parts
    obj = json.loads(data_bytes.decode())
    enc_key = base64.b64decode(obj['k'])
    nonce = base64.b64decode(obj['n'])
    ciphertext = base64.b64decode(obj['c'])
    # Recover AES key using RSA private key (OAEP SHA-256)
    aes_key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decrypt and authenticate with AES-GCM
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def receiver(sock, stop, private_key):
    # Background thread: receive, decrypt, display messages
    while not stop.is_set():
        try:
            frame = recv_frame(sock)
            if not frame:
                # Invalid frame or server closed; stop the client
                print('Server disconnected or sent invalid frame. Closing client...')
                stop.set()
                break
            try:
                # Decrypt and decode message; ignore bad bytes
                plaintext = decrypt_payload(private_key, frame)
                msg_hash = hash_message(plaintext)
                text = plaintext.decode(errors='ignore')
                print(f'Message hash (SHA-256): {msg_hash}')
            except Exception:
                # Crypto or format error; terminate for safety
                print('Decryption failed. Closing client...')
                stop.set()
                break
            # Graceful shutdown command
            if text.strip().lower() == 'exit':
                print('Server requested to end chat. Closing client...')
                stop.set()
                break
            # Show received text
            print(f'\nMessage Received: {text}')
        except Exception:
            # Any unexpected error stops processing
            stop.set()
            break

if __name__ == '__main__':
    # Parse CLI args: host and port to connect
    parser = argparse.ArgumentParser(description='Simple chat client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host/IP to connect to (use 127.0.0.1 for same machine)')
    parser.add_argument('--port', type=int, default=8000, help='Server port to connect to')
    args = parser.parse_args()

    # Create TCP socket and connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = args.host
    port = args.port
    try:
        s.connect((host, port))
    except Exception as e:
        print(f'Failed to connect to {host}:{port} -> {e}')
        safe_close(s)
        raise SystemExit(1)
    print(f'Connected to server at {host}:{port}. Type messages and press Enter. Type "exit" to quit.')
    stop = Event()  # Shared stop flag between threads

    # Key exchange: generate client RSA, receive server PEM, send client PEM
    client_priv = generate_rsa_keypair()
    client_pub = client_priv.public_key()
    server_pub_pem = recv_frame(s)
    if not server_pub_pem:
        print('Failed to receive server public key.')
        safe_close(s)
        raise SystemExit(1)
    server_pub = load_public_key(server_pub_pem)
    send_frame(s, serialize_public_key(client_pub))
    print('Secure channel established.')

    # Start receiver thread; main thread handles user input and sending
    rcv = Thread(target=receiver, args=(s, stop, client_priv), daemon=True)
    rcv.start()

    # Send loop: read input, encrypt with server public key, send frames
    while not stop.is_set():
        try:
            msg = input('Type Message: ')
            msg_bytes = msg.encode()
            print(f'Message hash (SHA-256): {hash_message(msg_bytes)}')
            if msg.strip().lower() == 'exit':
                # Send exit, then stop gracefully
                try:
                    send_frame(s, encrypt_payload(server_pub, msg_bytes))
                except Exception:
                    pass
                stop.set()
                break
            # Normal message: encrypt and send
            send_frame(s, encrypt_payload(server_pub, msg_bytes))
        except Exception:
            # On I/O or socket error, stop and exit
            stop.set()
            break

    # Wait briefly for receiver to finish and close socket
    rcv.join(timeout=1)
    safe_close(s)