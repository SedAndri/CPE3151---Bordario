import socket
import argparse
from threading import Thread, Event
import os, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FRAME_SIZE = 1_048_576  # 1 MB cap; adjust as needed

def safe_close(sock):
    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        if sock:
            sock.close()
    except Exception:
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
    # Treat zero-length or oversized frames as invalid
    if length == 0 or length > MAX_FRAME_SIZE:
        return None
    return recv_exact(sock, length)

def generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def serialize_public_key(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

def encrypt_payload(peer_public_key, plaintext: bytes) -> bytes:
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    enc_key = peer_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    obj = {
        'k': base64.b64encode(enc_key).decode(),
        'n': base64.b64encode(nonce).decode(),
        'c': base64.b64encode(ciphertext).decode()
    }
    return json.dumps(obj).encode()

def decrypt_payload(private_key, data_bytes: bytes) -> bytes:
    obj = json.loads(data_bytes.decode())
    enc_key = base64.b64decode(obj['k'])
    nonce = base64.b64decode(obj['n'])
    ciphertext = base64.b64decode(obj['c'])
    aes_key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def receiveMsg(conn, stop, private_key):
    while not stop.is_set():
        try:
            frame = recv_frame(conn)
            if not frame:
                print('Peer disconnected or sent invalid frame. Closing server...')
                stop.set()
                break
            try:
                text = decrypt_payload(private_key, frame).decode(errors='ignore')
            except Exception:
                print('Decryption failed. Closing server...')
                stop.set()
                break
            if text.strip().lower() == 'exit':
                print('Peer requested to end chat. Closing server...')
                stop.set()
                break
            print(f'\nMessage Received: {text}')
        except Exception:
            stop.set()
            break
    safe_close(conn)

def sendMessage(conn, stop, peer_public_key):
    while not stop.is_set():
        try:
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                try:
                    send_frame(conn, encrypt_payload(peer_public_key, msg.encode()))
                except Exception:
                    pass
                stop.set()
                break
            send_frame(conn, encrypt_payload(peer_public_key, msg.encode()))
        except Exception:
            stop.set()
            break

def listenConnection(host='127.0.0.1', port=8000):
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
    parser.add_argument('--host', default='127.0.0.1', help='Host/IP to bind (use 127.0.0.1 for local-only)')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    args = parser.parse_args()

    stop = Event()
    srv_sock = None
    conn = None
    try:
        conn, addr, srv_sock = listenConnection(args.host, args.port)
        # RSA keypair and public key exchange (server sends first)
        server_priv = generate_rsa_keypair()
        server_pub = server_priv.public_key()
        send_frame(conn, serialize_public_key(server_pub))
        peer_pub_pem = recv_frame(conn)
        if not peer_pub_pem:
            raise RuntimeError('Key exchange failed (no client public key).')
        peer_pub = load_public_key(peer_pub_pem)
        print('Secure channel established.')
        rcv = Thread(target=receiveMsg, args=(conn, stop, server_priv), daemon=True)
        rcv.start()
        sendMessage(conn, stop, peer_pub)
        rcv.join(timeout=1)
    finally:
        safe_close(conn)
        safe_close(srv_sock)
