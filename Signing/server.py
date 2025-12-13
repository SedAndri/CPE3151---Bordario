import socket
import argparse
from threading import Thread, Event
import os, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FRAME_SIZE = 1_048_576

def safe_close(sock):
    try:
        if sock: sock.shutdown(socket.SHUT_RDWR)
    except: pass
    try:
        if sock: sock.close()
    except: pass

def send_frame(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: return None
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if not hdr: return None
    length = int.from_bytes(hdr, 'big')
    if length == 0 or length > MAX_FRAME_SIZE: return None
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

def encrypt_and_sign(peer_public_key, my_private_key, plaintext: bytes) -> bytes:
    # 1. Sign the message (Integrity + Authentication)
    #    - Hashing is performed inside the sign method (SHA256)
    signature = my_private_key.sign(
        plaintext,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # 2. Encrypt the message (Confidentiality)
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # 3. Encrypt the AES key with Peer's Public Key
    enc_key = peer_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Concatenate/Package everything
    obj = {
        'k': base64.b64encode(enc_key).decode(),
        'n': base64.b64encode(nonce).decode(),
        'c': base64.b64encode(ciphertext).decode(),
        's': base64.b64encode(signature).decode()  # Include the signature
    }
    return json.dumps(obj).encode()

def decrypt_and_verify(my_private_key, peer_public_key, data_bytes: bytes) -> bytes:
    obj = json.loads(data_bytes.decode())
    enc_key = base64.b64decode(obj['k'])
    nonce = base64.b64decode(obj['n'])
    ciphertext = base64.b64decode(obj['c'])
    signature = base64.b64decode(obj['s'])

    # 1. Decrypt AES key
    aes_key = my_private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Decrypt Ciphertext
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # 3. Verify Signature using Peer's Public Key
    try:
        peer_public_key.verify(
            signature,
            plaintext,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("   [Integrity Check: SIGNATURE VALID]")
    except Exception as e:
        print("   [Integrity Check: SIGNATURE INVALID!]")
        raise e  # Reject message if signature fails

    return plaintext

def receiveMsg(conn, stop, my_private_key, peer_public_key):
    while not stop.is_set():
        try:
            frame = recv_frame(conn)
            if not frame:
                print('Peer disconnected.')
                stop.set()
                break
            try:
                # Decrypt AND Verify
                text = decrypt_and_verify(my_private_key, peer_public_key, frame).decode()
            except Exception:
                print('Decryption or Verification failed.')
                stop.set()
                break
            
            if text.strip().lower() == 'exit':
                print('Peer requested exit.')
                stop.set()
                break
            print(f'Message Received: {text}')
        except Exception:
            stop.set()
            break
    safe_close(conn)

def sendMessage(conn, stop, peer_public_key, my_private_key):
    while not stop.is_set():
        try:
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                try:
                    send_frame(conn, encrypt_and_sign(peer_public_key, my_private_key, msg.encode()))
                except: pass
                stop.set()
                break
            # Encrypt AND Sign
            send_frame(conn, encrypt_and_sign(peer_public_key, my_private_key, msg.encode()))
        except Exception:
            stop.set()
            break

def listenConnection(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1)
    print(f'Listening on {host}:{port}...')
    conn, addr = s.accept()
    print(f'Connected: {addr}')
    return conn, s

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()

    stop = Event()
    conn, srv_sock = listenConnection(args.host, args.port)

    # Key Generation
    my_priv = generate_rsa_keypair()
    my_pub = my_priv.public_key()

    # Exchange Keys
    send_frame(conn, serialize_public_key(my_pub))
    peer_pub_pem = recv_frame(conn)
    peer_pub = load_public_key(peer_pub_pem)
    print('Secure channel (Signed & Encrypted) established.')

    rcv = Thread(target=receiveMsg, args=(conn, stop, my_priv, peer_pub), daemon=True)
    rcv.start()
    sendMessage(conn, stop, peer_pub, my_priv)
    
    rcv.join(timeout=1)
    safe_close(conn)
    safe_close(srv_sock)