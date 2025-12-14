import socket
import argparse
from threading import Thread, Event
import os, json, base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

MAX_FRAME_SIZE = 1_048_576
SIGNED_TAG = ' [S]'

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

# [DEFENSE NOTE]: Confidentiality
# Uses AES-256 with the pre-shared 'session_key'.
# Much faster than RSA, preventing DoS attacks on the CPU.
def encrypt_payload(session_key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    obj = {
        'i': base64.b64encode(iv).decode(),
        'c': base64.b64encode(ciphertext).decode()
    }
    return json.dumps(obj).encode()

def decrypt_payload(session_key: bytes, data_bytes: bytes) -> bytes:
    obj = json.loads(data_bytes.decode())
    iv = base64.b64decode(obj['i'])
    ciphertext = base64.b64decode(obj['c'])
    
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def key_fingerprint(public_key) -> bytes:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()

# [DEFENSE NOTE]: Integrity
# The signature ensures the encrypted payload has not been modified.
def build_signed_message(text: str, signer, intended_recipient_key, session_key) -> bytes:
    plaintext = text.encode('utf-8')
    enc_blob = encrypt_payload(session_key, plaintext)
    
    signature_input = key_fingerprint(intended_recipient_key) + enc_blob
    signature = signer.sign(
        signature_input,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        SHA256()
    )
    return json.dumps({
        'enc': base64.b64encode(enc_blob).decode(),
        'sig': base64.b64encode(signature).decode()
    }).encode()

def unwrap_signed_message(data: bytes, peer_public_key, private_key, session_key) -> str:
    obj = json.loads(data.decode())
    enc_b64 = obj.get('enc')
    sig_b64 = obj.get('sig')
    
    if not enc_b64 or not sig_b64:
        raise ValueError('Missing signed ciphertext bundle')
    
    enc_blob = base64.b64decode(enc_b64)
    signature = base64.b64decode(sig_b64)
    
    signature_input = key_fingerprint(private_key.public_key()) + enc_blob
    try:
        peer_public_key.verify(
            signature,
            signature_input,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(algorithm=SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            SHA256()
        )
    except Exception as exc:
        raise ValueError('Signature verification failed') from exc
        
    plaintext = decrypt_payload(session_key, enc_blob)
    return plaintext.decode(errors='ignore')

def receiver(sock, stop, private_key, peer_public_key, session_key):
    while not stop.is_set():
        try:
            frame = recv_frame(sock)
            if not frame:
                print('Server disconnected. Closing...')
                stop.set()
                break
            try:
                text = unwrap_signed_message(frame, peer_public_key, private_key, session_key)
            except ValueError:
                print('Signature verification failed!')
                stop.set()
                break
            except Exception:
                print('Decryption failed.')
                stop.set()
                break
            
            if text.strip().lower() == 'exit':
                print('Server ended chat.')
                stop.set()
                break
            
            print(f'\nMessage Received{SIGNED_TAG}: {text}')
        except Exception:
            stop.set()
            break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((args.host, args.port))
    except Exception as e:
        print(f'Connect failed: {e}')
        raise SystemExit(1)
    
    print(f'Connected to {args.host}:{args.port}')
    stop = Event()

    # 1. Identity Setup
    client_priv = generate_rsa_keypair()
    client_pub = client_priv.public_key()

    # 2. Public Key Exchange
    server_pub_pem = recv_frame(s)
    if not server_pub_pem:
        safe_close(s)
        raise SystemExit(1)
    server_pub = load_public_key(server_pub_pem)
    send_frame(s, serialize_public_key(client_pub))

    # 3. [DEFENSE NOTE]: Session Handshake (Client Side)
    # The CLIENT generates the random session key.
    print("Generating Session Key...")
    session_key = os.urandom(32) # AES-256 Key

    # Encrypt Session Key with Server's RSA Public Key (Hybrid Encryption)
    enc_session_key = server_pub.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    # Send it to the server
    send_frame(s, enc_session_key)
    print("Session Key Sent. Secure Channel Ready.")

    # 4. Start Chat
    rcv = Thread(target=receiver, args=(s, stop, client_priv, server_pub, session_key), daemon=True)
    rcv.start()

    while not stop.is_set():
        try:
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                try:
                    send_frame(s, build_signed_message(msg, client_priv, server_pub, session_key))
                except Exception:
                    pass
                stop.set()
                break
            send_frame(s, build_signed_message(msg, client_priv, server_pub, session_key))
        except Exception:
            stop.set()
            break

    rcv.join(timeout=1)
    safe_close(s)