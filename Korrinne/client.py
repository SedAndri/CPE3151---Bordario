import socket                           # TCP networking primitives
import argparse                         # Command-line parsing
from threading import Thread, Event     # Concurrency for receive loop
import os                               # Secure random bytes
import json                             # Message packaging
import base64                           # Binary-to-text encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  # RSA + OAEP
from cryptography.hazmat.primitives import serialization                            # Key (de)serialization
from cryptography.hazmat.primitives.hashes import SHA256                            # Hashing (shorter name)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import hashlib                          # Key fingerprinting

MAX_FRAME_SIZE = 1_048_576  # 1 MB safety cap for inbound frames
SIGNED_TAG = ' [S]'        # Indicates a message’s signature verified successfully

def safe_close(sock):
    """Safely shut down and close a socket.

    This helper attempts to fully shut down the given socket and then close it,
    suppressing any exceptions that occur (for example, if the socket is already
    closed or in an invalid state).

    Args:
        sock (socket.socket | None): The socket to shut down and close. If None,
            the function does nothing.
    """
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
    """Send a single framed message over a connected socket.

    This function implements a simple length-prefixed framing protocol:
    it first encodes the length of the payload as a 4-byte big-endian
    unsigned integer, then sends the length header followed immediately
    by the raw payload bytes using ``sock.sendall``.

    Args:
        sock: A connected socket-like object that provides a ``sendall`` method.
        data: The raw bytes to be sent as one framed message.

    Raises:
        OSError: If a low-level socket error occurs during transmission.
    """
    # Length-prefix the payload with 4-byte big-endian size for framing
    length = len(data).to_bytes(4, 'big')
    # Send header + payload as one stream
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    """Receive exactly `n` bytes from a socket.

    This function repeatedly calls `sock.recv()` until exactly `n` bytes have
    been read or the remote end closes the connection. It is useful for
    protocols where message sizes are fixed or prefixed by a length header.

    Args:
        sock: A socket-like object exposing a `recv(max_bytes: int) -> bytes` method.
        n (int): The exact number of bytes to read from the socket.

    Returns:
        bytes | None: A `bytes` object containing exactly `n` bytes if successful;
        `None` if the connection is closed or an error occurs before `n` bytes
        can be read.
    """
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
    """Receive a single length-prefixed frame from a socket.

    This function reads a 4-byte big-endian length header from the given
    socket, validates the resulting frame size against zero and
    MAX_FRAME_SIZE, then reads and returns exactly that many payload bytes.

    Args:
        sock: A connected socket-like object supporting a recv() method.

    Returns:
        bytes | None: The received payload bytes on success, or None if the
        connection is closed, the frame length is zero, exceeds
        MAX_FRAME_SIZE, or a complete frame cannot be read.
    """
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
    """Generate a new 2048-bit RSA private key for use as an RSA key pair.

    The returned private key includes the corresponding public key and can be used
    for encrypting, decrypting, signing, and verifying operations.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: A newly
            generated RSA private key with public exponent 65537 and key size
            of 2048 bits.
    """
    # Create a 2048-bit RSA private key (public exponent 65537)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def serialize_public_key(pub):
    """Serialize an asymmetric public key to PEM-encoded SubjectPublicKeyInfo bytes.

    This helper converts a public key object into a standard PEM representation
    suitable for sending over the wire or storing on disk.

    Args:
        pub: A public key object that implements the `public_bytes` method from
            the `cryptography` library (e.g., RSA, EC, or Ed25519 public key).

    Returns:
        bytes: The PEM-encoded SubjectPublicKeyInfo representation of the public key.
    """
    # Convert public key to PEM (SubjectPublicKeyInfo) for wire exchange
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    """Load an RSA public key from PEM-encoded bytes.

    Args:
        pem_bytes: The PEM-encoded public key data as a bytes object.

    Returns:
        An RSA public key instance created from the provided PEM data.

    Raises:
        ValueError: If the data is not in valid PEM format or cannot be decoded.
        TypeError: If the input is not bytes or the key type is unsupported.
    """
    # Parse PEM-encoded public key into an RSA key object
    return serialization.load_pem_public_key(pem_bytes)

def encrypt_payload(peer_public_key, plaintext: bytes) -> bytes:
    """Encrypt a plaintext payload for a peer using a hybrid RSA–AES scheme.

    This function:
    1. Generates a random 256-bit AES key and 128-bit IV.
    2. Applies PKCS#7 padding to the given plaintext.
    3. Encrypts the padded plaintext with AES-256 in CBC mode.
    4. Encrypts (wraps) the AES key using the peer's RSA public key with OAEP
        padding and SHA-256 as the hash algorithm.
    5. Packages the encrypted AES key (`k`), IV (`i`), and ciphertext (`c`) into
        a JSON object, with each component base64-encoded, and returns it as UTF-8
        encoded bytes.

    Args:
         peer_public_key: An RSA public key object compatible with the `cryptography`
              library, used to encrypt the per-message AES key.
         plaintext (bytes): The raw plaintext data to encrypt.

    Returns:
         bytes: A UTF-8 encoded JSON document containing base64-encoded fields:
              - "k": the RSA-encrypted AES key,
              - "i": the IV used for AES-CBC,
              - "c": the AES-CBC ciphertext of the padded plaintext.
    """
    # Per-message AES-256 key and 16-byte IV
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # Wrap AES key with peer RSA public key using OAEP(SHA-256)
    enc_key = peer_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    # Package encrypted key (k), IV (i), and ciphertext (c) as base64 JSON
    obj = {
        'k': base64.b64encode(enc_key).decode(),
        'i': base64.b64encode(iv).decode(),
        'c': base64.b64encode(ciphertext).decode()
    }
    # Return UTF-8 bytes ready for framing
    return json.dumps(obj).encode()

def decrypt_payload(private_key, data_bytes: bytes) -> bytes:
    """Decrypt a hybrid-encrypted payload using an RSA private key.

    The payload is expected to be a JSON-encoded bytes object containing
    three base64-encoded fields:
        - "k": the AES session key encrypted with the RSA public key
        - "i": the AES-CBC initialization vector (IV)
        - "c": the ciphertext encrypted with the AES session key

    Decryption steps:
    1. Parse the JSON structure from ``data_bytes``.
    2. Base64-decode the encrypted AES key, IV, and ciphertext.
    3. Use the provided RSA private key with OAEP + SHA-256 to recover the AES key.
    4. Decrypt the ciphertext using AES-CBC with the recovered key and IV.
    5. Remove PKCS7 padding from the plaintext.

    Args:
        private_key: An RSA private key object compatible with
            ``cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey``
            that can perform OAEP-SHA256 decryption.
        data_bytes (bytes): The JSON-encoded encrypted payload received
            over the wire.

    Returns:
        bytes: The decrypted plaintext payload.

    Raises:
        json.JSONDecodeError: If ``data_bytes`` is not valid JSON.
        KeyError: If required fields ("k", "i", "c") are missing from the JSON.
        ValueError: If base64 decoding or cryptographic operations fail.
        cryptography.exceptions.InvalidSignature: If decryption fails due to
            incorrect key material or tampering.
    """
    # Parse JSON and base64-decode parts
    obj = json.loads(data_bytes.decode())
    enc_key = base64.b64decode(obj['k'])
    iv = base64.b64decode(obj['i'])
    ciphertext = base64.b64decode(obj['c'])
    # Recover AES key using RSA private key (OAEP SHA-256)
    aes_key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    # Decrypt with AES-CBC and strip PKCS7 padding
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def key_fingerprint(public_key) -> bytes:
    """Compute a SHA-256 fingerprint for the given public key.

    This helper converts the public key to DER-encoded SubjectPublicKeyInfo
    format and returns the 32-byte SHA-256 digest of that encoding. The
    fingerprint can be used as a stable, opaque identifier for the key.

    Args:
        public_key: A public key object providing a ``public_bytes`` method
            compatible with ``cryptography``'s key interfaces.

    Returns:
        bytes: The 32-byte SHA-256 fingerprint of the DER-encoded public key.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()

def build_signed_message(text: str, signer, intended_recipient_key) -> bytes:
    """Build a signed, encrypted message for a specific recipient.

    This function encodes the given text as UTF-8, encrypts it for the
    intended recipient, and signs the combination of the recipient key's
    fingerprint and the encrypted payload. The result is a JSON object
    containing the encrypted payload and the signature, both base64-encoded,
    returned as bytes.

    Args:
        text: Plaintext message to encrypt and sign.
        signer: Private key or signing object providing a ``sign(data, padding, algorithm)``
            method compatible with RSA-PSS and SHA-256.
        intended_recipient_key: Public key used to encrypt the message and to derive
            its fingerprint for the signature input.

    Returns:
        Bytes containing a JSON document with two fields:
            - ``"enc"``: Base64-encoded encrypted payload.
            - ``"sig"``: Base64-encoded digital signature over the fingerprint
              of ``intended_recipient_key`` concatenated with the encrypted payload.
    """
    plaintext = text.encode('utf-8')
    enc_blob = encrypt_payload(intended_recipient_key, plaintext)
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

def unwrap_signed_message(data: bytes, peer_public_key, private_key) -> str:
    """Verify and decrypt a signed, encrypted message bundle.

    The input is expected to be a JSON-encoded bytes object containing base64-
    encoded fields:
        - "enc": the encrypted payload
        - "sig": the digital signature over the key fingerprint and ciphertext

    The function:
        1. Parses and validates the JSON structure.
        2. Base64-decodes the ciphertext and signature.
        3. Constructs the signature input as the sender key fingerprint combined
           with the encrypted blob.
        4. Verifies the signature using the peer's public key with RSA-PSS
           and SHA-256.
        5. Decrypts the ciphertext with the provided private key.
        6. Returns the resulting plaintext as a UTF-8 string, ignoring decoding
           errors.

    Args:
        data (bytes): JSON-encoded bundle containing base64-encoded "enc"
            and "sig" fields.
        peer_public_key: Public key object used to verify the signature of
            the message (e.g., an RSA public key).
        private_key: Private key object corresponding to the local identity,
            used to decrypt the encrypted payload.

    Returns:
        str: The decrypted plaintext message.

    Raises:
        ValueError: If the bundle is malformed, required fields are missing,
            or signature verification fails.
    """
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
    plaintext = decrypt_payload(private_key, enc_blob)
    return plaintext.decode(errors='ignore')

def receiver(sock, stop, private_key, peer_public_key):
    """Continuously receive, verify, decrypt, and display messages from a peer.

    This function is intended to run in a background thread. It repeatedly:
    1. Receives a framed message from the given socket.
    2. Attempts to unwrap (verify signature and decrypt) the message using the
        provided peer public key and local private key.
    3. Prints the resulting plaintext message to the console, prefixed with
        a signed message tag.
    4. Monitors for termination conditions (remote 'exit' command, invalid
        frames, failed signature verification, decryption errors, or other
        unexpected exceptions) and, when encountered, sets the provided stop
        event and exits the loop to shut down the client cleanly.

    Args:
         sock: A connected socket-like object used to receive framed messages.
         stop: A threading.Event used as a shared flag to signal when the
              receive loop should terminate.
         private_key: The local private key used to decrypt incoming messages.
         peer_public_key: The peer's public key used to verify message signatures.
    """
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
                text = unwrap_signed_message(frame, peer_public_key, private_key)
            except ValueError:
                print('Signature verification failed. Closing client...')
                stop.set()
                break
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
            print(f'\nMessage Received{SIGNED_TAG}: {text}')
        except Exception:
            # Any unexpected error stops processing
            stop.set()
            break



if __name__ == '__main__':
    # Overall flow:
    #   1. Parse command-line options to know which server (host/port) to connect to.
    #   2. Open a TCP socket and connect to the server.
    #   3. Perform an RSA key exchange to set up a secure channel.
    #   4. Start a background receiver thread that decrypts & verifies incoming messages.
    #   5. In the main thread, read user input, encrypt & sign it, and send to the server.
    #   6. When "exit" is typed or an error occurs, shut down both threads and close socket.

    # argparse.ArgumentParser: parses CLI options like --host and --port and
    # populates the `args` object with the chosen values.
    # Parse CLI args: host and port to connect
    parser = argparse.ArgumentParser(description='Simple chat client')
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Server host/IP to connect to (use 127.0.0.1 for same machine)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8000,               #=============change port here=============
        help='Server port to connect to'
    )
    # args: holds parsed CLI values, e.g., args.host and args.port
    args = parser.parse_args()

    # socket.socket: creates a TCP/IP socket used to connect to the remote server.
    # Create a TCP socket and attempt to connect to the specified server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = args.host
    port = args.port
    try:
        # s.connect: establishes a TCP connection to (host, port).
        s.connect((host, port))
    except Exception as e:
        # Connection failed: report error and exit
        print(f'Failed to connect to {host}:{port} -> {e}')
        # safe_close: shuts down and closes the socket, ignoring any errors.
        safe_close(s)
        raise SystemExit(1)

    # Connection succeeded: inform user and set up a stop event for clean shutdown
    print(f'Connected to server at {host}:{port}. Type messages and press Enter. Type "exit" to quit.')
    # Event(): thread-safe flag used to coordinate shutdown between main and receiver thread.
    stop = Event()  # Shared stop flag between threads

    # Key exchange phase:
    # 1. Generate an RSA key pair for this client
    # 2. Receive the server's public key (PEM) as a framed message
    # 3. Send this client's public key (PEM) back to the server
    # generate_rsa_keypair: creates a new 2048-bit RSA private key (with associated public key).
    client_priv = generate_rsa_keypair()
    client_pub = client_priv.public_key()
    # recv_frame: reads one length-prefixed frame from the socket (here, server's PEM public key).
    server_pub_pem = recv_frame(s)
    if not server_pub_pem:
        # If we didn't get a valid server key, abort
        print('Failed to receive server public key.')
        safe_close(s)
        raise SystemExit(1)
    # load_public_key: converts PEM bytes into a usable RSA public key object.
    server_pub = load_public_key(server_pub_pem)
    # serialize_public_key: turns the client's public key into PEM bytes.
    # send_frame: sends a length-prefixed frame containing those PEM bytes to the server.
    send_frame(s, serialize_public_key(client_pub))
    print('Secure channel established.')

    # Thread: starts a background worker that runs the `receiver` function concurrently.
    # receiver: continuously calls recv_frame + unwrap_signed_message to verify/decrypt
    # incoming messages using server_pub (verify) and client_priv (decrypt), then prints them.
    # Start a background thread that receives, verifies, decrypts, and displays messages
    # The main thread will only handle user input and sending messages
    rcv = Thread(target=receiver, args=(s, stop, client_priv, server_pub), daemon=True)
    rcv.start()

    # Main send loop: read user input, sign & encrypt it, then send to the server
    while not stop.is_set():
        try:
            # input: reads a line of text from the user on stdin.
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                # User requested to quit:
                # try to send an encrypted/signed "exit" message, then stop
                try:
                    # build_signed_message: encrypts `msg` for server_pub and signs it with client_priv.
                    # send_frame: transports the signed+encrypted blob as one framed message.
                    send_frame(s, build_signed_message(msg, client_priv, server_pub))
                except Exception:
                    # Ignore errors on shutdown send
                    pass
                stop.set()
                break

            # Normal message: sign, encrypt for the server, and send as a framed message
            send_frame(s, build_signed_message(msg, client_priv, server_pub))
        except Exception:
            # Any I/O or socket error: stop and break out of the loop
            stop.set()
            break

    # rcv.join: wait briefly for the receiver thread to exit after stop is set.
    # Wait briefly for the receiver thread to terminate, then close the socket
    rcv.join(timeout=1)
    # safe_close: ensures the client socket is cleanly shut down and closed.
    safe_close(s)