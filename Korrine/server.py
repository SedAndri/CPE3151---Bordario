import socket                   # Low-level TCP networking
import argparse                 # Command-line argument parsing
from threading import Thread, Event  # Concurrency primitives for receiver/sender
import os, json, base64         # Random bytes, JSON packing, base64 encoding
import hashlib                 # Key fingerprinting
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  # RSA + OAEP padding
from cryptography.hazmat.primitives import serialization            # PEM serialization
from cryptography.hazmat.primitives.hashes import SHA256            # Hashing (shorter name)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

MAX_FRAME_SIZE = 1_048_576  # Safety cap for message frames to prevent oversized allocations
SIGNED_TAG = ' [S]'        # Indicates a message’s signature verified successfully

def safe_close(sock):
    """Safely close a socket by shutting it down and then closing it, ignoring errors.

    Args:
        sock (socket.socket | None): The socket to be closed. If None, the
            function does nothing.

    This helper attempts to shut down both directions of the socket to
    terminate ongoing communication, then closes the socket handle. Any
    exceptions raised during shutdown or close (for example, if the socket
    is already closed) are caught and suppressed to make the operation
    idempotent and safe to call in cleanup code.
    """
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
    """Send a length-prefixed binary frame over a socket.

    This function implements a simple framing protocol by prefixing the
    payload with its length encoded as a 4-byte big-endian integer and
    sending the resulting frame using ``sock.sendall`` so the entire
    message is transmitted before returning.

    Args:
        sock: A connected socket-like object providing a ``sendall`` method.
        data: The payload to send as a single framed message, in bytes.

    Raises:
        OSError: If the underlying socket send operation fails.
    """
    # Prefix payload with 4-byte big-endian length for framing
    length = len(data).to_bytes(4, 'big')
    # Send length + data atomically using sendall
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    """Receive exactly `n` bytes from a socket, handling partial (short) reads.

    This function repeatedly calls `sock.recv()` until exactly `n` bytes have been
    read, or the socket is closed.

    Args:
        sock: A socket-like object that implements a `recv(size: int) -> bytes` method.
        n (int): The exact number of bytes to read from the socket.

    Returns:
        bytes | None: A `bytes` object of length `n` containing the received data if
        successful; `None` if the socket is closed or an error occurs before `n`
        bytes can be read.
    """
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
    """Receive a single length-prefixed frame from the given socket.

    This function first reads a 4-byte big-endian length header, validates that
    the resulting length is non-zero and does not exceed ``MAX_FRAME_SIZE``,
    then reads exactly that many bytes from the socket using ``recv_exact``.

    Args:
        sock: A connected socket-like object supporting ``recv`` calls.

    Returns:
        bytes | None: The received frame payload as a bytes object, or ``None`` if
        the connection is closed, the header cannot be read, or the length is
        invalid.
    """
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
    """Generate and return a new 2048-bit RSA private key.

    This function creates a fresh RSA key pair using a public exponent of
    65537 and a key size of 2048 bits.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey:
            A newly generated RSA private key that can be used to derive
            the corresponding public key, sign data, or decrypt messages.
    """
    # Create a fresh 2048-bit RSA private key (public exponent 65537)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def serialize_public_key(pub):
    """Serialize an RSA public key to PEM-encoded SubjectPublicKeyInfo bytes.

    Args:
        pub: An RSA public key object (from the ``cryptography`` library) to serialize.

    Returns:
        bytes: The PEM-encoded representation of the public key, suitable for
            transmission or storage.
    """
    # Convert RSA public key to PEM (SubjectPublicKeyInfo) for wire exchange
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    """Load an RSA public key object from PEM-encoded bytes.

    This function takes a PEM-encoded public key (as bytes) and uses the
    cryptography library to deserialize it into an RSA public key object
    that can be used for cryptographic operations such as signature
    verification or encryption.

    Args:
        pem_bytes (bytes): The PEM-encoded public key data.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey:
            The deserialized RSA public key object.

    Raises:
        ValueError: If the provided data is not a valid PEM-encoded public key.
        TypeError: If the input is not of type ``bytes``.
    """
    # Parse a PEM-encoded public key back into an RSA key object
    return serialization.load_pem_public_key(pem_bytes)

def encrypt_payload(peer_public_key, plaintext: bytes) -> bytes:
    """Encrypt a plaintext payload using a hybrid RSA–AES scheme and return a JSON package.

    This function:
    - Generates a random 256-bit AES key and a 16-byte IV.
    - Applies PKCS7 padding to the plaintext and encrypts it with AES-256 in CBC mode.
    - Encrypts the AES key with the peer's RSA public key using OAEP padding with SHA-256.
    - Base64-encodes the encrypted key, IV, and ciphertext and packages them into a JSON
        object with fields:
            - 'k': encrypted AES key (base64-encoded string)
            - 'i': IV (base64-encoded string)
            - 'c': ciphertext (base64-encoded string)

    Args:
            peer_public_key: An RSA public key object (from the `cryptography` library)
                    used to encrypt the generated AES key.
            plaintext (bytes): The raw data to be encrypted.

    Returns:
            bytes: A UTF-8 encoded JSON document containing the base64-encoded encrypted
            AES key, IV, and ciphertext, suitable for transmission or storage.
    """
    # Generate a fresh AES-256 key and 16-byte IV per message
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # Encrypt the AES key using the peer’s RSA public key with OAEP + SHA-256
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
    # Return bytes suitable for framing
    return json.dumps(obj).encode()

def decrypt_payload(private_key, data_bytes: bytes) -> bytes:
    """Decrypt a hybrid-encrypted payload using an RSA private key and AES-CBC.

    The input is expected to be a JSON-encoded bytes object containing three
    base64-encoded fields:
        - "k": RSA-OAEP-encrypted AES key
        - "i": AES initialization vector (IV)
        - "c": AES-CBC-encrypted ciphertext

    The function:
    1. Parses the JSON structure from the given bytes.
    2. Base64-decodes the RSA-encrypted AES key, IV, and ciphertext.
    3. Uses the provided RSA private key to decrypt the AES key with OAEP + SHA-256.
    4. Decrypts the ciphertext using AES-CBC with the recovered AES key and IV.
    5. Removes PKCS#7 padding from the decrypted data and returns the plaintext.

    Args:
        private_key: An RSA private key object compatible with `cryptography`, used
            to decrypt the embedded AES session key.
        data_bytes (bytes): The JSON-encoded payload holding the base64-encoded
            encrypted AES key, IV, and ciphertext.

    Returns:
        bytes: The decrypted plaintext resulting from the hybrid decryption process.

    Raises:
        json.JSONDecodeError: If `data_bytes` is not valid JSON.
        KeyError: If required keys ("k", "i", "c") are missing in the JSON object.
        ValueError: If decryption, padding removal, or base64 decoding fails.
    """
     # Parse JSON and base64-decode components
    obj = json.loads(data_bytes.decode())
    enc_key = base64.b64decode(obj['k'])
    iv = base64.b64decode(obj['i'])
    ciphertext = base64.b64decode(obj['c'])
    # Recover AES key with RSA private key (OAEP + SHA-256)
    aes_key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    # Decrypt ciphertext with AES-CBC and remove padding
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def key_fingerprint(public_key) -> bytes:
    """Compute a SHA-256 fingerprint of a public key.

    The public key is first serialized to DER using the SubjectPublicKeyInfo
    format, then hashed with SHA-256.

    Args:
        public_key: A cryptography public key object supporting `public_bytes()`.

    Returns:
        bytes: The 32-byte SHA-256 digest representing the key's fingerprint.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()

def build_signed_message(text: str, signer, intended_recipient_key) -> bytes:
    """Build a signed, encrypted message for a specific recipient.

    This helper takes a plaintext string, encrypts it for the intended recipient,
    and signs the resulting encrypted payload (along with the recipient key
    fingerprint) using the provided signer. The output is a JSON-encoded bytes
    object containing base64-encoded ciphertext and signature.

    Args:
        text (str): The plaintext message to encrypt and sign.
        signer: An object with a ``sign(data, padding, algorithm)`` method,
            typically an RSA private key used to produce the digital signature.
        intended_recipient_key: The public key of the intended recipient, used
            to encrypt the message and derive the key fingerprint.

    Returns:
        bytes: A UTF-8 encoded JSON document with the structure:
            {
                "enc": "<base64-encoded encrypted payload>",
                "sig": "<base64-encoded signature over fingerprint + ciphertext>"
            }.
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

    This function expects a JSON-encoded bytes object containing two
    base64-encoded fields:
        - "enc": the encrypted payload
        - "sig": the digital signature over a fingerprint of the recipient's
          public key concatenated with the encrypted payload.

    The function:
    1. Parses and validates the JSON structure.
    2. Base64-decodes the encrypted payload and its signature.
    3. Verifies the signature using the sender's (peer) public key.
    4. Decrypts the encrypted payload using the provided private key.
    5. Returns the resulting plaintext as a string.

    Args:
        data (bytes): JSON-encoded message bundle containing the encrypted
            payload and its signature.
        peer_public_key: Public key object of the peer (sender), used to
            verify the signature.
        private_key: Private key object of the local party, used to decrypt
            the encrypted payload.

    Returns:
        str: The decrypted plaintext message. Any undecodable bytes are
        ignored during decoding.

    Raises:
        ValueError: If the bundle is malformed, missing required fields,
            or if signature verification fails.
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

def receiveMsg(conn, stop, private_key, peer_public_key):
    """
    Continuously receive, decrypt, verify, and display signed messages from a peer.

    This function is intended to run in a background thread. It repeatedly reads
    framed data from the given connection, attempts to unwrap and verify a
    cryptographically signed message using the peer's public key and the local
    private key, and prints the resulting plaintext. The loop terminates and the
    connection is closed when:

    - The peer disconnects or sends an invalid frame.
    - Signature verification or decryption fails.
    - The peer sends the shutdown command "exit".
    - Any unexpected exception occurs.

    Args:
        conn: A socket-like connection object used to receive frames from the peer.
        stop: A threading.Event (or compatible) used as a shutdown flag; when set,
            the receive loop terminates.
        private_key: The local private key used for decrypting incoming messages.
        peer_public_key: The peer's public key used to verify message signatures.

    Side Effects:
        - Prints received messages and status information to stdout.
        - Sets the `stop` event on error or orderly shutdown.
        - Closes the connection via `safe_close(conn)` when the loop exits.
    """
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
                text = unwrap_signed_message(frame, peer_public_key, private_key)
            except ValueError:
                print('Signature verification failed. Closing server...')
                stop.set()
                break
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
            print(f'\nMessage Received{SIGNED_TAG}: {text}')
        except Exception:
            # Any unexpected error stops processing
            stop.set()
            break
    # Ensure the connection is closed after loop ends
    safe_close(conn)

def sendMessage(conn, stop, peer_public_key, private_key):
    """Interactively send encrypted, signed messages to a peer over an open connection.

    This function runs in a loop, reading plaintext messages from standard input,
    encrypting and signing each message with the local private key and the peer's
    public key, then sending the resulting frame over the given socket-like
    connection using ``send_frame`` and ``build_signed_message``.

    Typing ``exit`` (case-insensitive, with optional surrounding whitespace) causes
    a final signed "exit" message to be sent, the shared stop event to be set, and
    the loop to terminate. Any I/O or socket-related exception also sets the stop
    event and breaks the loop, allowing coordinating threads to shut down cleanly.

    Args:
        conn: A socket-like connection object used to transmit message frames.
        stop: A threading.Event (or compatible) used to signal when sending should stop.
        peer_public_key: The public key object used to encrypt messages for the peer.
        private_key: The local private key object used to sign outgoing messages.
    """
    # Main thread: read user input, encrypt with peer public key, send frames
    while not stop.is_set():
        try:
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                # Send exit, then request stop
                try:
                    send_frame(conn, build_signed_message(msg, private_key, peer_public_key))
                except Exception:
                    pass
                stop.set()
                break
            # Normal message: encrypt and send
            send_frame(conn, build_signed_message(msg, private_key, peer_public_key))
        except Exception:
            # On I/O or socket error, stop and exit
            stop.set()
            break

def listenConnection(host='127.0.0.1', port=8000):
    """Listen for a single incoming TCP client connection.

    Creates a TCP/IP socket bound to the specified host and port, enables
    address reuse to allow quick restarts, and blocks while waiting for
    one incoming client connection. Once a client connects, the function
    returns the connection object, the client's address, and the listening
    server socket so they can be used for communication and later closed.

    Args:
        host (str, optional): Host/IP address to bind the server to.
            Defaults to '127.0.0.1' (localhost).
        port (int, optional): TCP port to listen on. Defaults to 8000.

    Returns:
        tuple:
            conn (socket.socket): Connected socket object for the client.
            addr (tuple): Client address as (ip, port).
            s (socket.socket): Server listening socket.
    """
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
        rcv = Thread(target=receiveMsg, args=(conn, stop, server_priv, peer_pub), daemon=True)
        rcv.start()
        # Main thread handles user input and sending encrypted messages
        sendMessage(conn, stop, peer_pub, server_priv)
        # Wait briefly for receiver to finish
        rcv.join(timeout=1)
    finally:
        # Cleanly close sockets on exit
        safe_close(conn)
        safe_close(srv_sock)