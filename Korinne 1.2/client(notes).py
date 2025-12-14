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
    """Safely and idempotently shut down and close a TCP socket.

    In the secure messaging client, this helper ensures that the underlying
    network channel is torn down in a controlled way even if errors, crashes,
    or attacks cause abnormal termination. By attempting a full shutdown before
    closing the socket and by suppressing cleanup errors, it helps prevent
    resource leaks, half-open connections, and inconsistent connection state
    that could otherwise weaken availability or be abused for denial-of-service.

    Step-by-step, the function:
      1. Attempts to shut down both directions of the TCP stream (send/receive).
      2. Silently ignores any shutdown errors (e.g., already closed or reset).
      3. Attempts to close the socket and release OS-level resources.
      4. Silently ignores any close errors so cleanup never masks prior failures.

    Args:
        sock (socket.socket | None): The TCP socket to terminate. May be None
            or already closed; the function checks for a valid object and
            suppresses shutdown/close errors so callers can safely invoke it
            from error handlers and finally blocks without extra guards.

    Returns:
        None: This function performs best-effort cleanup in place and does not
        report success or failure to the caller.

    Raises:
        None: All exceptions raised during shutdown or close are intentionally
        caught and suppressed to keep cleanup paths simple and robust.
    """
    # Best-effort, idempotent socket shutdown to avoid leaks/half-open connections
    try:
        if sock:
            # Disable further sends/receives before closing (clean TCP teardown)
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        # Ignore shutdown errors (e.g., already closed, reset by peer)
        pass
    try:
        if sock:
            # Close underlying OS descriptor; final resource release
            sock.close()
    except Exception:
        # Ignore close errors so cleanup never interrupts error handling
        pass

def send_frame(sock, data: bytes):
    """Send a single length-prefixed binary frame over a TCP socket.

    This helper wraps higher-level protocol messages (for example, encrypted and
    signed payloads) into a fixed header‑plus‑body format so that the receiver
    can unambiguously reassemble message boundaries on a streaming TCP
    connection. By enforcing an explicit length header, it simplifies parsing
    and enables the receiving side to enforce size limits for robustness and
    denial‑of‑service mitigation.

    Step-by-step, the function:
      1. Computes a 4-byte big-endian length prefix for the outgoing payload.
      2. Concatenates the length prefix and payload into a single byte sequence.
      3. Uses `sendall()` to reliably transmit the entire framed message.

    Args:
        sock (socket.socket): Connected TCP socket used as the transport
            channel; must be open and in a valid state so the framed message
            can be delivered to the peer.
        data (bytes): Fully encoded protocol message to send (typically already
            encrypted and/or signed by higher-level logic); must be a bytes-like
            object because it is sent verbatim over the wire.

    Returns:
        None: On successful return, the complete frame (length header and
        payload) has been handed off to the operating system for transmission.

    Raises:
        OSError: If the underlying socket send operation fails (for example,
            due to a broken connection or network error).
        TypeError: If `data` is not a bytes-like object accepted by
            `len()`/`to_bytes()` and `sock.sendall()`.
    """
    # Compute fixed-size 4-byte big-endian length prefix for framing
    length = len(data).to_bytes(4, 'big')
    # Send header + payload atomically so receiver can reconstruct exact message
    sock.sendall(length + data)

def recv_exact(sock, n: int):
    """Reliably read exactly ``n`` bytes from a TCP socket or signal disconnect.

    In the secure messaging protocol, this helper ensures that encrypted and/or
    signed messages are reassembled into complete frames before any parsing or
    cryptographic operations are performed. By strictly honoring message
    boundaries, it prevents partial reads from corrupting ciphertext, breaking
    signature verification, or leaking protocol state that could weaken
    confidentiality and integrity guarantees.

    The function allocates a buffer, repeatedly reads from the socket until it
    has accumulated exactly ``n`` bytes, and then returns the result as an
    immutable ``bytes`` object. If the peer closes the connection before the
    requested amount of data is received, it returns ``None`` so callers can
    treat this as a clean disconnect and avoid processing incomplete messages.

    Args:
        sock (socket.socket): Connected TCP socket used as the underlying
            transport channel; must be open and readable so that protocol
            frames (including encrypted/signed blobs) can be fully retrieved.
        n (int): Exact number of bytes to read, typically the length prefix or
            message body size; enforcing this bound ensures that higher-level
            cryptographic operations always see complete and correctly sized
            inputs.

    Returns:
        bytes | None: A ``bytes`` object containing exactly ``n`` bytes read
        from the socket on success, or ``None`` if the connection is closed
        before that many bytes can be obtained (indicating EOF/disconnect).

    Raises:
        OSError: If a low-level socket error occurs during ``recv`` (e.g.,
            network failure, connection reset by peer).
        ValueError: If the socket is in an invalid state or misconfigured such
            that ``recv`` cannot be performed successfully.
    """
    # Initialize mutable buffer to accumulate incoming bytes until target length
    buf = bytearray()

    # Loop until we've collected exactly n bytes or the peer disconnects
    while len(buf) < n:
        # Read up to the remaining required bytes from the TCP stream
        chunk = sock.recv(n - len(buf))

        # If recv() returns empty, treat it as clean disconnect / EOF
        if not chunk:
            return None

        # Append newly received bytes to the buffer
        buf.extend(chunk)

    # Convert to immutable bytes before returning to callers
    return bytes(buf)

def recv_frame(sock):
    """Receive a single length-prefixed binary frame from a TCP socket.

    This helper reconstructs discrete protocol messages from the raw TCP stream
    by enforcing a fixed 4-byte length header in front of each encrypted/signed
    payload. In the secure messaging protocol, this framing guarantees that
    cryptographic operations (decryption, signature verification) always operate
    on complete messages, which is essential for maintaining confidentiality and
    integrity guarantees. The function also enforces a maximum frame size to
    limit resource usage and reduce the risk of denial-of-service attacks via
    oversized payloads.

    Internally, the function first reads exactly 4 bytes for the length header,
    converts that header to an integer, validates it against basic sanity and
    security limits, and then reads exactly that many bytes as the message body.
    If the peer closes the connection or an invalid/unsafe length is observed,
    it returns ``None`` so the caller can treat it as a clean disconnect or
    protocol violation and abort further processing.

    Args:
        sock (socket.socket): A connected TCP socket from which to read the
            next framed message. The socket must be open and readable so the
            function can reliably retrieve both the length header and payload.

    Returns:
        bytes | None: The raw message payload as a ``bytes`` object when a
        well-formed frame is successfully received, or ``None`` if the peer
        disconnects before a full frame is read or if the declared length is
        zero/invalid/too large (indicating a protocol or safety violation).

    Raises:
        OSError: If a low-level socket error occurs during underlying reads
            performed by ``recv_exact`` (e.g., connection reset, network error).
        ValueError: If the socket is in an invalid state such that ``recv``
            cannot be performed correctly, as propagated from ``recv_exact``.
        TypeError: If the socket-like object does not provide a compatible
            ``recv`` interface required by ``recv_exact``.
    """
    # Read fixed-size 4-byte header that encodes the upcoming frame length
    hdr = recv_exact(sock, 4)
    if not hdr:
        # Treat missing/partial header as clean disconnect / EOF
        return None

    # Convert big-endian length prefix to integer for validation and bounds check
    length = int.from_bytes(hdr, 'big')

    # Reject empty or excessively large frames to enforce protocol and prevent DoS
    if length == 0 or length > MAX_FRAME_SIZE:
        return None
    # Read and return exactly `length` bytes as the message body
    return recv_exact(sock, length)

def generate_rsa_keypair():
    """Generate a new RSA private/public key pair for the secure messaging client.

    This function bootstraps the client's asymmetric identity used to sign
    messages (authenticity and integrity) and to participate in public-key
    operations during the session setup. By creating a fresh 2048-bit RSA key
    pair at runtime, it provides a cryptographic anchor that peers can trust
    when verifying signatures and binding encrypted data to a specific entity.

    Internally, the function delegates to the `cryptography` library's RSA key
    generator, using the industry-standard public exponent 65537 and a
    2048-bit modulus considered secure for typical messaging scenarios. The
    returned private key object encapsulates both private and public components;
    callers can derive the public key via `private_key.public_key()` and then
    serialize and exchange it as part of the protocol handshake.

    Args:
        None: All key-generation parameters (key size, public exponent, and
            randomness source) are fixed to secure defaults appropriate for
            this protocol to avoid misconfiguration.

    Returns:
        rsa.RSAPrivateKey: A newly generated RSA private key object that
        contains both the private and public components. The caller must
        protect the private key material (e.g., never send it over the network)
        and may serialize/share only the corresponding public key with peers.

    Raises:
        ValueError: Propagated from the underlying RSA generator if given
            invalid parameters (not expected with the fixed secure defaults).
        RuntimeError: If the system's cryptographically secure random number
            generator fails, preventing safe key generation.
        Exception: Any other low-level exceptions raised by
            `rsa.generate_private_key` are propagated unchanged.
    """
    # Generate a 2048-bit RSA key using standard exponent 65537 (widely vetted, secure default)
    # Relies on OS CSPRNG so keys are unpredictable and suitable for long-term identity
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Return the private key; public key is derived when needed to minimize exposure
    return private_key

def serialize_public_key(pub):
    """Serialize an RSA public key into a PEM-encoded byte string.

    In the secure messaging protocol, this function prepares a participant's
    public key for transport during the initial key-exchange handshake. Using a
    standard PEM / SubjectPublicKeyInfo representation ensures the peer can
    reconstruct exactly the same key needed to verify signatures and perform
    encryption, which underpins authenticity and confidentiality. A canonical
    serialized form also avoids parsing ambiguities that could otherwise cause
    verification failures or key-mismatch issues.

    Internally, the function delegates to the `cryptography` library to encode
    the in-memory key object into a portable, text-friendly format. The result
    can be safely framed, transmitted, and later deserialized by the receiver
    without losing any cryptographic properties of the original key.

    Args:
        pub (rsa.RSAPublicKey): The RSA public key object to serialize and share
            with a remote peer so it can verify signatures from, and encrypt
            data to, the holder of the corresponding private key.

    Returns:
        bytes: The PEM-encoded representation of the provided public key, in
        SubjectPublicKeyInfo format, ready for network transmission or storage.

    Raises:
        TypeError: If ``pub`` is not a supported public key object for
            ``public_bytes``.
        ValueError: If the key cannot be serialized with the requested
            encoding/format combination.
        cryptography.exceptions.UnsupportedAlgorithm: If the underlying backend
            does not support serializing this key type or parameters.
    """
    # Serialize to standard PEM + SubjectPublicKeyInfo for interoperability and safe exchange
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(pem_bytes: bytes):
    """Load an RSA public key object from a PEM-encoded byte string.

    In the secure messaging protocol, this reconstructs the peer's public key
    exchanged during the handshake so it can be used for signature verification
    (authenticity/integrity) and RSA key encapsulation. By relying on the
    `cryptography` library's strict PEM parser, it helps ensure that only
    well-formed, supported key material is admitted into the cryptographic
    workflow, reducing the risk of malformed or attacker-crafted keys.

    The function takes the raw PEM bytes received over the network, parses and
    validates them, and returns a public key object that higher-level functions
    use for encryption and verification operations.

    Args:
        pem_bytes (bytes): PEM-encoded public key data received from a remote
            peer (or loaded from storage); must represent a valid
            SubjectPublicKeyInfo public key so it can safely participate in the
            protocol's handshake and message verification steps.

    Returns:
        rsa.RSAPublicKey: A deserialized RSA public key object constructed from
        the PEM input, ready to be used for signature verification and RSA
        encryption in the secure channel setup.

    Raises:
        ValueError: If the provided bytes are not valid PEM or contain an
            invalid/unsupported public key structure.
        TypeError: If `pem_bytes` is not a bytes-like object acceptable to the
            underlying deserialization routine.
        cryptography.exceptions.UnsupportedAlgorithm: If the key type or
            parameters are not supported by the configured backend.
    """
    # Parse and validate peer's PEM-encoded public key from handshake
    # Returned key is later used for RSA verification/encryption
    return serialization.load_pem_public_key(pem_bytes)

# [DEFENSE NOTE]: Confidentiality
# Uses AES-256 with the pre-shared 'session_key'.
# Much faster than RSA, preventing DoS attacks on the CPU.
def encrypt_payload(session_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a plaintext message using AES-CBC and package it for safe transport.

    This function provides confidentiality for application messages by encrypting
    them with a symmetric AES session key before transmission over an untrusted
    network. It is the symmetric-encryption component of the secure messaging
    protocol and is typically combined with a digital signature to achieve both
    confidentiality and integrity/authenticity at the message level.

    Internally, the function generates a fresh random IV, applies PKCS#7 padding
    to the plaintext, encrypts the padded bytes with AES-CBC using the provided
    session key, then base64-encodes the IV and ciphertext and wraps them in a
    JSON structure suitable for framing and signing.

    Args:
        session_key (bytes): Symmetric key used for AES encryption (expected to
            be 32 bytes for AES‑256). This pre-shared key is what ensures only
            parties in possession of it can decrypt the resulting ciphertext.
        plaintext (bytes): Raw application data to encrypt. It is padded and
            transformed into ciphertext to prevent disclosure of its contents on
            the wire.

    Returns:
        bytes: UTF‑8 encoded JSON document containing two base64-encoded fields:
        ``"i"`` (the random IV) and ``"c"`` (the AES‑CBC ciphertext). This
        serialized blob is ready to be signed and sent as a length‑prefixed
        frame over the transport.

    Raises:
        ValueError: If the session key length is invalid for AES or if padding
            or encryption operations fail due to malformed inputs.
        TypeError: If either ``session_key`` or ``plaintext`` is not a bytes-like
            object accepted by the underlying cryptographic and JSON routines.
        json.JSONEncodeError: If serialization of the payload object to JSON
            fails (rare, but may occur with unexpected data types).
    """
    # Generate a fresh random IV per message to ensure semantic security for AES-CBC
    iv = os.urandom(16)

    # Apply PKCS#7 padding so plaintext length is a multiple of the AES block size
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    # Encrypt padded plaintext with AES-CBC using the shared session key and IV
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Encode IV and ciphertext as base64 so they are safe to embed in JSON/text
    obj = {
        'i': base64.b64encode(iv).decode(),
        'c': base64.b64encode(ciphertext).decode()
    }

    # Serialize encrypted package as JSON bytes; ready for signing and transport
    return json.dumps(obj).encode()

def decrypt_payload(session_key: bytes, data_bytes: bytes) -> bytes:
    """Decrypt an AES-CBC–encrypted payload and remove padding to recover plaintext.

    This function is the receiving-side counterpart to `encrypt_payload` in the
    secure messaging protocol, restoring the original application bytes from an
    encrypted transport blob. It enforces confidentiality by using the shared
    symmetric session key, and correctly handles PKCS#7 padding so that only
    well-formed ciphertexts produced by the protocol are successfully accepted.
    In practice, it is called only after integrity/authenticity checks (e.g.,
    signature verification) so that decryption is performed on trusted ciphertext.

    The function: (1) parses the JSON-encoded payload, (2) base64-decodes the IV
    and ciphertext, (3) decrypts the ciphertext using AES-CBC with the provided
    session key and IV, and (4) strips PKCS#7 padding to return the original
    plaintext bytes.

    Args:
        session_key (bytes): Symmetric AES key (typically 32 bytes for AES‑256)
            used to decrypt the ciphertext; must match the key used at
            encryption time or decryption/padding will fail.
        data_bytes (bytes): UTF‑8 encoded JSON structure containing base64-
            encoded fields for the initialization vector ("i") and ciphertext
            ("c") produced by `encrypt_payload`.

    Returns:
        bytes: The recovered plaintext message bytes after successful decryption
        and PKCS#7 unpadding, ready for higher-level processing or decoding
        (e.g., UTF‑8 string conversion).

    Raises:
        json.JSONDecodeError: If ``data_bytes`` is not valid JSON.
        KeyError: If required fields ("i" or "c") are missing from the JSON.
        binascii.Error: If the base64-encoded IV or ciphertext cannot be decoded.
        ValueError: If AES decryption or PKCS#7 unpadding fails (e.g., wrong key,
            corrupted ciphertext, or invalid padding).
    """
    # Parse JSON wrapper to extract base64-encoded IV and ciphertext
    obj = json.loads(data_bytes.decode())
    # Decode IV and ciphertext from transport-safe base64 representation
    iv = base64.b64decode(obj['i'])
    ciphertext = base64.b64decode(obj['c'])
    
    # Decrypt using AES-CBC with the shared session key and extracted IV
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding to recover the exact original plaintext bytes
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def key_fingerprint(public_key) -> bytes:
    """Compute a stable SHA-256 fingerprint of an RSA public key.

    This fingerprint is a compact, fixed-length identifier that binds protocol
    messages to a specific public key, supporting authenticity and integrity
    checks across the secure messaging session. By hashing the canonical DER
    representation of the key, both peers derive the same value without ever
    transmitting secret material, which helps detect key-substitution or
    impersonation attacks.

    Internally, the function first serializes the public key into a standardized
    DER-encoded SubjectPublicKeyInfo blob, then computes a SHA-256 hash over
    those bytes and returns the raw digest as the fingerprint.

    Args:
        public_key (rsa.RSAPublicKey): The RSA public key object whose identity
            will be summarized; its canonical encoding is hashed and later
            embedded into signatures to bind messages to this specific key.

    Returns:
        bytes: A 32-byte SHA-256 digest uniquely representing the provided
        public key in the protocol; suitable for inclusion in signed data or
        comparison during key verification.

    Raises:
        TypeError: If `public_key` is not a valid key object supported by
            `public_bytes`.
        ValueError: If the key cannot be serialized with the requested encoding
            and format.
        cryptography.exceptions.UnsupportedAlgorithm: If the backend does not
            support the key type or its parameters.
    """
    # Serialize key to canonical DER so all parties hash the exact same bytes
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Hash the encoded key with SHA-256 to obtain a stable, collision-resistant fingerprint
    return hashlib.sha256(der).digest()

# [DEFENSE NOTE]: Integrity
# The signature ensures the encrypted payload has not been modified.
def build_signed_message(text: str, signer, intended_recipient_key, session_key) -> bytes:
    """Encrypt and sign an outgoing chat message for authenticated, confidential transport.

    This function is the sending-side counterpart to ``unwrap_signed_message``: it
    provides confidentiality via symmetric AES encryption and binds the result to
    both the sender (signature) and the intended recipient (key fingerprint) to
    ensure authenticity and integrity. The resulting JSON blob is what is framed
    and sent over the wire in the secure messaging protocol.

    Internally, the function encodes the plaintext to bytes, encrypts it with
    the shared AES session key, prepends the recipient's key fingerprint to the
    ciphertext as the signature input, signs that byte sequence with the
    sender's RSA private key, then base64-encodes both ciphertext and signature
    into a compact JSON structure.

    Args:
        text (str): Human-readable message content to send; it is UTF-8 encoded
            before encryption so arbitrary text can be transmitted safely.
        signer (rsa.RSAPrivateKey): Sender's RSA private key used to generate a
            PSS/SHA-256 signature, proving authorship and protecting integrity of
            the encrypted payload.
        intended_recipient_key (rsa.RSAPublicKey): Recipient's RSA public key
            whose fingerprint is mixed into the signature input, cryptographically
            binding the message to this specific recipient and deterring key
            substitution attacks.
        session_key (bytes): Symmetric AES session key (e.g., 32 bytes for
            AES-256) shared between peers; used to encrypt the plaintext so only
            parties holding this key can recover the message content.

    Returns:
        bytes: UTF-8 encoded JSON document containing two base64-encoded fields:
            ``"enc"`` (the AES-encrypted payload produced by ``encrypt_payload``)
            and ``"sig"`` (the RSA-PSS signature over recipient fingerprint +
            ciphertext). This blob is ready to be length-prefixed and sent over
            the TCP channel.

    Raises:
        TypeError: If any argument is of an unexpected type or JSON serialization
            fails due to invalid data types.
        ValueError: If encryption or signing fail due to invalid key material or
            parameters, or if JSON serialization encounters invalid values.
        cryptography.exceptions.UnsupportedAlgorithm: If the configured backend
            does not support the RSA or hash algorithms used for signing.
    """
    # Encode user-supplied text to bytes for symmetric encryption
    plaintext = text.encode('utf-8')

    # Encrypt plaintext with shared AES session key (provides confidentiality)
    enc_blob = encrypt_payload(session_key, plaintext)

    # Bind message to intended recipient by hashing their public key into input
    signature_input = key_fingerprint(intended_recipient_key) + enc_blob

    # Sign (recipient fingerprint + ciphertext) with sender's RSA key
    # This combines authenticity (who sent) and integrity (what was sent, to whom)
    signature = signer.sign(
        signature_input,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        SHA256()
    )

    # Package ciphertext and signature as base64-encoded JSON for transport
    return json.dumps({
        'enc': base64.b64encode(enc_blob).decode(),
        'sig': base64.b64encode(signature).decode()
    }).encode()

def unwrap_signed_message(data: bytes, peer_public_key, private_key, session_key) -> str:
    """Verify the sender's signature and decrypt an encrypted message payload.

    This function is the receiving-side counterpart to `build_signed_message` in
    the secure messaging protocol. It ensures that the message was created by
    the expected peer (authenticity), has not been modified in transit
    (integrity), and that only a party with the shared session key can read its
    contents (confidentiality). By combining asymmetric signatures with
    symmetric encryption, it protects against tampering and key-substitution
    attacks.

    Internally, the function parses the signed bundle, base64-decodes the
    encrypted blob and signature, reconstructs the exact byte sequence that was
    originally signed (recipient key fingerprint + ciphertext), and uses the
    sender's public key to verify the signature. If the signature is valid, it
    decrypts the ciphertext with the shared AES session key and returns the
    resulting UTF‑8 text.

    Args:
        data (bytes): Raw JSON-encoded bundle received over the network,
            containing the base64-encoded encrypted payload and signature.
        peer_public_key: RSA public key object of the peer (sender), used to
            verify the digital signature and confirm the sender's identity.
        private_key: Local RSA private key object, whose public part identifies
            the intended recipient; used to derive the key fingerprint bound
            into the signature input.
        session_key (bytes): Symmetric AES session key shared between client and
            server, used to decrypt the encrypted payload once its integrity and
            authenticity have been verified.

    Returns:
        str: The decrypted message as a UTF‑8 string. Any invalid UTF‑8 byte
            sequences are ignored during decoding, but the verified plaintext
            bytes are otherwise returned unmodified.

    Raises:
        ValueError: If the signed ciphertext bundle is structurally incomplete
            (missing fields) or if signature verification fails.
        json.JSONDecodeError: If `data` is not valid JSON.
        binascii.Error: If the base64-encoded fields cannot be decoded.
        Exception: Any cryptographic or padding errors propagated from
            `decrypt_payload` (e.g., when ciphertext or key material is invalid).
    """
    # Parse incoming JSON bundle; must contain both encrypted blob and signature
    obj = json.loads(data.decode())
    enc_b64 = obj.get('enc')
    sig_b64 = obj.get('sig')
    
    # Basic structural validation of required fields before any crypto work
    if not enc_b64 or not sig_b64:
        raise ValueError('Missing signed ciphertext bundle')
    
    # Decode base64-encoded ciphertext and signature from transport-safe form
    enc_blob = base64.b64decode(enc_b64)
    signature = base64.b64decode(sig_b64)
    
    # Build the exact byte sequence that was signed: recipient fingerprint + ciphertext
    # This binds the message to the intended recipient and prevents key substitution
    signature_input = key_fingerprint(private_key.public_key()) + enc_blob
    try:
        # Verify the sender's signature using their RSA public key (authenticity + integrity)
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
        # Normalize any verification failure into a ValueError for callers
        raise ValueError('Signature verification failed') from exc
        
    # Decrypt the verified ciphertext using the shared AES session key (confidentiality)
    plaintext = decrypt_payload(session_key, enc_blob)
    # Decode bytes to text; ignore invalid sequences but preserve verified content
    return plaintext.decode(errors='ignore')

def receiver(sock, stop, private_key, peer_public_key, session_key):
    """Continuously receive, verify, and decrypt signed messages from the server.

    This function acts as the client's inbound message loop in the secure
    messaging protocol, ensuring that only authentic, untampered messages from
    the trusted server are displayed. It combines transport framing, signature
    verification, and symmetric decryption to preserve confidentiality,
    integrity, and authenticity for all incoming chat messages. On any security
    failure (e.g., invalid signature, decryption error) or disconnect, it
    cleanly terminates the receiving loop and signals the main thread to stop.

    Internally, the function repeatedly: (1) reads a length-prefixed frame from
    the TCP socket, (2) passes it to `unwrap_signed_message` to verify the
    server's signature and decrypt the payload, (3) interprets special control
    messages like "exit", and (4) prints verified plaintext messages to the
    console. Any network or cryptographic errors are treated as protocol
    failures, causing the loop to stop and the connection to be torn down.

    Args:
        sock (socket.socket): Connected TCP socket used to receive framed
            ciphertext/signature bundles from the server.
        stop (threading.Event): Shared shutdown flag used to coordinate
            termination with the main thread; set when the connection or
            protocol should be closed.
        private_key (rsa.RSAPrivateKey): Client's RSA private key whose public
            part identifies the intended recipient; its fingerprint is used
            inside `unwrap_signed_message` to bind messages to this client.
        peer_public_key (rsa.RSAPublicKey): Server's RSA public key used by
            `unwrap_signed_message` to verify digital signatures and ensure
            messages truly originate from the trusted server.
        session_key (bytes): Symmetric AES session key shared with the server,
            used inside `unwrap_signed_message` to decrypt the confidential
            payload once its integrity and authenticity are confirmed.

    Returns:
        None: This function runs until the connection is closed, a fatal error
        occurs, or a termination message is received. It signals shutdown by
        setting the ``stop`` event and then returns without a value.

    Raises:
        This function is designed to handle network and cryptographic exceptions
        internally. It does not intentionally propagate exceptions; unexpected
        errors cause the loop to terminate and the function to return.
    """
    # Main receive loop; runs until stop is signaled or a fatal condition occurs
    while not stop.is_set():
        try:
            # Receive and validate a single framed message from the TCP stream
            frame = recv_frame(sock)
            if not frame:
                # Treat missing/empty frame as remote disconnect and shut down
                print('Server disconnected. Closing...')
                stop.set()
                break

            try:
                # Verify server signature and decrypt payload (auth+integrity+confidentiality)
                text = unwrap_signed_message(frame, peer_public_key, private_key, session_key)
            except ValueError:
                # Signature or structural verification failure: treat as protocol attack/error
                print('Signature verification failed!')
                stop.set()
                break
            except Exception:
                # Any decryption/crypto failure implies message corruption or key issue
                print('Decryption failed.')
                stop.set()
                break

            # Handle server-initiated termination command
            if text.strip().lower() == 'exit':
                print('Server ended chat.')
                stop.set()
                break

            # Display verified and decrypted message to the user
            print(f'\nMessage Received{SIGNED_TAG}: {text}')
        except Exception:
            # Catch-all for unexpected network/logic errors; stop receiver safely
            stop.set()
            break

def run_client(host: str, port: int) -> None:
    """Establish and run a mutually authenticated, end-to-end encrypted chat session.

    This function drives the client side of the secure messaging protocol: it
    connects to the server, performs an RSA public-key exchange, sets up an
    AES-256 session key, and then sends/receives signed and encrypted messages.
    By combining asymmetric signatures with a symmetric session key, it provides
    confidentiality for message contents and authenticity and integrity for all
    traffic exchanged with the server.

    Internally, the function: (1) opens a TCP connection to the server, (2)
    generates the client's RSA keypair, (3) exchanges public keys with the
    server, (4) generates and RSA-OAEP–encrypts a fresh AES-256 session key to
    bootstrap the secure channel, (5) starts a background receiver thread that
    verifies signatures and decrypts incoming messages, and (6) enters an
    interactive loop that signs, encrypts, and sends user messages until exit.

    Args:
        host (str): Hostname or IP address of the secure messaging server to
            connect to; identifies the remote endpoint for the TCP connection.
        port (int): TCP port number on which the secure messaging server is
            listening; combined with `host` to form the transport address.

    Returns:
        None: Runs the client’s secure messaging loop until shutdown is
        requested or a fatal error occurs, then terminates without a return
        value.

    Raises:
        SystemExit: If the initial TCP connection cannot be established or the
            server's public key is not received.
        OSError: If network operations on the socket fail after connection
            (e.g., connection reset, send/recv errors).
        ValueError: If cryptographic setup or message construction fails due to
            invalid key material or malformed protocol data.
        Exception: Propagated from unexpected failures in threading or
            cryptographic helper functions.
    """
    # Establish outbound TCP connection to the declared secure messaging server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
    except Exception as e:
        # Fail fast on connection errors before any protocol state is created
        print(f'Connect failed: {e}')
        raise SystemExit(1)

    print(f'Connected to {host}:{port}')

    # Shared shutdown flag coordinating sender and background receiver thread
    stop = Event()

    # Generate a fresh RSA identity for this client (authenticity & signing)
    client_priv = generate_rsa_keypair()
    client_pub = client_priv.public_key()

    # Receive server's RSA public key (used to verify signatures & encrypt key)
    server_pub_pem = recv_frame(s)
    if not server_pub_pem:
        # Abort if server disconnects or sends no/invalid key material
        safe_close(s)
        raise SystemExit(1)

    # Deserialize server's public key from PEM for cryptographic operations
    server_pub = load_public_key(server_pub_pem)

    # Send our public key so the server can verify our signatures
    send_frame(s, serialize_public_key(client_pub))

    # Generate a fresh random AES-256 session key (confidentiality for messages)
    print("Generating Session Key...")
    session_key = os.urandom(32)  # AES-256 key (32 bytes)

    # Protect the session key using server's RSA key (hybrid encryption with OAEP)
    enc_session_key = server_pub.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Transmit the encrypted session key to complete secure-channel setup
    send_frame(s, enc_session_key)
    print("Session Key Sent. Secure Channel Ready.")

    # Start background thread to receive, verify, and decrypt incoming messages
    rcv = Thread(target=receiver, args=(s, stop, client_priv, server_pub, session_key), daemon=True)
    rcv.start()

    # Main send loop: read user input, sign & encrypt, then send over the wire
    while not stop.is_set():
        try:
            # Read plaintext input from the user for secure transmission
            msg = input('Type Message: ')
            if msg.strip().lower() == 'exit':
                # Send a signed, encrypted termination message before shutdown
                try:
                    send_frame(s, build_signed_message(msg, client_priv, server_pub, session_key))
                except Exception:
                    # Ignore send errors during shutdown; connection may be broken
                    pass
                stop.set()
                break

            # Sign and encrypt normal chat messages for confidentiality + integrity
            send_frame(s, build_signed_message(msg, client_priv, server_pub, session_key))
        except Exception:
            # Any unexpected error in the send loop triggers a clean shutdown
            stop.set()
            break

    # Let receiver thread finish processing before closing the transport
    rcv.join(timeout=1)
    safe_close(s)


if __name__ == '__main__':
    # Parse CLI arguments that specify the remote server endpoint
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()

    # Run the secure client with validated command-line parameters
    run_client(args.host, args.port)