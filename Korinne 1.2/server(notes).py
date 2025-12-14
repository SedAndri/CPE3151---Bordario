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
    """Safely and quietly tear down a TCP socket connection.

    In the secure messaging protocol, this helper ensures connections are
    closed in a controlled, best-effort way during error paths or normal
    shutdown, preventing resource leaks without introducing new failures in
    the cleanup phase. By reliably terminating sockets, it supports the
    protocol’s security guarantees by avoiding reuse of broken connections
    and helping ensure that stale sessions cannot continue exchanging data.

    The function (1) checks whether a socket object was provided, (2) attempts
    a full-duplex shutdown so both send and receive directions are closed,
    (3) then attempts to close the underlying file descriptor, and (4) suppresses
    any socket-related exceptions raised during these operations to keep caller
    shutdown logic simple and predictable.

    Args:
        sock (socket.socket | None): The TCP socket to shut down and close.
            May be ``None`` or already closed; in those cases the function
            simply returns without error. A valid, connected socket ensures
            that the protocol session is cleanly terminated on both ends.

    Returns:
        None: This function performs side effects only and does not return a
        value. After execution, the socket is best-effort shut down and closed
        and should not be used again.

    Raises:
        This function is designed not to propagate normal socket shutdown or
        close exceptions; they are caught and suppressed. Only unexpected
        programming errors (e.g., non-socket objects without ``shutdown`` or
        ``close`` attributes) may still surface as exceptions.
    """
    # Best-effort: close both send/recv directions if socket looks valid
    try:
        if sock:
            sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        # Swallow shutdown errors so cleanup never crashes callers
        pass

    # Finally, release the OS resource; ignore close-time errors
    try:
        if sock:
            sock.close()
    except Exception:
        # Suppress close errors to keep teardown robust and idempotent
        pass


def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send a single length-prefixed binary frame over a TCP socket.

    This helper encapsulates arbitrary application data (e.g., encrypted and/or
    signed payloads) into a fixed 4-byte length header plus body format so the
    receiver can reconstruct exact message boundaries from the raw TCP stream.
    Well-defined framing supports the secure messaging protocol by ensuring that
    ciphertexts and signatures are always processed over the intended, complete
    byte sequences, reducing the risk of truncation, concatenation, or parsing
    errors that could weaken integrity and authenticity guarantees.

    Internally, the function optionally validates the payload size, computes a
    4-byte big-endian length prefix, concatenates this header with the payload,
    and then uses ``sendall`` to transmit the entire frame atomically (or raise
    on failure). The receiver later uses the same length to read back exactly
    the same bytes for decryption and signature verification.

    Args:
        sock (socket.socket): A connected TCP socket over which the framed
            message will be sent. The socket must be open and writable so that
            the entire header and payload can be reliably transmitted.
        data (bytes): The already-encoded message payload to send (e.g.,
            encrypted+signed blob, serialized JSON). This must be a non-empty
            bytes-like object whose length does not exceed ``MAX_FRAME_SIZE``
            so that the peer can safely allocate buffers and enforce protocol
            limits.

    Returns:
        None: This function does not return a value. If it completes without
        raising an exception, the full frame (length header + payload) has been
        handed off to the OS for transmission to the peer.

    Raises:
        TypeError: If ``data`` is not a bytes-like object (``bytes`` or
            ``bytearray``), indicating an incorrect caller usage.
        ValueError: If ``data`` is empty or its length exceeds
            ``MAX_FRAME_SIZE``, indicating a protocol or safety violation that
            could lead to malformed frames or resource exhaustion.
        OSError: If the underlying ``socket.sendall`` call fails due to network
            errors, a closed/broken connection, or other low-level I/O issues.
    """
    # Validate that caller provided a bytes-like payload to keep framing strict
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be a bytes-like object")

    # Enforce protocol frame size bounds to prevent abuse / resource exhaustion
    if len(data) == 0 or len(data) > MAX_FRAME_SIZE:
        raise ValueError("frame payload size is invalid or exceeds protocol limits")

    # Compute 4-byte big-endian length header for robust, unambiguous framing
    length = len(data).to_bytes(4, 'big')

    # sendall ensures the entire framed message is transmitted or raises on error
    sock.sendall(length + data)


def recv_exact(sock, n: int):
    """Read exactly ``n`` bytes from a TCP socket or return ``None`` on EOF.

    In the secure messaging protocol, this helper enforces strict message
    boundaries by ensuring we reconstruct the exact number of bytes that were
    length-prefixed and sent by the peer. This is critical for safely applying
    cryptographic operations (e.g., decryption, signature verification) over the
    intended, complete payload, which supports confidentiality and integrity by
    preventing truncated or concatenated ciphertexts. By signaling early
    termination with ``None``, it also allows callers to detect clean disconnects
    or protocol violations and tear down the secure session safely.

    The function: (1) allocates a mutable buffer, (2) repeatedly calls
    ``sock.recv`` until ``n`` bytes have been collected or the peer closes the
    connection, and (3) returns the accumulated bytes as an immutable ``bytes``
    object, or ``None`` if the stream ends before ``n`` bytes are read.

    Args:
        sock (socket.socket): A connected TCP socket (or socket-like object)
            from which to read. Must provide a ``recv`` method compatible with
            the standard socket API so that framed, encrypted messages can be
            reconstructed exactly.
        n (int): The exact number of bytes to read. This should match the
            length declared in the frame header so that the full encrypted and/or
            signed message body is obtained without over- or under-reading.

    Returns:
        bytes | None: A ``bytes`` object containing exactly ``n`` bytes when
        successful, preserving the original framing for subsequent cryptographic
        processing; or ``None`` if the peer closes the connection before
        ``n`` bytes are received, allowing the caller to treat it as a clean
        disconnect or protocol violation.

    Raises:
        OSError: If a low-level socket error occurs during ``sock.recv`` (e.g.,
            connection reset, network failure).
        TypeError: If ``sock`` does not expose a compatible ``recv`` method or
            if ``n`` is not an integer accepted by ``recv``.
        ValueError: If the underlying socket is in an invalid state such that
            ``recv`` cannot proceed (propagated from the socket implementation).
    """
    # Buffer to accumulate bytes until requested length is reached
    buf = bytearray()
    # Loop until we have read exactly n bytes or detect a closed connection
    while len(buf) < n:
        # Core read operation; may return fewer bytes than requested
        chunk = sock.recv(n - len(buf))
        if not chunk:
            # Peer closed connection before full frame; signal caller with None
            return None
        buf.extend(chunk)
    # Return immutable bytes object for downstream cryptographic processing
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes | None:
    """Receive a single length-prefixed binary frame from a TCP socket.

    This function reconstructs one complete application-level frame from the raw
    TCP stream using a fixed 4-byte big-endian length prefix. In the secure
    messaging protocol, strict framing ensures that encrypted payloads and
    signatures are processed over the exact bytes that were sent, supporting
    confidentiality, integrity, and authenticity by preventing truncation or
    concatenation attacks. By enforcing size limits and returning ``None`` on
    protocol violations or clean disconnects, it helps callers safely decide
    when to terminate a secure session.

    Internally, the function (1) reads exactly 4 bytes for the length header,
    (2) parses and validates the announced payload size against protocol
    bounds, and (3) uses ``recv_exact`` to read exactly that many bytes as the
    frame body. If the peer closes the connection or an invalid length is
    observed, the function returns ``None`` to signal that no valid frame
    could be obtained.

    Args:
        sock (socket.socket): A connected TCP socket (or compatible object)
            from which to read the next framed message. The socket must be in
            a readable state so that the 4-byte header and full payload can be
            retrieved without blocking indefinitely or violating protocol limits.

    Returns:
        bytes | None: The raw frame payload as a ``bytes`` object when a valid
        length-prefixed frame is successfully read; or ``None`` if the peer
        closes the connection before a complete header/body is received, or if
        the declared length is zero or exceeds ``MAX_FRAME_SIZE`` (treated as a
        protocol violation and no frame is returned).

    Raises:
        OSError: Propagated from ``recv_exact`` if a low-level socket error
            occurs while reading the header or body (e.g., connection reset).
        TypeError: Propagated from ``recv_exact`` if ``sock`` is not a
            compatible socket-like object.
        ValueError: Propagated from ``recv_exact`` if the underlying socket is
            in an invalid state that prevents reading the requested number of
            bytes.

    """
    # Read the 4-byte big-endian length prefix; None means peer closed/EOF
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None

    # Parse and validate frame length to enforce protocol bounds and prevent abuse
    length = int.from_bytes(hdr, 'big')
    if length == 0 or length > MAX_FRAME_SIZE:
        # Treat invalid sizes as protocol violations and discard the frame
        return None

    # Read exactly 'length' bytes to reconstruct the full frame payload
    return recv_exact(sock, length)


def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    """Generate a new RSA private/public key pair using secure, modern defaults.

    This function provisions a fresh long-term identity key for a chat
    participant, which is later used to authenticate messages (signatures) and
    to decrypt session keys sent by peers. By basing all higher-level protocol
    operations on this key material, it underpins the channel’s authenticity
    (proving who sent what), integrity (detecting tampering), and
    confidentiality (via hybrid encryption of the AES session key).

    Internally, the function:
      1. Invokes the `cryptography` backend to generate a 2048-bit RSA key.
      2. Uses the industry-standard public exponent 65537 for a secure,
         well-studied balance between performance and robustness.
      3. Returns the private key object; callers derive the public key as
         needed via `private_key.public_key()` for exchange and verification.

    Args:
        None: All cryptographic parameters are fixed to recommended secure
            defaults (public_exponent=65537, key_size=2048) to avoid
            misconfiguration.

    Returns:
        rsa.RSAPrivateKey: A freshly generated RSA private key object
        representing both halves of the key pair. The corresponding public key
        can be obtained by calling `.public_key()` and is safe to share with
        peers for signature verification and RSA encryption of session keys.

    Raises:
        ValueError: If the backend rejects the provided key size or public
            exponent (e.g., due to unsupported parameters).
        cryptography.exceptions.UnsupportedAlgorithm: If the active
            cryptographic backend does not support RSA key generation.
        Exception: Any other unexpected errors propagated from the underlying
            cryptographic library during key generation.
    """
    # Generate a 2048-bit RSA key pair with standard exponent 65537
    # (well-vetted choice balancing security, interoperability, and performance)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def serialize_public_key(pub):
    """Serialize an RSA public key object into a PEM-encoded byte string.

    This function prepares a participant's long-term identity key for safe
    transmission or storage during the secure messaging protocol's handshake.
    By exporting the key in a standardized SubjectPublicKeyInfo PEM format, it
    enables peers to reliably reconstruct the exact public key used for later
    signature verification and session-key encryption, supporting authenticity
    and integrity of the channel setup.

    Internally, the function delegates to the `cryptography` library to:
      1. Encode the provided public key into DER using the SubjectPublicKeyInfo
         structure.
      2. Wrap the DER bytes in a text-friendly PEM container for transport.
      3. Return the resulting PEM-encoded bytes for use over the network or in
         persistent storage.

    Args:
        pub (rsa.RSAPublicKey): The RSA public key object to serialize. This is
            the identity key that peers will use to verify signatures and
            encrypt session keys, so it must be the exact key bound to the
            participant's identity.

    Returns:
        bytes: A PEM-encoded representation of the given public key, formatted
        as a SubjectPublicKeyInfo structure. These bytes are suitable for
        sending over the network or saving to disk and can be deserialized with
        standard PEM loaders on the receiving side.

    Raises:
        TypeError: If `pub` is not a valid public key object implementing
            `public_bytes`.
        ValueError: If the key object does not support the requested encoding
            or format parameters.
        cryptography.exceptions.UnsupportedAlgorithm: If the active backend
            cannot serialize the given key type or parameters.

    """
    # Serialize the public key using standard PEM + SubjectPublicKeyInfo format
    # (interoperable, unambiguous identity key representation for peers)
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(pem_bytes: bytes):
    """Load an RSA public key object from PEM-encoded bytes.

    This function reconstructs a peer's long-term identity public key from the
    PEM blob exchanged during the handshake, enabling later signature
    verification and RSA-based key encapsulation. By strictly parsing and
    validating the PEM structure, it helps ensure that only the intended,
    untampered identity key is used, supporting authenticity and integrity in
    the secure messaging protocol.

    Internally, the function delegates to
    ``cryptography.serialization.load_pem_public_key``, which parses the PEM
    container, validates that it holds a supported public key type, and returns
    a high-level key object. If the bytes are malformed or corrupted, an
    exception is raised immediately so that the protocol can abort instead of
    operating with an invalid or attacker-supplied key.

    Args:
        pem_bytes (bytes): PEM-encoded bytes representing the peer's public
            key, typically produced by :func:`serialize_public_key`. These
            bytes must match exactly what was sent by the peer so that the
            correct identity key is used for signature verification and
            RSA-based protection of the session key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: A
        deserialized RSA public key object ready for use in signature
        verification and RSA encryption within the rest of the protocol.

    Raises:
        ValueError: If the provided bytes are not valid PEM or do not contain a
            supported public key structure (e.g., truncated, corrupted, or
            tampered data).
        TypeError: If ``pem_bytes`` is not a bytes-like object accepted by the
            underlying cryptography loader.
        cryptography.exceptions.UnsupportedAlgorithm: If the encoded key uses
            an algorithm or parameters not supported by the active backend.
    """
    # Expect PEM-formatted bytes from the key-exchange handshake; any mismatch
    # here would break peer identity binding and later signature verification
    return serialization.load_pem_public_key(
        pem_bytes  # Parse & validate PEM, reconstructing the RSA public key object
    )

# [DEFENSE NOTE]: Confidentiality
# We use AES-256 (Symmetric) for the message body because it is fast and efficient.
# The 'session_key' was securely exchanged at startup.
def encrypt_payload(session_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a plaintext message with AES-CBC and package it into a JSON blob.

    This function provides confidentiality for chat messages by encrypting the
    raw plaintext with a symmetric AES session key that was previously
    negotiated via the RSA-based handshake. By returning a self-contained JSON
    structure that includes both the IV and ciphertext (Base64-encoded), it
    ensures the receiver has all parameters needed to safely decrypt while
    preventing an observer from learning the original content.

    Internally, the function: (1) generates a fresh random IV for CBC mode to
    ensure identical messages produce different ciphertexts, (2) applies PKCS7
    padding so the plaintext fits the AES block size, (3) encrypts using
    AES-256-CBC with the shared session key, and (4) encodes the IV and
    ciphertext with Base64 and serializes them into a UTF-8 JSON bytes blob for
    transport over the framed protocol.

    Args:
        session_key (bytes): Symmetric AES key used for encryption, typically
            a 32-byte key (AES-256) established during the session handshake.
            Only peers that possess this key can decrypt the resulting payload,
            which enforces message confidentiality.
        plaintext (bytes): Raw message content to be encrypted. Must be a
            bytes-like object; callers are responsible for encoding any
            higher-level text (e.g., UTF-8) before passing it in.

    Returns:
        bytes: A UTF-8 encoded JSON document containing two Base64-encoded
        fields: ``"i"`` (the IV) and ``"c"`` (the ciphertext). This packaged
        blob is suitable for direct transmission over the network and for
        subsequent decryption via :func:`decrypt_payload`.

    Raises:
        TypeError: If ``session_key`` or ``plaintext`` are not bytes-like
            objects accepted by the underlying cryptographic primitives.
        ValueError: If the provided key size or parameters are invalid for AES,
            or if padding/JSON serialization encounters malformed input.
        cryptography.exceptions.InvalidKey: If the session key is structurally
            invalid or rejected by the cryptography backend.
    """
    # Fresh random IV per message => same plaintext never produces same ciphertext
    iv = os.urandom(16)

    # PKCS7 pad plaintext to AES block size so CBC mode can encrypt safely
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # AES-CBC encryption using the shared symmetric session key
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Package IV + ciphertext as Base64 in a JSON object for transport
    obj = {
        'i': base64.b64encode(iv).decode(),          # Encode IV for JSON-safe transport
        'c': base64.b64encode(ciphertext).decode()   # Encode ciphertext for network transfer
    }

    # Serialize to bytes; caller sends this blob as the encrypted message body
    return json.dumps(obj).encode()

def decrypt_payload(session_key: bytes, data_bytes: bytes) -> bytes:
    """Decrypt an AES-CBC–encrypted JSON payload back into the original plaintext bytes.

    This function reverses the encryption performed by `encrypt_payload`, restoring
    message confidentiality by correctly unpacking, decrypting, and unpadding the
    ciphertext using the shared symmetric session key. By strictly reconstructing
    the IV and ciphertext from the JSON container, it ensures that decryption is
    applied to exactly the bytes produced during encryption, preserving integrity
    of the protected content within the secure messaging protocol.

    Internally, the function (1) parses the UTF-8 JSON blob into a Python object,
    (2) Base64-decodes the stored IV and ciphertext, (3) performs AES-256-CBC
    decryption with the provided session key, and (4) removes PKCS7 padding to
    recover the original plaintext bytes for higher-level processing.

    Args:
        session_key (bytes): The symmetric AES session key (typically 32 bytes
            for AES-256) previously negotiated during the handshake; only peers
            that possess this key can successfully decrypt the payload.
        data_bytes (bytes): UTF-8 encoded JSON bytes produced by
            :func:`encrypt_payload`, containing Base64-encoded fields ``"i"``
            (initialization vector) and ``"c"`` (ciphertext) needed for
            decryption.

    Returns:
        bytes: The decrypted, PKCS7-unpadded plaintext bytes exactly as they
        were provided to :func:`encrypt_payload`, ready for application-level
        decoding (e.g., UTF-8 string conversion) or further processing.

    Raises:
        json.JSONDecodeError: If ``data_bytes`` is not valid UTF-8 JSON or does
            not conform to the expected structure.
        KeyError: If the JSON object is missing the required ``"i"`` or
            ``"c"`` fields, indicating a malformed or tampered payload.
        binascii.Error: If Base64 decoding of the IV or ciphertext fails due to
            corrupted or invalid encoding.
        ValueError: If the AES decryption or PKCS7 unpadding fails (e.g.,
            incorrect key, wrong IV, or altered ciphertext), signaling a
            potential integrity or key mismatch issue.
    """
    # Parse JSON container holding Base64-encoded IV and ciphertext
    obj = json.loads(data_bytes.decode())
    # Decode IV and ciphertext back to raw bytes for AES-CBC decryption
    iv = base64.b64decode(obj['i'])
    ciphertext = base64.b64decode(obj['c'])
    
    # Recreate AES-CBC cipher with the shared session key and transmitted IV
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding to recover the original plaintext bytes
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def key_fingerprint(public_key) -> bytes:
    """Compute a stable SHA-256 fingerprint of a public key in canonical DER form.

    This fingerprint acts as a compact, collision-resistant identifier for a
    participant's long-term identity key, and is embedded into signatures to
    bind encrypted messages to their intended recipient. By hashing a
    canonicalized key representation, the protocol ensures that authenticity
    and integrity checks are performed against the exact public key originally
    exchanged during the handshake, preventing key-substitution attacks.

    Internally, the function:
      1. Serializes the given public key into a DER-encoded SubjectPublicKeyInfo
         structure to obtain a unique, unambiguous byte representation.
      2. Computes a SHA-256 hash over these DER bytes to derive a fixed-length
         fingerprint.
      3. Returns the raw 32-byte digest, which can be safely stored, compared,
         or combined into higher-level signature inputs.

    Args:
        public_key (rsa.RSAPublicKey): The public key whose identity fingerprint
            is to be derived. This must be the long-term identity key used in
            the protocol so that the resulting fingerprint reliably identifies
            the correct sender/recipient during signature verification.

    Returns:
        bytes: A 32-byte SHA-256 digest of the DER-encoded public key, serving
        as a compact, collision-resistant fingerprint that can be embedded in
        signatures or logs to strongly bind protocol messages to this key.

    Raises:
        TypeError: If ``public_key`` does not implement ``public_bytes`` with
            the required interface or is not a compatible key object.
        ValueError: If the key cannot be serialized using the specified DER
            encoding and SubjectPublicKeyInfo format (e.g., invalid parameters).
        cryptography.exceptions.UnsupportedAlgorithm: If the active
            cryptography backend does not support serializing this type of
            public key with the requested encoding/format.
    """
    # Expect a cryptography public key object; derive a canonical binary form (DER)
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Hash canonical DER with SHA-256 to get a collision-resistant key identity
    return hashlib.sha256(der).digest()

# [DEFENSE NOTE]: Integrity & Non-Repudiation
# We sign the encrypted blob + recipient fingerprint.
# - Integrity: Changes to the ciphertext will break the signature.
# - Non-Repudiation: Only the sender's Private Key could create this signature.
def build_signed_message(text: str, signer, intended_recipient_key, session_key) -> bytes:
    """Build a signed-and-encrypted message bundle for transmission to a peer.

    This function provides confidentiality, integrity, and authenticity for an
    outgoing chat message by first encrypting the plaintext with a shared AES
    session key, then signing the resulting ciphertext together with the
    intended recipient's public-key fingerprint. The recipient can later verify
    that the message was created by the holder of the sender's private key and
    that it was explicitly bound to their own public key, preventing message
    tampering and misdelivery attacks.

    Internally, the function (1) encodes the plaintext string to UTF-8 bytes,
    (2) encrypts those bytes using the shared session key via
    :func:`encrypt_payload`, (3) derives a SHA-256 fingerprint of the recipient
    public key and concatenates it with the encrypted blob as the signature
    input, (4) computes an RSA-PSS signature over that input using the sender's
    private key, and (5) packages the Base64-encoded ciphertext and signature
    into a UTF-8 encoded JSON object for transport.

    Args:
        text (str): Human-readable message content to be protected. This is
            encoded as UTF-8 before encryption so that arbitrary Unicode text
            can be safely transmitted.
        signer (rsa.RSAPrivateKey): The sender's RSA private key used to create
            the digital signature. Possession of this key proves authorship and
            enables the receiver to verify authenticity and integrity.
        intended_recipient_key (rsa.RSAPublicKey): The recipient's RSA public
            key whose fingerprint is mixed into the signature input. Binding
            the ciphertext to this key prevents a valid signed message from
            being credibly forwarded to or claimed by a different recipient.
        session_key (bytes): Symmetric AES session key (e.g., 32 bytes for
            AES-256) used by :func:`encrypt_payload` to encrypt the plaintext.
            Only peers that know this key can decrypt the message, providing
            confidentiality.

    Returns:
        bytes: A UTF-8 encoded JSON document containing two Base64-encoded
        fields: ``"enc"`` (the encrypted payload produced by
        :func:`encrypt_payload`) and ``"sig"`` (the RSA-PSS signature over the
        recipient fingerprint + encrypted blob). This bundle is ready to be
        sent as a single framed message and later consumed by
        :func:`unwrap_signed_message`.

    Raises:
        TypeError: If the keys or session key are not of the expected types
            accepted by the underlying cryptographic primitives.
        ValueError: If signing fails due to an invalid key, parameters, or
            configuration, or if JSON serialization cannot encode the bundle.
        cryptography.exceptions.UnsupportedAlgorithm: If the active
            cryptographic backend does not support the requested RSA-PSS or
            hashing algorithms for signing.
    """
    # Convert user-facing text into bytes for cryptographic processing
    plaintext = text.encode('utf-8')

    # Encrypt plaintext with the shared AES session key for confidentiality
    enc_blob = encrypt_payload(session_key, plaintext)

    # Bind ciphertext to the specific recipient by including their key fingerprint
    signature_input = key_fingerprint(intended_recipient_key) + enc_blob

    # Sign with sender private key (recipient_fingerprint || ciphertext) using RSA-PSS for integrity/authenticity
    signature = signer.sign(
        signature_input,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        SHA256()
    )

    # Package encrypted payload and signature as Base64 in a JSON message
    return json.dumps({
        'enc': base64.b64encode(enc_blob).decode(),
        'sig': base64.b64encode(signature).decode()
    }).encode()

# [DEFENSE NOTE]: Authentication
# Verification proves the message came from the holder of the expected Private Key.
def unwrap_signed_message(data: bytes, peer_public_key, private_key, session_key) -> str:
    """Verify and decrypt a signed message bundle received from a peer.

    This function enforces authenticity, integrity, and confidentiality for an
    incoming chat message by validating the sender's RSA signature over the
    encrypted payload and the intended recipient's key fingerprint before
    attempting decryption. Only if the bundle is structurally valid and the
    signature matches the expected peer key will the AES-encrypted content be
    decrypted with the shared session key and returned as a UTF-8 string. This
    ordering (verify-then-decrypt) prevents decryption of unauthenticated data
    and helps protect against tampering, misdelivery, and spoofing attacks in
    the secure messaging protocol.

    Internally, the function:
      1. Parses the outer JSON container and extracts the Base64-encoded
         ciphertext and signature.
      2. Reconstructs the original encrypted blob and signature from Base64.
      3. Builds the signature input by concatenating this recipient's public-key
         fingerprint with the encrypted blob, then verifies it with the peer's
         public key using RSA-PSS and SHA-256.
      4. On successful verification, decrypts the encrypted blob with the shared
         AES session key and returns the resulting plaintext as text.

    Args:
        data (bytes): UTF-8 encoded JSON message received over the network,
            containing two Base64-encoded fields: ``"enc"`` (the encrypted
            payload) and ``"sig"`` (the RSA-PSS signature). This is the raw
            framed payload produced by :func:`build_signed_message`.
        peer_public_key (rsa.RSAPublicKey): The sender's long-term RSA public
            key used to verify the digital signature. This binds the message to
            the expected peer and detects any tampering of the encrypted blob
            and recipient binding.
        private_key (rsa.RSAPrivateKey): Our own RSA private key, used only to
            derive our corresponding public key so that our key fingerprint can
            be recomputed and mixed into the signature input. This ensures the
            message was explicitly intended for this recipient and cannot be
            credibly forwarded to another party.
        session_key (bytes): The symmetric AES session key shared between us and
            the peer, used by :func:`decrypt_payload` to decrypt the ciphertext
            once its authenticity and integrity have been established.

    Returns:
        str: The verified and decrypted message as a UTF-8 string. Any
        non-decodable bytes are ignored during decoding, ensuring the function
        always returns a string upon successful verification and decryption.

    Raises:
        ValueError: If the JSON bundle is missing required fields, or if the
            signature verification fails (indicating tampering, wrong sender, or
            a message not intended for this recipient).
        json.JSONDecodeError: If ``data`` is not valid UTF-8 JSON or does not
            parse into an object.
        binascii.Error: If Base64 decoding of the encrypted payload or
            signature fails due to invalid encoding.
        Exception: Any lower-level cryptographic or decryption errors
            propagated from :func:`decrypt_payload` (e.g., wrong session key,
            corrupted ciphertext) that prevent recovering the plaintext.

    """
    # Parse outer JSON wrapper and pull out Base64-encoded ciphertext/signature
    obj = json.loads(data.decode())
    enc_b64 = obj.get('enc')
    sig_b64 = obj.get('sig')

    # Basic structural validation: both components of the signed bundle must exist
    if not enc_b64 or not sig_b64:
        raise ValueError('Missing signed ciphertext bundle')

    # Decode encrypted blob and signature back to raw bytes
    enc_blob = base64.b64decode(enc_b64)
    signature = base64.b64decode(sig_b64)

    # Build signature input: bind ciphertext to THIS recipient via our key fingerprint
    signature_input = key_fingerprint(private_key.public_key()) + enc_blob

    # Verify sender's RSA-PSS signature before decrypting (authenticate + integrity check)
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
        # Normalize any verification failure as ValueError for the caller
        raise ValueError('Signature verification failed') from exc

    # Decrypt the verified ciphertext using the shared AES session key
    plaintext = decrypt_payload(session_key, enc_blob)

    # Return UTF-8 text form of the plaintext; ignore stray non-text bytes
    return plaintext.decode(errors='ignore')

def receiveMsg(conn, stop, private_key, peer_public_key, session_key):
    """Receive, verify, decrypt, and display signed chat messages from a peer.

    This function runs as the inbound loop for the secure chat session, reading
    framed messages from the TCP connection and enforcing authenticity,
    integrity, and confidentiality before displaying any plaintext. It delegates
    signature verification, recipient binding, and AES decryption to
    `unwrap_signed_message`, and coordinates clean session teardown on errors or
    disconnects.

    High-level steps:
        1. Continuously read the next length-prefixed frame from the socket.
        2. Use `unwrap_signed_message` to verify the RSA signature (with
           recipient fingerprint binding) and decrypt the AES-encrypted payload.
        3. Interpret control messages such as "exit" to end the chat gracefully.
        4. Print verified messages and shut down on any verification, decryption,
           or connection errors.

    Args:
        conn (socket.socket): Active TCP connection to the peer, used as the
            source of length-prefixed, encrypted, and signed message frames.
        stop (threading.Event): Shared shutdown flag that is set to signal this
            loop and other threads to terminate when the session ends or on
            fatal errors.
        private_key (rsa.RSAPrivateKey): This party's RSA private key, used
            indirectly by `unwrap_signed_message` to derive our public key and
            fingerprint, ensuring messages were explicitly intended for this
            recipient.
        peer_public_key (rsa.RSAPublicKey): Peer’s long-term RSA public key,
            used by `unwrap_signed_message` to verify the digital signature and
            thus the sender’s identity and the integrity of each message.
        session_key (bytes): Shared symmetric AES session key used by
            `unwrap_signed_message` to decrypt the ciphertext, providing
            confidentiality for incoming messages.

    Returns:
        None: The function runs until the connection is closed, an "exit"
        control message is received, or `stop` is set. It closes `conn` as a
        side effect before returning.

    Raises:
        This function is designed to catch and handle normal network and
        cryptographic errors internally; such exceptions trigger `stop` and a
        clean shutdown instead of being propagated. Only unexpected conditions
        outside the generic `Exception` handling (e.g., interpreter shutdown)
        may escape.
    """
    # Main receive loop; exit when shutdown is requested
    while not stop.is_set():
        try:
            # Read the next framed message; None/empty signals peer disconnect
            frame = recv_frame(conn)
            if not frame:
                print('Peer disconnected. Closing...')
                stop.set()
                break

            try:
                # Verify signature + recipient binding and decrypt payload
                # Ensures authenticity, integrity, and confidentiality
                text = unwrap_signed_message(frame, peer_public_key, private_key, session_key)
            except ValueError:
                # Signature/recipient check failed -> possible tampering; abort
                print('Signature verification failed!')
                stop.set()
                break
            except Exception:
                # Any decryption/crypto failure is treated as fatal for safety
                print('Decryption failed.')
                stop.set()
                break

            # Interpret "exit" as a peer-initiated graceful shutdown
            if text.strip().lower() == 'exit':
                print('Peer ended chat.')
                stop.set()
                break

            # Display verified plaintext, tagged as having a valid signature
            print(f'\nMessage Received{SIGNED_TAG}: {text}')
        except Exception:
            # Catch unexpected I/O/logic errors, signal shutdown, and exit loop
            stop.set()
            break

    # Ensure the underlying socket is closed when the receive loop terminates
    safe_close(conn)

def sendMessage(conn, stop, peer_public_key, private_key, session_key):
    """Read user input, build signed-and-encrypted messages, and send them to the peer.

    This function acts as the outbound loop of the secure chat protocol, taking
    plaintext input from the user, wrapping it in a signed-and-encrypted bundle,
    and transmitting it as length-prefixed frames. By consistently using the
    shared AES session key and the RSA key pair, it ensures that all outgoing
    messages provide confidentiality (encryption), integrity, and authenticity
    (signatures) to the remote party.

    Internally, the function repeatedly: (1) reads a line of input from the
    console, (2) checks for an "exit" command to trigger a graceful shutdown,
    (3) calls :func:`build_signed_message` to encrypt and sign the message for
    the intended recipient, and (4) uses :func:`send_frame` to send the
    resulting binary bundle over the TCP connection. Any error during message
    construction or transmission causes the loop to set the shared stop flag
    and terminate to avoid using a potentially compromised connection.

    Args:
        conn (socket.socket): Active TCP connection to the peer; used to send
            length-prefixed, signed-and-encrypted message frames over the
            established secure channel.
        stop (threading.Event): Shared shutdown flag; when set, the send loop
            stops reading input and exits, coordinating termination with the
            receive loop.
        peer_public_key (rsa.RSAPublicKey): The recipient's long-term RSA public
            key, used by :func:`build_signed_message` to bind signatures to the
            intended peer and prevent credible message forwarding to others.
        private_key (rsa.RSAPrivateKey): This party's RSA private key; used to
            digitally sign each outgoing encrypted message, proving authorship
            and protecting integrity.
        session_key (bytes): Shared symmetric AES session key for this session;
            used by :func:`build_signed_message` to encrypt plaintext so only
            the peer that knows this key can read the message contents.

    Returns:
        None: The function runs until the user types "exit", the connection
        fails, or ``stop`` is set. It sends any final "exit" message (if
        possible) before cleanly breaking out of the loop.

    Raises:
        This function is designed to catch and handle generic exceptions
        internally (e.g., I/O or cryptographic errors) by setting ``stop`` and
        exiting the loop. Only unexpected errors that occur before the main
        try/except block (such as programmer mistakes in argument types) may
        propagate.
    """
    # Main send loop; exit when shutdown flag is set
    while not stop.is_set():
        try:
            # Input parsing: read next user message as plaintext
            msg = input('Type Message: ')

            # Check for user-initiated graceful shutdown
            if msg.strip().lower() == 'exit':
                try:
                    # Sign + encrypt the exit notice and send before closing
                    send_frame(conn, build_signed_message(msg, private_key, peer_public_key, session_key))
                except Exception:
                    # Best-effort: ignore send failures on shutdown
                    pass
                # Signal all threads to stop and break send loop
                stop.set()
                break

            # Normal message path: build signed+encrypted bundle and send
            send_frame(conn, build_signed_message(msg, private_key, peer_public_key, session_key))
        except Exception:
            # Any error (I/O/crypto) triggers session shutdown for safety
            stop.set()
            break

def listenConnection(host='127.0.0.1', port=8000):
    """Create a TCP listening socket and accept a single incoming client connection.

    This function is the entry point for establishing the underlying transport
    channel over which all encrypted and authenticated messages are exchanged.
    By binding to a specific interface and port and then accepting exactly one
    client, it provides a dedicated, long-lived TCP connection that higher-level
    cryptographic handshakes (RSA key exchange, session key setup) can securely
    run on top of. While this function itself does not perform encryption, it
    sets up the reliable, ordered, byte-stream foundation required for the
    protocol’s confidentiality, integrity, and authenticity guarantees.

    Internally, the function:
      1. Creates a TCP (AF_INET, SOCK_STREAM) socket.
      2. Enables address reuse so the server can restart quickly on the same port.
      3. Binds the socket to the requested host/port and starts listening.
      4. Blocks until a client connects, then returns the accepted connection
         along with the client address and the listening socket.

    Args:
        host (str): IP address or hostname on which to listen (e.g. "127.0.0.1").
            Controls which network interface accepts incoming connections and
            therefore who can initiate a secure session.
        port (int): TCP port number to bind the listening socket to. Must be a
            valid, available port on the host OS; determines where clients must
            connect to start the secure messaging protocol.

    Returns:
        tuple[socket.socket, tuple[str, int], socket.socket]:
            A 3-tuple ``(conn, addr, s)`` where:
            * ``conn`` is the newly accepted per-client TCP socket used for all
              subsequent framed, encrypted, and signed message exchange.
            * ``addr`` is the client's address tuple (ip, port), useful for
              logging or access control.
            * ``s`` is the listening server socket, which should be closed when
              the server is shutting down.

    Raises:
        OSError: If socket creation, option setting, binding, listening, or
            accepting the connection fails (e.g., port in use, insufficient
            privileges, network errors).
        ValueError: If the provided host or port are invalid for socket binding,
            as determined by the underlying OS and socket implementation.
    """
    # Create a TCP socket to accept incoming secure chat connections
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow quick server restart by reusing the address/port without long TIME_WAIT
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind listener to specific interface/port; OS enforces which peers can reach it
    s.bind((host, port))
    print(f'Server listening on {host}:{port} ...')

    # Start listening; limit backlog to a single pending client for this demo
    s.listen(1)

    # Block until a client connects; returns dedicated socket for this session
    conn, addr = s.accept()
    print(f'Accepted connection from {addr}')

    # Return client socket, client address, and listening socket for lifecycle control
    return conn, addr, s

if __name__ == '__main__':
    # Parse CLI arguments to determine where the server will listen
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()

    """Run the secure chat server and perform the full cryptographic handshake.

    This function acts as the authenticated, encrypted entry point of the server
    side of the messaging protocol, setting up long-term RSA identities,
    establishing an ephemeral AES session key, and then launching the secure
    bidirectional chat loops. By orchestrating key generation, key exchange,
    and message-thread startup, it ensures confidentiality (AES encryption),
    integrity, and authenticity (RSA signatures and key binding) for all
    subsequent messages over a single TCP connection.

    High-level steps:
      1. Listen for an incoming TCP connection from a client.
      2. Generate the server's RSA key pair and exchange public keys with the client.
      3. Receive and RSA-decrypt the client-generated AES session key
         (hybrid encryption handshake).
      4. Start concurrent send/receive threads that sign, encrypt, verify, and
         decrypt all chat messages using the established keys.
      5. Cleanly shut down sockets and threads on error or when the session ends.

    Args:
        host (str): Interface/IP address on which the server listens. Determines
            which peers can reach this secure messaging endpoint.
        port (int): TCP port number on which to accept the incoming connection.
            Must match the client's target port so the handshake can begin.

    Returns:
        None: This function blocks until the chat session completes or a fatal
        error occurs, then closes the underlying sockets as a side effect.

    Raises:
        RuntimeError: If the public-key exchange fails (e.g., missing peer key
            frame) and a secure channel cannot be established.
        OSError: If socket operations (binding, accepting, sending, or receiving)
            fail due to network or OS-level issues.
        cryptography.exceptions.InvalidKey: If RSA/AES operations fail because
            of invalid or incompatible key material.
        Exception: Propagated for any unexpected cryptographic or threading
            errors that occur before the main try/finally cleanup.
    """
    # Create a shared shutdown flag for coordinating sender/receiver threads
    stop = Event()

    # Establish the underlying TCP transport for the secure channel
    conn, addr, srv_sock = listenConnection(args.host, args.port)

    try:
        # Generate a fresh long-term RSA identity for this server instance
        server_priv = generate_rsa_keypair()
        server_pub = server_priv.public_key()

        # Exchange RSA public keys so each side can verify signatures and
        # decrypt the hybrid-encrypted session key
        send_frame(conn, serialize_public_key(server_pub))
        peer_pub_pem = recv_frame(conn)
        if not peer_pub_pem:
            # Abort if the client does not provide a valid public key
            raise RuntimeError('Key exchange failed.')
        peer_pub = load_public_key(peer_pub_pem)

        # Receive the AES session key that the client encrypted with our
        # public RSA key (hybrid encryption: RSA for key, AES for data)
        print("Waiting for Session Key...")
        enc_session_key = recv_frame(conn)

        # Use the server's RSA private key to unwrap the symmetric AES key,
        # ensuring only the intended server can derive the session key
        session_key = server_priv.decrypt(
            enc_session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )
        print("Secure Session Key Established.")

        # Start the inbound message thread (verify signatures + decrypt payloads)
        rcv = Thread(
            target=receiveMsg,
            args=(conn, stop, server_priv, peer_pub, session_key),
            daemon=True,
        )
        rcv.start()

        # Run the outbound loop (sign + encrypt messages and send as frames)
        sendMessage(conn, stop, peer_pub, server_priv, session_key)

        # Give the receiver thread a brief chance to finish cleanup
        rcv.join(timeout=1)

    finally:
        # Ensure sockets are always torn down to avoid stale secure sessions
        safe_close(conn)
        safe_close(srv_sock)