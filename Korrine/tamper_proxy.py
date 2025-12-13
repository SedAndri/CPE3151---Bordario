import argparse
import base64
import json
import socket
from threading import Thread, Event, Lock

MAX_FRAME_SIZE = 1_048_576

def safe_close(sock):
    """Safely shut down and close a socket, suppressing any errors.

    This function attempts to gracefully shut down both directions of the
    given socket before closing it. Any exceptions raised during shutdown
    or close are ignored, making it safe to call multiple times or on
    sockets that may already be closed or invalid.

    Args:
        sock: A socket-like object with ``shutdown`` and ``close`` methods,
            or ``None``. If ``None``, no action is taken.
    """
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
    """Send a length-prefixed data frame over a socket.

    This function transmits a single frame of binary data by first sending
    its length as a 4-byte big-endian integer, followed by the raw payload.

    Args:
        sock: A connected socket-like object that provides a ``sendall`` method.
        data (bytes): The binary payload to send.

    Raises:
        OSError: If the underlying socket operation fails.

    Module Purpose:
        This module provides helper utilities for sending and possibly
        tampering with framed (length-prefixed) data over a network socket.
    """
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def recv_exact(sock, n: int):
    """Receive exactly `n` bytes from a socket.

    This helper repeatedly calls `sock.recv()` until either `n` bytes have
    been read or the remote peer closes the connection.

    Args:
        sock: A socket-like object providing a `recv(bufsize: int) -> bytes` method.
        n: The exact number of bytes to read from the socket.

    Returns:
        bytes: A bytes object containing exactly `n` bytes if successful.
        None: If the connection is closed before `n` bytes can be read.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(sock):
    """Receive a single length-prefixed frame from a socket for the tamper proxy module.

    Frames are encoded as:
        - A 4-byte big-endian unsigned integer indicating the payload length.
        - Followed by exactly `length` bytes of payload.

    Args:
        sock: A socket-like object supporting a blocking recv method, used as
            the transport for framed messages.

    Returns:
        bytes | None: The full frame payload if successfully received and its
        length is within valid bounds; otherwise None if the connection is
        closed, the frame cannot be fully read, or the length is 0 or exceeds
        MAX_FRAME_SIZE.
    """
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = int.from_bytes(hdr, 'big')
    if length == 0 or length > MAX_FRAME_SIZE:
        return None
    body = recv_exact(sock, length)
    if not body:
        return None
    return body

def process_frame(data: bytes, direction: str, is_handshake: bool, mode: str):
    """Process a single WebSocket frame in the tamper proxy.
    Depending on the mode and whether the frame is part of the handshake,
    this function can forward the frame unchanged, inspect (peek) its
    contents, tamper with its ciphertext/payload, or mark it to be dropped.
    Diagnostic information about the action taken is printed to stdout.
    Args:
        data (bytes): Raw frame payload.
        direction (str): Human-readable direction label (e.g. 'C->S', 'S->C')
            used for logging.
        is_handshake (bool): True if this frame belongs to the initial
            handshake; handshake frames are always forwarded unchanged.
        mode (str): Operation mode. Supported values:
            - 'forward': Forward data as-is.
            - 'peek': Attempt to parse JSON and show a short preview of the
              base64-encoded ciphertext field 'c'; otherwise report non-JSON.
            - 'tamper': Attempt to parse JSON, flip the first byte of the
              decoded ciphertext field 'c' (or, if not JSON, flip the first
              byte of the raw payload), then re-encode and return it.
            - 'drop': Log and signal that the frame should be discarded.
            Any other value falls back to forwarding as-is.
    Returns:
        tuple[bytes, bool]: A tuple ``(payload, should_drop)`` where
            ``payload`` is the (possibly modified) frame data to send on,
            and ``should_drop`` indicates whether the caller should drop the
            frame instead of forwarding it.
    """
    if is_handshake:
        print(f'[{direction}] Handshake frame ({len(data)} bytes) forwarded.')
        return data, False

    if mode == 'forward':
        print(f'[{direction}] FORWARD ({len(data)} bytes).')
        return data, False

    if mode == 'peek':
        try:
            obj = json.loads(data.decode())
            cipher = base64.b64decode(obj.get('c', b''))
            preview = base64.b64encode(cipher[:32]).decode()
            print(f'[{direction}] PEEK -> cipher len {len(cipher)} bytes, head32 b64={preview}')
        except Exception:
            print(f'[{direction}] PEEK -> non-JSON payload ({len(data)} bytes).')
        return data, False

    if mode == 'tamper':
        try:
            obj = json.loads(data.decode())
            cipher = bytearray(base64.b64decode(obj['c']))
            if cipher:
                cipher[0] ^= 0xFF
            obj['c'] = base64.b64encode(bytes(cipher)).decode()
            tampered = json.dumps(obj).encode()
            print(f'[{direction}] TAMPER -> ciphertext corrupted.')
            return tampered, False
        except Exception:
            if data:
                buf = bytearray(data)
                buf[0] ^= 0xFF
                print(f'[{direction}] TAMPER -> raw flip on non-JSON frame.')
                return bytes(buf), False
            return data, False

    if mode == 'drop':
        print(f'[{direction}] DROP -> frame discarded ({len(data)} bytes).')
        return data, True

    return data, False

def pump(src, dst, direction, stop_evt, shared_state):
    """Continuously relay frames from one endpoint to another, with optional tampering.
    This function runs a loop that receives frames from `src`, classifies whether
    each frame is part of the handshake, passes the frame through `process_frame`,
    and then forwards the (possibly modified) frame to `dst` unless it should be
    dropped. It stops when the peer disconnects, an error occurs, or `stop_evt`
    is set.
    Parameters
    ----------
    src : socket.socket or file-like
        Source endpoint from which frames are read.
    dst : socket.socket or file-like
        Destination endpoint to which processed frames are written.
    direction : str
        Human-readable label for the traffic direction (e.g., "C->S", "S->C"),
        used only for logging.
    stop_evt : threading.Event
        Event used to coordinate shutdown between pump loops. The loop exits when
        this event is set, and will also set it on disconnection or errors.
    shared_state : dict
        Shared mutable state between the bidirectional pump tasks. Expected keys:
        - "lock": a threading.Lock (or compatible) guarding shared access.
        - "frames_forwarded": int counter of how many frames have been forwarded
          so far; used to detect handshake frames (the first two frames).
        - "mode": current tampering mode, passed to `process_frame` to control
          how frames are modified or dropped.
    Behavior
    --------
    - Treats the first two forwarded frames (per shared state) as handshake frames.
    - Calls `process_frame(frame, direction, is_handshake, mode)` to obtain the
      processed frame and a flag indicating whether it should be dropped.
    - Forwards non-dropped frames via `send_frame`.
    - Logs disconnects and errors, and ensures `stop_evt` is set so the other
      direction can terminate as well.
    """
    while not stop_evt.is_set():
        try:
            frame = recv_frame(src)
            if not frame:
                print(f'[{direction}] peer disconnected.')
                stop_evt.set()
                break

            with shared_state['lock']:
                is_handshake = shared_state['frames_forwarded'] < 2
                if is_handshake:
                    shared_state['frames_forwarded'] += 1
                mode = shared_state['mode']

            processed, should_drop = process_frame(frame, direction, is_handshake, mode)

            if should_drop:
                continue
            send_frame(dst, processed)
        except Exception as exc:
            print(f'[{direction}] error -> {exc}')
            stop_evt.set()
            break

def main():
    """Entry point for the MITM tampering proxy.
    This function parses command-line arguments, establishes a TCP connection
    to the real server, listens for a single client connection, and then
    bridges the two sockets via bidirectional pump threads.
    The module implements a simple man-in-the-middle proxy that can operate
    in several modes:
    - forward: transparently forwards all traffic unchanged
    - peek: logs (or inspects) encrypted/ciphertext frames without altering them
    - tamper: corrupts or modifies client-to-server frames before forwarding
    - drop: discards client-to-server frames instead of forwarding
    Once the proxy is running, it tracks basic state (such as the number of
    frames forwarded) and ensures that all sockets and threads are cleanly
    shut down when the proxy stops.
    """
    parser = argparse.ArgumentParser(description='MITM proxy with selectable attack modes.')
    parser.add_argument('--listen-host', default='127.0.0.1')
    parser.add_argument('--listen-port', type=int, default=9000)
    parser.add_argument('--server-host', default='127.0.0.1')
    parser.add_argument('--server-port', type=int, default=8000)
    parser.add_argument('--mode', choices=['forward', 'peek', 'tamper', 'drop'], default='tamper',     #mode change here
                        help='forward=transparent, peek=log ciphertext, tamper=corrupt C->S frames, drop=discard C->S frames')
    args = parser.parse_args()

    print('=== tamper_proxy ===')
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.connect((args.server_host, args.server_port))
    print(f'[SETUP] Connected to real server at {args.server_host}:{args.server_port}')

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(1)
    print(f'[SETUP] Listening for client on {args.listen_host}:{args.listen_port} ...')
    client_sock, client_addr = listener.accept()
    print(f'[SETUP] Client connected from {client_addr}')

    state = {
        'frames_forwarded': 0,
        'mode': args.mode,
        'lock': Lock(),
    }
    stop = Event()

    t_client = Thread(target=pump, args=(client_sock, srv_sock, 'CLIENT->SERVER', stop, state), daemon=True)
    t_server = Thread(target=pump, args=(srv_sock, client_sock, 'SERVER->CLIENT', stop, state), daemon=True)
    t_client.start()
    t_server.start()

    try:
        t_client.join()
        t_server.join()
    finally:
        stop.set()
        safe_close(client_sock)
        safe_close(srv_sock)
        safe_close(listener)
        print('[INFO] Proxy stopped.')

if __name__ == '__main__':
    main()
