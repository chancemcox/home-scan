"""Minimal RFC6455 WebSocket hub for dashboard push updates."""
import base64
import hashlib
import socket
import struct
import threading

GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
OP_TEXT, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x8, 0x9, 0xA
# Keep quieter than Docker Desktop / mobile idle timeouts (~2 minutes).
PING_INTERVAL = 20


def accept_key(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def frame(opcode, payload=b''):
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126: header += bytes([n])
    elif n < 65536: header += struct.pack('!BH', 126, n)
    else: header += struct.pack('!BQ', 127, n)
    return header + payload


class Client:
    def __init__(self, sock):
        self.sock = sock
        self.lock = threading.Lock()
        self.alive = True

    def send(self, opcode, payload=b''):
        with self.lock:
            if not self.alive: return
            self.sock.sendall(frame(opcode, payload))

    def send_text(self, text):
        self.send(OP_TEXT, text.encode() if isinstance(text, str) else text)

    def close(self):
        with self.lock:
            if not self.alive: return
            self.alive = False
            try: self.sock.sendall(frame(OP_CLOSE))
            except OSError: pass
            try: self.sock.shutdown(2)
            except OSError: pass
            try: self.sock.close()
            except OSError: pass

    def _read(self, n):
        chunks = []
        while n > 0:
            chunk = self.sock.recv(n)
            if not chunk: raise ConnectionError('closed')
            chunks.append(chunk)
            n -= len(chunk)
        return b''.join(chunks)

    def recv(self):
        header = self._read(2)
        opcode, length = header[0] & 0x0F, header[1] & 0x7F
        masked = bool(header[1] & 0x80)
        if length == 126: length = struct.unpack('!H', self._read(2))[0]
        elif length == 127: length = struct.unpack('!Q', self._read(8))[0]
        mask = self._read(4) if masked else b''
        payload = self._read(length)
        if masked: payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload


class Hub:
    def __init__(self):
        self._clients = set()
        self._lock = threading.Lock()

    def add(self, client):
        with self._lock: self._clients.add(client)

    def remove(self, client):
        with self._lock: self._clients.discard(client)
        client.close()

    def broadcast(self, text):
        with self._lock: clients = list(self._clients)
        dead = []
        for client in clients:
            try: client.send_text(text)
            except OSError: dead.append(client)
        for client in dead: self.remove(client)

    def serve(self, handler, snapshot):
        """Complete the HTTP upgrade on handler and stream until disconnect."""
        key = handler.headers.get('Sec-WebSocket-Key', '')
        if (handler.headers.get('Upgrade', '').lower() != 'websocket'
                or handler.headers.get('Connection', '').lower().find('upgrade') < 0
                or not key):
            return handler.send(400, b'{"error":"WebSocket upgrade required"}')
        handler.send_response(101, 'Switching Protocols')
        handler.send_header('Upgrade', 'websocket')
        handler.send_header('Connection', 'Upgrade')
        handler.send_header('Sec-WebSocket-Accept', accept_key(key))
        handler.end_headers()
        client = Client(handler.connection)
        try:
            client.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                client.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                client.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, 'TCP_KEEPCNT'):
                client.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError:
            pass
        client.sock.settimeout(PING_INTERVAL)
        self.add(client)
        try:
            client.send_text(snapshot())
            while client.alive:
                try:
                    opcode, payload = client.recv()
                except TimeoutError:
                    try: client.send(OP_PING)
                    except OSError: break
                    continue
                if opcode == OP_CLOSE: break
                if opcode == OP_PING: client.send(OP_PONG, payload)
        except (OSError, ConnectionError, struct.error):
            pass
        finally:
            self.remove(client)
