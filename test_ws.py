import base64
import hashlib
import os
import socket
import struct
import threading
import time
import unittest

import ws


class WebSocketProtocolTest(unittest.TestCase):
    def test_accept_key_matches_rfc_sample(self):
        key = 'dGhlIHNhbXBsZSBub25jZQ=='
        expected = base64.b64encode(hashlib.sha1((key + ws.GUID).encode()).digest()).decode()
        self.assertEqual(ws.accept_key(key), expected)
        self.assertEqual(expected, 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')

    def test_frame_lengths(self):
        small = ws.frame(ws.OP_TEXT, b'hi')
        self.assertEqual(small[0], 0x81)
        self.assertEqual(small[1], 2)
        self.assertEqual(small[2:], b'hi')

        mid = ws.frame(ws.OP_PING, b'x' * 200)
        self.assertEqual(mid[0], 0x80 | ws.OP_PING)
        self.assertEqual(mid[1], 126)
        self.assertEqual(struct.unpack('!H', mid[2:4])[0], 200)
        self.assertEqual(mid[4:], b'x' * 200)

        large = ws.frame(ws.OP_TEXT, b'y' * 70000)
        self.assertEqual(large[1], 127)
        self.assertEqual(struct.unpack('!Q', large[2:10])[0], 70000)

    def test_ping_interval_beats_idle_proxy(self):
        self.assertLessEqual(ws.PING_INTERVAL, 30)


class HubTests(unittest.TestCase):
    def read_frame(self, sock):
        header = sock.recv(2)
        self.assertEqual(len(header), 2)
        opcode, length = header[0] & 0x0F, header[1] & 0x7F
        if length == 126:
            length = struct.unpack('!H', sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', sock.recv(8))[0]
        payload = b''
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            self.assertTrue(chunk)
            payload += chunk
        return opcode, payload

    def send_masked(self, sock, opcode, payload=b''):
        mask = os.urandom(4)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        header = bytes([0x80 | opcode, 0x80 | len(payload)]) + mask
        sock.sendall(header + body)

    def test_broadcast_and_dead_client_cleanup(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        hub = ws.Hub()
        client = ws.Client(left)
        hub.add(client)
        hub.broadcast('hello')
        opcode, payload = self.read_frame(right)
        self.assertEqual(opcode, ws.OP_TEXT)
        self.assertEqual(payload, b'hello')
        right.close()
        hub.broadcast('again')
        self.assertNotIn(client, hub._clients)

    def test_serve_rejects_non_websocket(self):
        hub = ws.Hub()
        sent = {}

        class Handler:
            headers = {'Upgrade': 'http', 'Connection': 'keep-alive'}
            def send(self, code, body):
                sent['code'] = code
                sent['body'] = body

        hub.serve(Handler(), lambda: '{}')
        self.assertEqual(sent['code'], 400)

    def test_serve_snapshot_ping_and_client_close(self):
        server_sock, client_sock = socket.socketpair()
        self.addCleanup(server_sock.close)
        self.addCleanup(client_sock.close)
        key = base64.b64encode(b'xxxxxxxxxxxxxxxx').decode()
        headers_out = []

        class Handler:
            def __init__(self):
                self.headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': key,
                }
                self.connection = server_sock
                self._buf = b''

            def send_response(self, code, message):
                headers_out.append((code, message))

            def send_header(self, name, value):
                headers_out.append((name, value))

            def end_headers(self):
                headers_out.append(('end', True))

        hub = ws.Hub()
        old = ws.PING_INTERVAL
        ws.PING_INTERVAL = 0.2
        done = threading.Event()

        def run():
            try:
                hub.serve(Handler(), lambda: '{"ok":true}')
            finally:
                done.set()

        try:
            threading.Thread(target=run, daemon=True).start()
            # The upgrade response is written through BaseHTTPRequestHandler.wfile in production;
            # our stub only records headers, then streams on the raw socket.
            deadline = time.time() + 2
            opcode = payload = None
            client_sock.settimeout(0.5)
            while time.time() < deadline:
                try:
                    opcode, payload = self.read_frame(client_sock)
                    break
                except (TimeoutError, BlockingIOError, OSError):
                    continue
            self.assertEqual(opcode, ws.OP_TEXT)
            self.assertEqual(payload, b'{"ok":true}')
            self.assertEqual(headers_out[0], (101, 'Switching Protocols'))
            self.assertIn(('Sec-WebSocket-Accept', ws.accept_key(key)), headers_out)

            ping = None
            deadline = time.time() + 2
            while time.time() < deadline:
                try:
                    opcode, payload = self.read_frame(client_sock)
                except (TimeoutError, BlockingIOError, OSError):
                    continue
                if opcode == ws.OP_PING:
                    ping = opcode
                    break
            self.assertEqual(ping, ws.OP_PING)
            self.send_masked(client_sock, ws.OP_CLOSE)
            self.assertTrue(done.wait(2))
            self.assertEqual(hub._clients, set())
        finally:
            ws.PING_INTERVAL = old


if __name__ == '__main__':
    unittest.main()
