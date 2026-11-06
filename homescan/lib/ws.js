import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

export const OP_TEXT = 0x1;
export const OP_CLOSE = 0x8;
export const OP_PING = 0x9;
export const OP_PONG = 0xA;
export const PING_INTERVAL = 20;

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export function acceptKey(key) {
  return crypto.createHash('sha1').update(String(key) + GUID).digest('base64');
}

function frame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const header = [0x80 | opcode];
  if (data.length < 126) header.push(data.length);
  else if (data.length < 65536) header.push(126, (data.length >> 8) & 255, data.length & 255);
  else {
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(data.length));
    header.push(127, ...len);
  }
  return Buffer.concat([Buffer.from(header), data]);
}

export class Hub extends EventEmitter {
  constructor() {
    super();
    this.clients = new Set();
  }
  broadcast(text) {
    const packet = frame(OP_TEXT, text);
    for (const socket of [...this.clients]) {
      try { socket.write(packet); }
      catch { this.clients.delete(socket); }
    }
  }
  serve(socket, head, snapshot) {
    this.clients.add(socket);
    socket.write(frame(OP_TEXT, snapshot()));
    const timer = setInterval(() => {
      try { socket.write(frame(OP_PING, Buffer.alloc(0))); }
      catch { this.clients.delete(socket); }
    }, PING_INTERVAL * 1000);
    socket.on('data', (chunk) => this._consume(socket, chunk));
    socket.on('close', () => { clearInterval(timer); this.clients.delete(socket); });
    socket.on('error', () => { clearInterval(timer); this.clients.delete(socket); });
    if (head && head.length) socket.unshift(head);
  }
  _consume(socket, chunk) {
    if (!socket._wsBuf) socket._wsBuf = Buffer.alloc(0);
    socket._wsBuf = Buffer.concat([socket._wsBuf, chunk]);
    while (socket._wsBuf.length >= 2) {
      const buf = socket._wsBuf;
      const opcode = buf[0] & 0x0f;
      let length = buf[1] & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (buf.length < 4) return;
        length = buf.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (buf.length < 10) return;
        length = Number(buf.readBigUInt64BE(2));
        offset = 10;
      }
      const masked = (buf[1] & 0x80) !== 0;
      if (masked) offset += 4;
      if (buf.length < offset + length) return;
      let payload = buf.subarray(offset, offset + length);
      if (masked) {
        const mask = buf.subarray(offset - 4, offset);
        payload = Buffer.from(payload.map((byte, index) => byte ^ mask[index % 4]));
      }
      socket._wsBuf = buf.subarray(offset + length);
      if (opcode === OP_CLOSE) { try { socket.end(frame(OP_CLOSE, Buffer.alloc(0))); } catch { /* ignore */ } return; }
      if (opcode === OP_PING) { try { socket.write(frame(OP_PONG, payload)); } catch { /* ignore */ } }
      if (opcode === OP_TEXT) this.emit('text', socket, payload.toString('utf8'));
    }
  }
}

export function handshakeHeaders(key) {
  return [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey(key)}`,
    '', '',
  ].join('\r\n');
}
