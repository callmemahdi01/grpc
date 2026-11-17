import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = '';
const TARGET_PORT = 0;
const CONNECT_TIMEOUT_MS = 5000;
const MAX_FRAME = 1 << 20;

const USER_ID = Uint8Array.from(UUID.replace(/-/g, '').match(/../g), (h) => parseInt(h, 16));
const PATHS = new Set([`/${SERVICE_NAME}/Tun`, `/${SERVICE_NAME}/TunMulti`]);
const decoder = new TextDecoder();

const concat = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

const encodeFrame = (data) => {
  const n = data.length;
  let v = n;
  let varintLength = 1;
  while (v >= 128) {
    v >>>= 7;
    varintLength++;
  }
  const messageLength = 1 + varintLength + n;
  const out = new Uint8Array(5 + messageLength);
  new DataView(out.buffer).setUint32(1, messageLength);
  out[5] = 10;
  let o = 6;
  v = n;
  while (v >= 128) {
    out[o++] = (v & 127) | 128;
    v >>>= 7;
  }
  out[o++] = v;
  out.set(data, o);
  return out;
};

const parseHeader = (d) => {
  if (d.length < 22 || d[0] !== 0) return null;
  for (let i = 0; i < 16; i++) if (d[1 + i] !== USER_ID[i]) return null;
  let p = 18 + d[17];
  if (p + 4 > d.length) return null;
  const cmd = d[p];
  const port = (d[p + 1] << 8) | d[p + 2];
  const type = d[p + 3];
  p += 4;
  let host;
  if (type === 1) {
    if (p + 4 > d.length) return null;
    host = d.subarray(p, p + 4).join('.');
    p += 4;
  } else if (type === 2) {
    const length = d[p++];
    if (!length || p + length > d.length) return null;
    host = decoder.decode(d.subarray(p, p + length));
    p += length;
  } else if (type === 3) {
    if (p + 16 > d.length) return null;
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((d[p + i] << 8) | d[p + i + 1]).toString(16));
    host = groups.join(':');
    p += 16;
  } else {
    return null;
  }
  return { version: d[0], cmd, port, host, offset: p };
};

const open = async (hostname, port) => {
  const socket = connect({ hostname, port });
  let timer;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(reject, CONNECT_TIMEOUT_MS, new Error('timeout'));
      }),
    ]);
    return socket;
  } catch (error) {
    try {
      socket.close();
    } catch {}
    throw error;
  } finally {
    clearTimeout(timer);
  }
};

const dial = async ({ host, port }) => {
  try {
    return await open(host, port);
  } catch (error) {
    if (!TARGET_HOST) throw error;
    return open(TARGET_HOST, TARGET_PORT || port);
  }
};

const pipeDown = async (socket, out, version, stop) => {
  const reader = socket.readable.getReader();
  let head = new Uint8Array([version, 0]);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      await out.write(encodeFrame(head ? concat(head, value) : value));
      head = null;
    }
    if (head) await out.write(encodeFrame(head));
    await out.close();
  } catch (error) {
    try {
      await out.abort(error);
    } catch {}
  } finally {
    try {
      socket.close();
    } catch {}
    stop();
  }
};

const tunnel = async (request, writable) => {
  const out = writable.getWriter();
  const reader = request.body.getReader();
  let socket;
  let sink;
  let downlink;
  let buf = new Uint8Array(0);
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf = buf.length ? concat(buf, value) : value;
      let off = 0;
      while (buf.length - off >= 5) {
        if (buf[off] !== 0) throw new Error('compressed');
        const length = new DataView(buf.buffer, buf.byteOffset + off + 1, 4).getUint32(0);
        if (length > MAX_FRAME) throw new Error('frame too large');
        if (buf.length - off < 5 + length) break;
        const message = buf.subarray(off + 5, off + 5 + length);
        off += 5 + length;
        for (let i = 0; i < message.length; ) {
          if (message[i++] !== 10) throw new Error('bad message');
          let n = 0;
          let shift = 0;
          let byte;
          do {
            byte = message[i++];
            n |= (byte & 127) << shift;
            shift += 7;
          } while (byte & 128 && shift < 28);
          if (byte & 128 || i + n > message.length) throw new Error('bad message');
          const data = message.subarray(i, i + n);
          i += n;
          if (!sink) {
            const header = parseHeader(data);
            if (!header || header.cmd !== 1) throw new Error('bad request');
            socket = await dial(header);
            sink = socket.writable.getWriter();
            downlink = pipeDown(socket, out, header.version, () => reader.cancel().catch(() => {}));
            if (header.offset < data.length) await sink.write(data.subarray(header.offset));
          } else if (n) {
            await sink.write(data);
          }
        }
      }
      buf = off < buf.length ? buf.slice(off) : new Uint8Array(0);
    }
    if (sink) {
      await sink.close();
      await downlink;
    } else {
      await out.close();
    }
  } catch {
    try {
      socket?.close();
    } catch {}
    try {
      await out.abort();
    } catch {}
  }
};

export default {
  fetch(request, env, ctx) {
    const contentType = request.headers.get('content-type') || '';
    if (
      request.method !== 'POST' ||
      !request.body ||
      !contentType.startsWith('application/grpc') ||
      !PATHS.has(new URL(request.url).pathname)
    ) {
      return new Response(null, { status: 404 });
    }
    const { readable, writable } = new TransformStream();
    ctx.waitUntil(tunnel(request, writable));
    return new Response(readable, {
      headers: { 'content-type': 'application/grpc', 'cache-control': 'no-store' },
    });
  },
};
