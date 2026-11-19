import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = 'proxyip.fxxk.dedyn.io';
const TARGET_PORT = 443;
const MAX_FRAME = 1 << 20;
const EARLY_DATA_MAX_BYTES = 8192;

const PATH_TUN = `/${SERVICE_NAME}/Tun`;
const PATH_MULTI = `/${SERVICE_NAME}/TunMulti`;
const EMPTY = new Uint8Array(0);
const NEED_MORE = Symbol();
const HTML = { 'content-type': 'text/html; charset=utf-8' };
const GRPC = { 'content-type': 'application/grpc', 'cache-control': 'no-store' };

const NGINX_PAGE = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`;

const NOT_FOUND_PAGE = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`;

const USER_ID = Uint8Array.from(UUID.replace(/-/g, '').match(/../g), (h) => parseInt(h, 16));

const concat = (a, b) => {
  if (!a.length) return b;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

const encodeFrame = (data, prefix) => {
  const n = data.length + (prefix ? prefix.length : 0);
  const varint = [];
  for (let v = n; ; v >>>= 7) {
    if (v < 128) {
      varint.push(v);
      break;
    }
    varint.push((v & 127) | 128);
  }
  const msgLen = 1 + varint.length + n;
  const out = new Uint8Array(5 + msgLen);
  new DataView(out.buffer).setUint32(1, msgLen);
  out[5] = 10;
  out.set(varint, 6);
  let o = 6 + varint.length;
  if (prefix) {
    out.set(prefix, o);
    o += prefix.length;
  }
  out.set(data, o);
  return out;
};

const encodeMuxFrame = (id, status, option, data, prefix) => {
  const dLen = data ? data.length : 0;
  const pLen = prefix ? prefix.length : 0;
  const n = pLen + 6 + (dLen ? 2 + dLen : 0);
  const varint = [];
  for (let v = n; ; v >>>= 7) {
    if (v < 128) {
      varint.push(v);
      break;
    }
    varint.push((v & 127) | 128);
  }
  const msgLen = 1 + varint.length + n;
  const out = new Uint8Array(5 + msgLen);
  new DataView(out.buffer).setUint32(1, msgLen);
  out[5] = 10;
  out.set(varint, 6);
  let o = 6 + varint.length;
  if (prefix) {
    out.set(prefix, o);
    o += prefix.length;
  }
  out[o++] = 0;
  out[o++] = 4;
  out[o++] = id >>> 8;
  out[o++] = id;
  out[o++] = status;
  out[o++] = option;
  if (dLen) {
    out[o++] = dLen >>> 8;
    out[o++] = dLen;
    out.set(data, o);
  }
  return out;
};

const payloads = (msg) => {
  const out = [];
  let i = 0;
  while (i < msg.length) {
    const tag = msg[i++];
    let n = 0;
    let shift = 0;
    let b;
    do {
      b = msg[i++];
      n |= (b & 127) << shift;
      shift += 7;
    } while (b & 128 && shift < 35);
    if (n < 0 || i + n > msg.length) throw new Error('bad message');
    if (tag === 10) out.push(msg.subarray(i, i + n));
    i += n;
  }
  return out;
};

async function* messages(body) {
  let buf = EMPTY;
  for await (const chunk of body) {
    buf = concat(buf, chunk);
    while (buf.length >= 5) {
      if (buf[0] !== 0) throw new Error('compressed');
      const len = new DataView(buf.buffer, buf.byteOffset).getUint32(1);
      if (len > MAX_FRAME) throw new Error('frame too large');
      if (buf.length < 5 + len) break;
      const msg = buf.subarray(5, 5 + len);
      buf = buf.subarray(5 + len);
      yield* payloads(msg);
    }
  }
}

const parseHeader = (d) => {
  if (d.length < 18) return NEED_MORE;
  if (d[0] !== 0) return null;
  for (let i = 0; i < 16; i++) if (d[1 + i] !== USER_ID[i]) return null;
  const p = 18 + d[17];
  if (p + 1 > d.length) return NEED_MORE;
  const cmd = d[p];
  if (cmd === 3) return { cmd, offset: p + 1 };
  if (cmd !== 1) return null;
  if (p + 4 > d.length) return NEED_MORE;
  const type = d[p + 3];
  const addrLen = type === 1 ? 4 : type === 3 ? 16 : type === 2 ? 1 + d[p + 4] : -1;
  if (addrLen < 0) return null;
  const offset = p + 4 + addrLen;
  return offset > d.length ? NEED_MORE : { cmd, offset };
};

const decodeEarlyData = (request) => {
  const raw = request.headers.get('sec-websocket-protocol');
  if (!raw) return null;
  try {
    const bytes = Uint8Array.fromBase64(raw, { alphabet: 'base64url' });
    return bytes.length && bytes.length <= EARLY_DATA_MAX_BYTES ? bytes : null;
  } catch {
    return null;
  }
};

const makeWriter = (writer) => {
  let chain = Promise.resolve();
  return {
    write: (frame) => (chain = chain.then(() => writer.ready).then(() => writer.write(frame))),
    close: () => (chain = chain.then(() => writer.close())),
    abort: (err) => writer.abort(err).catch(() => {}),
  };
};

const openTarget = () => connect({ hostname: TARGET_HOST, port: TARGET_PORT });

const pipeSingle = async (socket, out) => {
  let head = new Uint8Array(2);
  try {
    for await (const chunk of socket.readable) {
      out.write(encodeFrame(chunk, head));
      head = null;
    }
    if (head) out.write(encodeFrame(EMPTY, head));
    out.close();
  } catch (err) {
    out.abort(err);
  }
};

const pipeMux = async (socket, id, out, sessions) => {
  try {
    for await (const chunk of socket.readable) out.write(encodeMuxFrame(id, 2, 1, chunk));
    sessions.delete(id);
    out.write(encodeMuxFrame(id, 3, 0, null));
  } catch {
    sessions.delete(id);
    out.write(encodeMuxFrame(id, 3, 2, null));
  }
};

const openMuxSession = (id, out, sessions) => {
  const socket = openTarget();
  const sess = { sink: socket.writable.getWriter() };
  sessions.set(id, sess);
  pipeMux(socket, id, out, sessions);
  return sess;
};

const feedMux = (buf, out, sessions) => {
  let off = 0;
  while (buf.length - off >= 2) {
    const metaLen = (buf[off] << 8) | buf[off + 1];
    if (metaLen < 4) throw new Error('bad mux meta');
    if (buf.length - off < 2 + metaLen) break;
    const m = off + 2;
    const id = (buf[m] << 8) | buf[m + 1];
    const status = buf[m + 2];
    const option = buf[m + 3];
    const metaEnd = m + metaLen;

    let payload = EMPTY;
    off = metaEnd;
    if (option & 1) {
      if (buf.length - metaEnd < 2) break;
      const dLen = (buf[metaEnd] << 8) | buf[metaEnd + 1];
      if (buf.length - metaEnd - 2 < dLen) break;
      payload = buf.subarray(metaEnd + 2, metaEnd + 2 + dLen);
      off = metaEnd + 2 + dLen;
    }

    if (status === 1) {
      sessions.get(id) && sessions.delete(id);
      const sess = openMuxSession(id, out, sessions);
      if (payload.length) sess.sink.write(payload).catch(() => {});
    } else if (status === 2) {
      const sess = sessions.get(id);
      if (sess && payload.length) sess.sink.write(payload).catch(() => {});
    } else if (status === 3) {
      const sess = sessions.get(id);
      if (sess) {
        sessions.delete(id);
        sess.sink.close().catch(() => {});
      }
    }
  }
  return buf.subarray(off);
};

const tunnel = async (body, out, earlyData) => {
  let headerBuf = EMPTY;
  let header = null;
  let isMux = false;
  let muxBuf = EMPTY;
  const sessions = new Map();
  let socket;
  let sink;

  const feed = (data) => {
    if (!header) {
      headerBuf = concat(headerBuf, data);
      const h = parseHeader(headerBuf);
      if (h === NEED_MORE) return;
      if (!h) throw new Error('bad request');
      header = h;
      isMux = header.cmd === 3;
      const rest = headerBuf.subarray(header.offset);
      headerBuf = EMPTY;
      if (isMux) {
        if (rest.length) muxBuf = feedMux(rest, out, sessions);
      } else {
        socket = openTarget();
        sink = socket.writable.getWriter();
        pipeSingle(socket, out);
        if (rest.length) sink.write(rest);
      }
      return;
    }
    if (isMux) muxBuf = feedMux(concat(muxBuf, data), out, sessions);
    else sink.write(data);
  };

  try {
    if (earlyData) feed(earlyData);
    for await (const data of messages(body)) {
      if (data.length) feed(data);
    }
    if (isMux) {
      for (const sess of sessions.values()) sess.sink.close().catch(() => {});
      out.close();
    } else if (sink) {
      await sink.close();
    } else {
      out.close();
    }
  } catch (err) {
    socket?.close();
    for (const sess of sessions.values()) sess.sink.close().catch(() => {});
    out.abort(err);
  }
};

export default {
  fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);
    const head = request.method === 'HEAD';

    if (request.method === 'POST' && (pathname === PATH_TUN || pathname === PATH_MULTI) && request.body) {
      const type = request.headers.get('content-type') || '';
      if (type.toLowerCase().startsWith('application/grpc')) {
        const { readable, writable } = new TransformStream();
        const out = makeWriter(writable.getWriter());
        const earlyData = decodeEarlyData(request);
        ctx.waitUntil(tunnel(request.body, out, earlyData));
        return new Response(readable, { headers: GRPC });
      }
    }

    if ((request.method === 'GET' || head) && (pathname === '/' || pathname === '/index.html')) {
      return new Response(head ? null : NGINX_PAGE, { headers: HTML });
    }

    return new Response(head ? null : NOT_FOUND_PAGE, { status: 404, headers: HTML });
  },
};
