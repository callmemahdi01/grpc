import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = 'proxyip.fxxk.dedyn.io';
const TARGET_PORT = 0; // 0 = پورت درخواست کلاینت (برای اجبار 443 عدد 443 بگذارید)
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
  let v = n, vl = 1;
  while (v >= 128) { v >>>= 7; vl++; }
  const out = new Uint8Array(6 + vl + n);
  new DataView(out.buffer).setUint32(1, 1 + vl + n);
  out[5] = 10;
  let o = 6;
  v = n;
  while (v >= 128) { out[o++] = (v & 127) | 128; v >>>= 7; }
  out[o++] = v;
  out.set(data, o);
  return out;
};

const parseHeader = (d) => {
  if (d.length < 22 || d[0] !== 0) return null;
  for (let i = 0; i < 16; i++) if (d[1 + i] !== USER_ID[i]) return null;
  let p = 18 + d[17];
  if (p + 4 > d.length) return null;
  const cmd = d[p], port = (d[p + 1] << 8) | d[p + 2], type = d[p + 3];
  p += 4;
  let host;
  if (type === 1) {
    if (p + 4 > d.length) return null;
    host = d.subarray(p, p + 4).join('.');
    p += 4;
  } else if (type === 2) {
    const len = d[p++];
    if (!len || p + len > d.length) return null;
    host = decoder.decode(d.subarray(p, p + len));
    p += len;
  } else if (type === 3) {
    if (p + 16 > d.length) return null;
    const g = [];
    for (let i = 0; i < 16; i += 2) g.push(((d[p + i] << 8) | d[p + i + 1]).toString(16));
    host = g.join(':');
    p += 16;
  } else return null;
  return { version: d[0], cmd, port, host, offset: p };
};

const resolveIPv4 = async (host) => {
  if (/^\d+(\.\d+){3}$/.test(host) || host.includes(':')) return [host];
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 2000);
  try {
    const r = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal: ac.signal,
    });
    const ips = ((await r.json()).Answer || []).filter((a) => a.type === 1).map((a) => a.data);
    return ips.length ? [...new Set(ips), host] : [host];
  } catch {
    return [host];
  } finally {
    clearTimeout(t);
  }
};

const open = async (hostname, port) => {
  const socket = connect({ hostname, port });
  socket.opened.catch(() => {});
  let timer;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, rej) => { timer = setTimeout(rej, CONNECT_TIMEOUT_MS, new Error('timeout')); }),
    ]);
    return socket;
  } catch (err) {
    try { socket.close(); } catch {}
    throw err;
  } finally {
    clearTimeout(timer);
  }
};

const dialFallback = async (port, fb) => {
  if (!fb.list) {
    const [h, p] = TARGET_HOST.includes(':') && !TARGET_HOST.includes('[')
      ? TARGET_HOST.split(':') : [TARGET_HOST, 0];
    const targetPort = Number(p) || TARGET_PORT || port;
    fb.list = (await resolveIPv4(h.trim())).slice(0, 5).map((host) => ({ host, port: targetPort }));
  }
  while (fb.i < fb.list.length) {
    const t = fb.list[fb.i++];
    try { return await open(t.host, t.port); } catch {}
  }
  throw new Error('fallback failed');
};

const tunnel = async (request, writable) => {
  const out = writable.getWriter();
  const reader = request.body.getReader();
  const stop = () => reader.cancel().catch(() => {});
  const fb = { list: null, i: 0 };
  let socket, sink, downlink, firstPayload;
  let buf = new Uint8Array(0);

  const pipeDown = async (version, port) => {
    let head = new Uint8Array([version, 0]);
    try {
      for (;;) {
        let gotData = false;
        const r = socket.readable.getReader();
        try {
          for (;;) {
            const { done, value } = await r.read();
            if (done) break;
            if (value?.length) {
              gotData = true;
              firstPayload = null;
              await out.write(encodeFrame(head ? concat(head, value) : value));
              head = null;
            }
          }
        } catch {} finally {
          try { r.releaseLock(); } catch {}
          try { socket.close(); } catch {}
        }
        if (gotData || !TARGET_HOST || !firstPayload) break;
        try {
          socket = await dialFallback(port, fb);
          try { sink.abort().catch(() => {}); sink.releaseLock(); } catch {}
          sink = socket.writable.getWriter();
          if (firstPayload.length) await sink.write(firstPayload);
        } catch {
          break;
        }
      }
      if (head) await out.write(encodeFrame(head));
      await out.close();
    } catch (e) {
      try { await out.abort(e); } catch {}
    } finally {
      try { socket?.close(); } catch {}
      stop();
    }
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf = buf.length ? concat(buf, value) : value;
      let off = 0;
      while (buf.length - off >= 5) {
        if (buf[off] !== 0) throw new Error('compressed');
        const len = new DataView(buf.buffer, buf.byteOffset + off + 1, 4).getUint32(0);
        if (len > MAX_FRAME) throw new Error('frame too large');
        if (buf.length - off < 5 + len) break;
        const msg = buf.subarray(off + 5, off + 5 + len);
        off += 5 + len;
        for (let i = 0; i < msg.length; ) {
          if (msg[i++] !== 10) throw new Error('bad message');
          let n = 0, s = 0, b;
          do { b = msg[i++]; n |= (b & 127) << s; s += 7; } while (b & 128 && s < 28);
          if (b & 128 || i + n > msg.length) throw new Error('bad message');
          const data = msg.subarray(i, i + n);
          i += n;
          if (!sink) {
            const h = parseHeader(data);
            if (!h || h.cmd !== 1) throw new Error('bad request');
            try {
              socket = await open(h.host, h.port);
            } catch (err) {
              if (!TARGET_HOST) throw err;
              socket = await dialFallback(h.port, fb);
            }
            sink = socket.writable.getWriter();
            firstPayload = h.offset < data.length ? data.subarray(h.offset) : new Uint8Array(0);
            if (firstPayload.length) await sink.write(firstPayload);
            downlink = pipeDown(h.version, h.port);
          } else if (n) {
            await sink.write(data);
          }
        }
      }
      buf = off < buf.length ? buf.slice(off) : new Uint8Array(0);
    }
    if (sink) {
      try { await sink.close(); } catch {}
      await downlink;
    } else {
      await out.close();
    }
  } catch {
    try { socket?.close(); } catch {}
    try { await out.abort(); } catch {}
  }
};

export default {
  fetch(request, env, ctx) {
    const ct = request.headers.get('content-type') || '';
    if (request.method !== 'POST' || !request.body || !ct.startsWith('application/grpc') || !PATHS.has(new URL(request.url).pathname)) {
      return new Response(null, { status: 404 });
    }
    const { readable, writable } = new TransformStream();
    ctx.waitUntil(tunnel(request, writable));
    return new Response(readable, { headers: { 'content-type': 'application/grpc', 'cache-control': 'no-store' } });
  },
};
