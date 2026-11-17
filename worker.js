import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = 'proxyip.fxxk.dedyn.io';
const TARGET_PORT = 443;

const CONNECT_TIMEOUT_MS = 1500;
const FALLBACK_TIMEOUT_MS = 1200;
const DOH_TIMEOUT_MS = 1500;
const PARALLEL_DIALS = 3;
const READ_CHUNK_SIZE = 65536;
const MAX_FRAME = 1 << 20;
const MAX_REPLAY_BYTES = 65536;
const EARLY_DATA_MAX_BYTES = 8192;
const EARLY_DATA_MAX_B64 = Math.ceil((EARLY_DATA_MAX_BYTES * 4) / 3) + 4;
const PROXY_CACHE_TTL_MS = 300000;

const NGINX_BODY = new TextEncoder().encode(`<!DOCTYPE html>
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
`);

const NOT_FOUND_BODY = new TextEncoder().encode(`<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
`);

const USER_ID = new Uint8Array(16);
{
  const hex = UUID.replace(/-/g, '');
  for (let i = 0; i < 16; i++) {
    USER_ID[i] = parseInt(hex.slice(i << 1, (i << 1) + 2), 16);
  }
}

const SVC = SERVICE_NAME.replace(/^\/+|\/+$/g, '');
const PATH_TUN = SVC ? `/${SVC}/Tun` : '/Tun';
const PATH_MULTI = SVC ? `/${SVC}/TunMulti` : '/TunMulti';
const EMPTY = new Uint8Array(0);
const NEED_MORE = { needMore: true };
const decoder = new TextDecoder();

const GRPC_HEADERS = { 'content-type': 'application/grpc', 'cache-control': 'no-store' };
const HTML_HEADERS = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' };
const DOH_HEADERS = { accept: 'application/dns-json' };

let proxyCacheKey = '';
let proxyCacheList = null;
let proxyCacheAt = 0;
let proxyIndex = 0;

const getPathname = (url) => {
  const s = url.indexOf('://');
  const start = url.indexOf('/', s === -1 ? 0 : s + 3);
  if (start === -1) return '/';
  let end = url.indexOf('?', start);
  const hash = url.indexOf('#', start);
  if (hash !== -1 && (end === -1 || hash < end)) end = hash;
  return end === -1 ? url.slice(start) : url.slice(start, end);
};

const concat = (a, b) => {
  const al = a.byteLength;
  const bl = b.byteLength;
  if (!al) return b;
  if (!bl) return a;
  const out = new Uint8Array(al + bl);
  out.set(a, 0);
  out.set(b, al);
  return out;
};

const formatHost = (host) => {
  const len = host.length;
  if (!len) return host;
  if (host.charCodeAt(0) === 91 && host.charCodeAt(len - 1) === 93) return host;
  return host.indexOf(':') !== -1 ? `[${host}]` : host;
};

const isBareIP = (host) => {
  if (!host) return false;
  if (host.indexOf(':') !== -1) return true;
  let dots = 0;
  let num = 0;
  let digits = 0;
  for (let i = 0; i < host.length; i++) {
    const c = host.charCodeAt(i);
    if (c === 46) {
      if (!digits || ++dots > 3) return false;
      num = 0;
      digits = 0;
    } else if (c >= 48 && c <= 57) {
      num = num * 10 + (c - 48);
      if (num > 255 || ++digits > 3) return false;
    } else {
      return false;
    }
  }
  return dots === 3 && digits > 0;
};

const encodeFrame = (data, prefix) => {
  const dLen = data.byteLength;
  const pLen = prefix ? prefix.byteLength : 0;
  const n = dLen + pLen;
  let v = n;
  let varintLen = 1;
  while (v >= 128) {
    v >>>= 7;
    varintLen++;
  }
  const msgLen = 1 + varintLen + n;
  const out = new Uint8Array(5 + msgLen);
  out[1] = msgLen >>> 24;
  out[2] = msgLen >>> 16;
  out[3] = msgLen >>> 8;
  out[4] = msgLen;
  out[5] = 10;
  let o = 6;
  v = n;
  while (v >= 128) {
    out[o++] = (v & 127) | 128;
    v >>>= 7;
  }
  out[o++] = v;
  if (pLen) {
    out.set(prefix, o);
    o += pLen;
  }
  if (dLen) out.set(data, o);
  return out;
};

const parseHeader = (d) => {
  const len = d.byteLength;
  if (len < 18) return NEED_MORE;
  if (d[0] !== 0) return null;
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= d[1 + i] ^ USER_ID[i];
  if (diff !== 0) return null;
  let p = 18 + d[17];
  if (p + 4 > len) return NEED_MORE;
  const cmd = d[p];
  if (cmd !== 1 && cmd !== 2) return null;
  const port = (d[p + 1] << 8) | d[p + 2];
  if (cmd === 2 && port !== 53) return null;
  const type = d[p + 3];
  p += 4;
  let host;
  if (type === 1) {
    if (p + 4 > len) return NEED_MORE;
    host = `${d[p]}.${d[p + 1]}.${d[p + 2]}.${d[p + 3]}`;
    p += 4;
  } else if (type === 2) {
    if (p + 1 > len) return NEED_MORE;
    const hLen = d[p++];
    if (!hLen) return null;
    if (p + hLen > len) return NEED_MORE;
    host = decoder.decode(d.subarray(p, p + hLen));
    p += hLen;
  } else if (type === 3) {
    if (p + 16 > len) return NEED_MORE;
    host =
      ((d[p] << 8) | d[p + 1]).toString(16) + ':' +
      ((d[p + 2] << 8) | d[p + 3]).toString(16) + ':' +
      ((d[p + 4] << 8) | d[p + 5]).toString(16) + ':' +
      ((d[p + 6] << 8) | d[p + 7]).toString(16) + ':' +
      ((d[p + 8] << 8) | d[p + 9]).toString(16) + ':' +
      ((d[p + 10] << 8) | d[p + 11]).toString(16) + ':' +
      ((d[p + 12] << 8) | d[p + 13]).toString(16) + ':' +
      ((d[p + 14] << 8) | d[p + 15]).toString(16);
    p += 16;
  } else {
    return null;
  }
  return { version: 0, cmd, port, host, offset: p };
};

const decodeEarlyData = (request) => {
  const raw =
    request.headers.get('sec-websocket-protocol') ||
    request.headers.get('x-early-data') ||
    request.headers.get('early-data');
  if (!raw || raw.length > EARLY_DATA_MAX_B64) return null;
  let bytes;
  if (typeof Uint8Array.fromBase64 === 'function') {
    try {
      bytes = Uint8Array.fromBase64(raw, { alphabet: 'base64url' });
    } catch {
      return null;
    }
  } else {
    let b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
    const rem = b64.length & 3;
    if (rem) b64 += rem === 2 ? '==' : rem === 3 ? '=' : '';
    let bin;
    try {
      bin = atob(b64);
    } catch {
      return null;
    }
    bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  }
  if (!bytes.byteLength || bytes.byteLength > EARLY_DATA_MAX_BYTES) return null;
  const h = parseHeader(bytes);
  return h && !h.needMore ? bytes : null;
};

const dohQuery = async (name, type) => {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: DOH_HEADERS, signal: AbortSignal.timeout(DOH_TIMEOUT_MS) }
    );
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.Answer) ? data.Answer : [];
  } catch {
    return [];
  }
};

const parseHostPort = (entry, defaultPort) => {
  const bracketEnd = entry.indexOf(']:');
  if (bracketEnd !== -1 && entry.charCodeAt(0) === 91) {
    return [entry.slice(0, bracketEnd + 1), parseInt(entry.slice(bracketEnd + 2), 10) || defaultPort];
  }
  const firstColon = entry.indexOf(':');
  if (firstColon !== -1 && entry.indexOf(':', firstColon + 1) === -1) {
    return [entry.slice(0, firstColon), parseInt(entry.slice(firstColon + 1), 10) || defaultPort];
  }
  return [entry, defaultPort];
};

const resolveProxyList = async (fallbackPort) => {
  const defaultPort = TARGET_PORT || fallbackPort || 443;
  const key = `${TARGET_HOST}|${defaultPort}`;
  const now = Date.now();
  if (proxyCacheList && proxyCacheKey === key && now - proxyCacheAt < PROXY_CACHE_TTL_MS) {
    return proxyCacheList;
  }

  const entries = TARGET_HOST.split(/[\s,]+/);
  const list = [];

  for (let k = 0; k < entries.length; k++) {
    const raw = entries[k].trim();
    if (!raw) continue;
    let [host, port] = parseHostPort(raw, defaultPort);
    const tpIdx = raw.indexOf('.tp');
    if (tpIdx !== -1) {
      const tpPort = parseInt(raw.slice(tpIdx + 3), 10);
      if (tpPort > 0 && tpPort <= 65535) port = tpPort;
    }
    if (isBareIP(host)) {
      list.push([host, port]);
      continue;
    }

    const [txtAns, aAns] = await Promise.all([dohQuery(host, 'TXT'), dohQuery(host, 'A')]);
    let foundTxt = false;
    for (let i = 0; i < txtAns.length; i++) {
      const r = txtAns[i];
      if (r.type !== 16 || typeof r.data !== 'string') continue;
      let s = r.data.trim();
      if (s.charCodeAt(0) === 34 && s.charCodeAt(s.length - 1) === 34) s = s.slice(1, -1);
      const parts = s.replace(/\\010/g, ',').split(/[\n,]+/);
      for (let j = 0; j < parts.length; j++) {
        const item = parts[j].trim();
        if (item) {
          list.push(parseHostPort(item, defaultPort));
          foundTxt = true;
        }
      }
    }
    if (foundTxt) continue;

    let foundA = false;
    for (let i = 0; i < aAns.length; i++) {
      const r = aAns[i];
      if (r.type === 1 && typeof r.data === 'string') {
        list.push([r.data, port]);
        foundA = true;
      }
    }
    if (foundA) continue;

    const aaaaAns = await dohQuery(host, 'AAAA');
    let foundAAAA = false;
    for (let i = 0; i < aaaaAns.length; i++) {
      const r = aaaaAns[i];
      if (r.type === 28 && typeof r.data === 'string') {
        list.push([`[${r.data}]`, port]);
        foundAAAA = true;
      }
    }
    if (!foundAAAA) list.push([host, port]);
  }

  for (let i = list.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = list[i];
    list[i] = list[j];
    list[j] = tmp;
  }

  proxyCacheList = list.length > 9 ? list.slice(0, 9) : list;
  proxyCacheKey = key;
  proxyCacheAt = now;
  return proxyCacheList;
};

const open = async (hostname, port, timeoutMs = CONNECT_TIMEOUT_MS) => {
  const socket = connect({ hostname: formatHost(hostname), port });
  let timer;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(reject, timeoutMs, new Error('timeout'));
      }),
    ]);
    return socket;
  } catch (err) {
    try {
      socket.close();
    } catch {}
    throw err;
  } finally {
    clearTimeout(timer);
  }
};

const openProxyFallback = async (fallbackPort) => {
  if (!TARGET_HOST) throw new Error('No fallback');
  const targets = await resolveProxyList(fallbackPort);
  const len = targets.length;
  for (let i = 0; i < len; i += PARALLEL_DIALS) {
    const batch = [];
    for (let j = 0; j < PARALLEL_DIALS && i + j < len; j++) {
      const idx = (proxyIndex + i + j) % len;
      batch.push(
        open(targets[idx][0], targets[idx][1], FALLBACK_TIMEOUT_MS).then((sock) => ({ sock, idx }))
      );
    }
    try {
      const winner = await Promise.any(batch);
      proxyIndex = winner.idx;
      for (let j = 0; j < batch.length; j++) {
        batch[j].then(({ sock }) => {
          if (sock !== winner.sock) {
            try {
              sock.close();
            } catch {}
          }
        }).catch(() => {});
      }
      return winner.sock;
    } catch {}
  }
  proxyCacheAt = 0;
  throw new Error('Proxy failed');
};

const tunnel = async (request, writable, earlyData) => {
  const out = writable.getWriter();
  const reader = request.body.getReader();
  const stopReader = () => reader.cancel().catch(() => {});

  const state = {
    socket: null,
    sink: null,
    downlink: null,
    header: null,
    hasData: false,
    fallbackUsed: false,
    fallbackPromise: null,
    replayChunks: [],
    replayBytes: 0,
    replayedCount: 0,
    closed: false,
  };

  let buf = EMPTY;
  let headerBuf = EMPTY;

  const saveReplay = (chunk) => {
    if (!state.replayChunks || state.hasData || state.fallbackUsed || !chunk.byteLength) return -1;
    if (state.replayBytes + chunk.byteLength > MAX_REPLAY_BYTES) return -1;
    state.replayBytes += chunk.byteLength;
    return state.replayChunks.push(chunk.slice()) - 1;
  };

  const pipeDown = async (socket, allowRetry) => {
    let sockReader;
    let byob = false;
    try {
      sockReader = socket.readable.getReader({ mode: 'byob' });
      byob = true;
    } catch {
      sockReader = socket.readable.getReader();
    }

    let head = new Uint8Array([state.header.version, 0]);
    try {
      if (byob) {
        let readBuf = new ArrayBuffer(READ_CHUNK_SIZE);
        for (;;) {
          const { done, value } = await sockReader.read(new Uint8Array(readBuf, 0, READ_CHUNK_SIZE));
          if (done) break;
          if (!value || !value.byteLength) {
            if (value && value.buffer.byteLength >= READ_CHUNK_SIZE) readBuf = value.buffer;
            continue;
          }
          state.hasData = true;
          state.replayChunks = null;
          const frame = encodeFrame(value, head);
          readBuf = value.buffer.byteLength >= READ_CHUNK_SIZE ? value.buffer : new ArrayBuffer(READ_CHUNK_SIZE);
          head = null;
          await out.write(frame);
        }
      } else {
        for (;;) {
          const { done, value } = await sockReader.read();
          if (done) break;
          if (!value || !value.byteLength) continue;
          state.hasData = true;
          state.replayChunks = null;
          const len = value.byteLength;
          if (len <= READ_CHUNK_SIZE) {
            await out.write(encodeFrame(value, head));
            head = null;
          } else {
            for (let off = 0; off < len; off += READ_CHUNK_SIZE) {
              const end = off + READ_CHUNK_SIZE < len ? off + READ_CHUNK_SIZE : len;
              await out.write(encodeFrame(value.subarray(off, end), head));
              head = null;
            }
          }
        }
      }

      if (!state.hasData && allowRetry && TARGET_HOST && !state.fallbackUsed && !state.closed) {
        try {
          sockReader.releaseLock();
        } catch {}
        try {
          socket.close();
        } catch {}
        await switchToFallback();
        return;
      }

      if (head) await out.write(encodeFrame(head));
      await out.close();
    } catch (err) {
      if (!state.hasData && allowRetry && TARGET_HOST && !state.fallbackUsed && !state.closed) {
        try {
          sockReader.releaseLock();
        } catch {}
        try {
          socket.close();
        } catch {}
        try {
          await switchToFallback();
          return;
        } catch {}
      }
      try {
        await out.abort(err);
      } catch {}
    } finally {
      try {
        sockReader.releaseLock();
      } catch {}
      if (state.socket === socket) {
        try {
          socket.close();
        } catch {}
        stopReader();
      }
    }
  };

  const switchToFallback = () => {
    if (state.fallbackPromise) return state.fallbackPromise;
    state.fallbackUsed = true;
    state.fallbackPromise = (async () => {
      if (state.sink) {
        try {
          state.sink.releaseLock();
        } catch {}
        state.sink = null;
      }
      if (state.socket) {
        try {
          state.socket.close();
        } catch {}
      }
      const sock = await openProxyFallback(state.header.port);
      state.socket = sock;
      state.sink = sock.writable.getWriter();
      state.downlink = pipeDown(sock, false);
      const chunks = state.replayChunks;
      state.replayChunks = null;
      if (chunks) {
        state.replayedCount = chunks.length;
        for (let i = 0; i < chunks.length; i++) {
          await state.sink.write(chunks[i]);
        }
      }
    })();
    return state.fallbackPromise;
  };

  const initConnection = async (rawBytes) => {
    headerBuf = headerBuf.byteLength ? concat(headerBuf, rawBytes) : rawBytes;
    const header = parseHeader(headerBuf);
    if (!header) throw new Error('bad request');
    if (header.needMore) return;

    const isUDP = header.cmd === 2;
    const destHost = isUDP ? '8.8.4.4' : header.host;
    const destPort = isUDP ? 53 : header.port;
    state.header = { version: header.version, host: destHost, port: destPort, isUDP };

    const initialData = headerBuf.subarray(header.offset);
    headerBuf = EMPTY;
    if (initialData.byteLength) saveReplay(initialData);

    let sock;
    let allowRetry = !isUDP && !!TARGET_HOST;
    try {
      sock = await open(destHost, destPort);
    } catch (err) {
      if (!allowRetry) throw err;
      state.fallbackUsed = true;
      allowRetry = false;
      sock = await openProxyFallback(destPort);
    }

    state.socket = sock;
    state.sink = sock.writable.getWriter();
    state.downlink = pipeDown(sock, allowRetry);
    if (initialData.byteLength) {
      await state.sink.write(initialData);
    }
  };

  const writeUpstream = async (chunk) => {
    if (!chunk.byteLength) return;
    if (state.fallbackPromise) await state.fallbackPromise;
    const canRetry = !state.fallbackUsed && !!TARGET_HOST;
    const savedIdx = canRetry ? saveReplay(chunk) : -1;
    try {
      await state.sink.write(chunk);
    } catch (err) {
      if (state.closed || !canRetry) throw err;
      await switchToFallback();
      if (savedIdx === -1 || savedIdx >= state.replayedCount) {
        await state.sink.write(chunk);
      }
    }
  };

  try {
    if (earlyData) {
      await initConnection(earlyData);
    }
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || !value.byteLength) continue;
      buf = buf.byteLength ? concat(buf, value) : value;
      const total = buf.byteLength;
      let off = 0;
      while (total - off >= 5) {
        if (buf[off] !== 0) throw new Error('compressed');
        const length = ((buf[off + 1] << 24) | (buf[off + 2] << 16) | (buf[off + 3] << 8) | buf[off + 4]) >>> 0;
        if (length > MAX_FRAME) throw new Error('frame too large');
        if (total - off < 5 + length) break;
        const msgEnd = off + 5 + length;
        let i = off + 5;
        off = msgEnd;
        while (i < msgEnd) {
          const tag = buf[i++];
          let n = 0;
          let shift = 0;
          let byte;
          for (;;) {
            if (i >= msgEnd) throw new Error('bad message');
            byte = buf[i++];
            n |= (byte & 127) << shift;
            if ((byte & 128) === 0) break;
            shift += 7;
            if (shift > 28) throw new Error('bad message');
          }
          if (i + n > msgEnd) throw new Error('bad message');
          if (tag === 10) {
            const data = buf.subarray(i, i + n);
            if (!state.header) {
              await initConnection(data);
            } else if (n) {
              await writeUpstream(data);
            }
          }
          i += n;
        }
      }
      buf = off < total ? buf.slice(off) : EMPTY;
    }

    state.closed = true;
    if (state.fallbackPromise) await state.fallbackPromise;
    if (state.sink) {
      await state.sink.close();
      while (state.downlink) {
        const p = state.downlink;
        await p;
        if (state.downlink === p) break;
      }
    } else {
      await out.close();
    }
  } catch {
    state.closed = true;
    try {
      state.socket?.close();
    } catch {}
    try {
      await out.abort();
    } catch {}
  }
};

export default {
  fetch(request, env, ctx) {
    const pathname = getPathname(request.url);
    if (
      request.method === 'POST' &&
      (pathname === PATH_TUN || pathname === PATH_MULTI) &&
      request.body
    ) {
      const ct = request.headers.get('content-type');
      if (ct && ct.length >= 16 && ct.slice(0, 16).toLowerCase() === 'application/grpc') {
        const earlyData = decodeEarlyData(request);
        const { readable, writable } = new TransformStream();
        ctx.waitUntil(tunnel(request, writable, earlyData));
        return new Response(readable, { headers: GRPC_HEADERS });
      }
    }

    if ((request.method === 'GET' || request.method === 'HEAD') && (pathname === '/' || pathname === '/index.html')) {
      return new Response(request.method === 'HEAD' ? null : NGINX_BODY, {
        status: 200,
        headers: HTML_HEADERS,
      });
    }

    return new Response(request.method === 'HEAD' ? null : NOT_FOUND_BODY, {
      status: 404,
      headers: HTML_HEADERS,
    });
  },
};
