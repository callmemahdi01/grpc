import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = 'proxyip.fxxk.dedyn.io';
const TARGET_PORT = 443;

const CONNECT_TIMEOUT_MS = 1500;
const FALLBACK_TIMEOUT_MS = 1200;
const DOH_TIMEOUT_MS = 1500;
const PARALLEL_DIALS = 2;
const MUX_CHUNK_SIZE = 65500;
const MAX_FRAME = 1 << 20;
const MAX_REPLAY_BYTES = 65536;
const MAX_MUX_PENDING_BYTES = 2 * 1024 * 1024;
const EARLY_DATA_MAX_BYTES = 8192;
const EARLY_DATA_MAX_B64 = Math.ceil((EARLY_DATA_MAX_BYTES * 4) / 3) + 4;
const PROXY_CACHE_TTL_MS = 1800000;
const PROXY_NEGATIVE_CACHE_TTL_MS = 15000;
const BAD_TARGET_TTL_MS = 60000;
const DNS_CACHE_TTL_MS = 60000;
const DNS_CACHE_MAX = 256;
const UDP_TX_MAX = 64;

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
const utf8Decoder = new TextDecoder();
const latin1Decoder = new TextDecoder('latin1');

const GRPC_HEADERS = { 'content-type': 'application/grpc', 'cache-control': 'no-store' };
const HTML_CACHE_HEADERS = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=86400' };
const DOH_HEADERS = { accept: 'application/dns-json' };

let proxyCacheKey = '';
let proxyCacheList = null;
let proxyCacheAt = 0;
let proxyCacheTtl = PROXY_CACHE_TTL_MS;
let proxyIndex = 0;
const badTargets = new Map();
const dnsCache = new Map();

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

const ensureCapacity = (buf, used, extra, minCap = 65536) => {
  const needed = used + extra;
  if (buf && buf.byteLength >= needed) return buf;
  let cap = buf ? buf.byteLength : minCap;
  while (cap < needed) cap <<= 1;
  const next = new Uint8Array(cap);
  if (buf && used) next.set(buf.subarray(0, used), 0);
  return next;
};

const formatHost = (host) => {
  const len = host.length;
  if (!len) return host;
  if (host.charCodeAt(0) === 91 && host.charCodeAt(len - 1) === 93) return host;
  return host.indexOf(':') !== -1 ? `[${host}]` : host;
};

const readIPv6 = (b, p) =>
  ((b[p] << 8) | b[p + 1]).toString(16) + ':' +
  ((b[p + 2] << 8) | b[p + 3]).toString(16) + ':' +
  ((b[p + 4] << 8) | b[p + 5]).toString(16) + ':' +
  ((b[p + 6] << 8) | b[p + 7]).toString(16) + ':' +
  ((b[p + 8] << 8) | b[p + 9]).toString(16) + ':' +
  ((b[p + 10] << 8) | b[p + 11]).toString(16) + ':' +
  ((b[p + 12] << 8) | b[p + 13]).toString(16) + ':' +
  ((b[p + 14] << 8) | b[p + 15]).toString(16);

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
  const varintLen = n < 128 ? 1 : n < 16384 ? 2 : n < 2097152 ? 3 : 4;
  const msgLen = 1 + varintLen + n;
  const out = new Uint8Array(5 + msgLen);
  out[1] = msgLen >>> 24;
  out[2] = msgLen >>> 16;
  out[3] = msgLen >>> 8;
  out[4] = msgLen;
  out[5] = 10;
  let o = 6;
  if (varintLen === 1) {
    out[o++] = n;
  } else if (varintLen === 2) {
    out[o++] = (n & 127) | 128;
    out[o++] = n >>> 7;
  } else {
    let v = n;
    while (v >= 128) {
      out[o++] = (v & 127) | 128;
      v >>>= 7;
    }
    out[o++] = v;
  }
  if (pLen) {
    out.set(prefix, o);
    o += pLen;
  }
  if (dLen) out.set(data, o);
  return out;
};

const encodeGrpcMuxFrame = (sessionId, status, option, data, prefix) => {
  const dLen = data ? data.byteLength : 0;
  const pLen = prefix ? prefix.byteLength : 0;
  const n = pLen + 6 + (dLen ? 2 + dLen : 0);
  const varintLen = n < 128 ? 1 : n < 16384 ? 2 : n < 2097152 ? 3 : 4;
  const msgLen = 1 + varintLen + n;
  const out = new Uint8Array(5 + msgLen);
  out[1] = msgLen >>> 24;
  out[2] = msgLen >>> 16;
  out[3] = msgLen >>> 8;
  out[4] = msgLen;
  out[5] = 10;
  let o = 6;
  if (varintLen === 1) {
    out[o++] = n;
  } else if (varintLen === 2) {
    out[o++] = (n & 127) | 128;
    out[o++] = n >>> 7;
  } else {
    let v = n;
    while (v >= 128) {
      out[o++] = (v & 127) | 128;
      v >>>= 7;
    }
    out[o++] = v;
  }
  if (pLen) {
    out.set(prefix, o);
    o += pLen;
  }
  out[o++] = 0;
  out[o++] = 4;
  out[o++] = sessionId >>> 8;
  out[o++] = sessionId;
  out[o++] = status;
  out[o++] = option;
  if (dLen) {
    out[o++] = dLen >>> 8;
    out[o++] = dLen;
    out.set(data, o);
  }
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
  if (p + 1 > len) return NEED_MORE;
  const cmd = d[p];
  if (cmd === 3) {
    return { version: 0, cmd: 3, port: 0, host: '', offset: p + 1 };
  }
  if (cmd !== 1 && cmd !== 2) return null;
  if (p + 4 > len) return NEED_MORE;
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
    host = utf8Decoder.decode(d.subarray(p, p + hLen));
    p += hLen;
  } else if (type === 3) {
    if (p + 16 > len) return NEED_MORE;
    host = readIPv6(d, p);
    p += 16;
  } else {
    return null;
  }
  return { version: 0, cmd, port, host, offset: p };
};

const parseMuxTarget = (buf, p, end) => {
  if (p + 4 > end) return null;
  const net = buf[p++];
  if (net !== 1 && net !== 2) return null;
  const port = (buf[p] << 8) | buf[p + 1];
  p += 2;
  const atype = buf[p++];
  let host;
  if (atype === 1) {
    if (p + 4 > end) return null;
    host = `${buf[p]}.${buf[p + 1]}.${buf[p + 2]}.${buf[p + 3]}`;
  } else if (atype === 2) {
    if (p + 1 > end) return null;
    const hLen = buf[p++];
    if (!hLen || p + hLen > end) return null;
    host = utf8Decoder.decode(buf.subarray(p, p + hLen));
  } else if (atype === 3) {
    if (p + 16 > end) return null;
    host = readIPv6(buf, p);
  } else {
    return null;
  }
  return { net, port, host };
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

const dnsQueryKey = (pkt) => {
  if (pkt.byteLength <= 12 || pkt.byteLength > 2048) return '';
  return latin1Decoder.decode(pkt.subarray(2));
};

const dnsCacheGet = (pkt) => {
  const key = dnsQueryKey(pkt);
  if (!key) return null;
  const entry = dnsCache.get(key);
  if (!entry) return null;
  if (Date.now() >= entry.expiresAt) {
    dnsCache.delete(key);
    return null;
  }
  dnsCache.delete(key);
  dnsCache.set(key, entry);
  const resp = entry.data.slice();
  resp[0] = pkt[0];
  resp[1] = pkt[1];
  return resp;
};

const dnsCacheSet = (key, resp) => {
  if (!key || resp.byteLength <= 12) return;
  if ((resp[3] & 0x0f) !== 0 || ((resp[6] << 8) | resp[7]) === 0) return;
  if (dnsCache.size >= DNS_CACHE_MAX) {
    const first = dnsCache.keys().next().value;
    if (first !== undefined) dnsCache.delete(first);
  }
  dnsCache.set(key, { data: resp.slice(), expiresAt: Date.now() + DNS_CACHE_TTL_MS });
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
  if (proxyCacheList && proxyCacheKey === key && now - proxyCacheAt < proxyCacheTtl) {
    return proxyCacheList;
  }

  const entries = TARGET_HOST.split(/[\s,]+/);
  const list = [];
  let resolvedAny = false;

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
      resolvedAny = true;
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
    if (foundTxt) {
      resolvedAny = true;
      continue;
    }

    let foundA = false;
    for (let i = 0; i < aAns.length; i++) {
      const r = aAns[i];
      if (r.type === 1 && typeof r.data === 'string') {
        list.push([r.data, port]);
        foundA = true;
      }
    }
    if (foundA) {
      resolvedAny = true;
      continue;
    }

    const aaaaAns = await dohQuery(host, 'AAAA');
    let foundAAAA = false;
    for (let i = 0; i < aaaaAns.length; i++) {
      const r = aaaaAns[i];
      if (r.type === 28 && typeof r.data === 'string') {
        list.push([`[${r.data}]`, port]);
        foundAAAA = true;
      }
    }
    if (foundAAAA) {
      resolvedAny = true;
    } else {
      list.push([host, port]);
    }
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
  proxyCacheTtl = resolvedAny ? PROXY_CACHE_TTL_MS : PROXY_NEGATIVE_CACHE_TTL_MS;
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
  const now = Date.now();
  if (badTargets.size > 128) {
    for (const [k, exp] of badTargets) {
      if (now >= exp) badTargets.delete(k);
    }
  }

  const healthy = [];
  for (let i = 0; i < targets.length; i++) {
    const idx = (proxyIndex + i) % targets.length;
    const t = targets[idx];
    const key = `${t[0]}:${t[1]}`;
    const exp = badTargets.get(key);
    if (!exp || now >= exp) {
      if (exp) badTargets.delete(key);
      healthy.push({ host: t[0], port: t[1], key, idx });
    }
  }
  if (!healthy.length) {
    badTargets.clear();
    for (let i = 0; i < targets.length; i++) {
      const idx = (proxyIndex + i) % targets.length;
      const t = targets[idx];
      healthy.push({ host: t[0], port: t[1], key: `${t[0]}:${t[1]}`, idx });
    }
  }

  for (let i = 0; i < healthy.length; i += PARALLEL_DIALS) {
    const batch = [];
    for (let j = 0; j < PARALLEL_DIALS && i + j < healthy.length; j++) {
      const item = healthy[i + j];
      batch.push(
        open(item.host, item.port, FALLBACK_TIMEOUT_MS)
          .then((sock) => ({ sock, idx: item.idx }))
          .catch((err) => {
            badTargets.set(item.key, Date.now() + BAD_TARGET_TTL_MS);
            throw err;
          })
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

const createGrpcResponseStream = (onCancel) => {
  let ctrl;
  let closed = false;
  let pullPromise = null;
  let pullResolve = null;

  const wakePull = () => {
    if (pullResolve) {
      const r = pullResolve;
      pullResolve = null;
      pullPromise = null;
      r();
    }
  };

  const readable = new ReadableStream(
    {
      start(c) {
        ctrl = c;
      },
      pull() {
        wakePull();
      },
      cancel() {
        closed = true;
        wakePull();
        if (onCancel) onCancel();
      },
    },
    { highWaterMark: 4 }
  );

  return {
    readable,
    isClosed: () => closed,
    waitReady: () => {
      if (closed || ctrl.desiredSize === null || ctrl.desiredSize > 0) return null;
      if (!pullPromise) {
        pullPromise = new Promise((r) => {
          pullResolve = r;
        });
      }
      return pullPromise;
    },
    enqueue: (chunk) => {
      if (!closed) ctrl.enqueue(chunk);
    },
    close: () => {
      if (closed) return;
      closed = true;
      wakePull();
      try {
        ctrl.close();
      } catch {}
    },
    abort: (err) => {
      if (closed) return;
      closed = true;
      wakePull();
      try {
        ctrl.error(err);
      } catch {}
    },
  };
};

const tunnel = async (request, streamOut, earlyData, state) => {
  const reader = request.body.getReader();
  const stopReader = () => reader.cancel().catch(() => {});

  let head = null;
  let grpcBuf = null;
  let grpcLen = 0;
  let headerBuf = EMPTY;
  let muxBuf = null;
  let muxLen = 0;
  const muxSessions = state.muxSessions;

  let pendingMuxBytes = 0;
  let muxDrainResolve = null;
  const notifyMuxDrain = () => {
    if (muxDrainResolve && pendingMuxBytes < (MAX_MUX_PENDING_BYTES >>> 1)) {
      const r = muxDrainResolve;
      muxDrainResolve = null;
      r();
    }
  };
  const waitMuxDrain = () =>
    pendingMuxBytes < MAX_MUX_PENDING_BYTES
      ? null
      : new Promise((resolve) => {
          muxDrainResolve = resolve;
        });

  const emitGrpc = (data) => {
    let h = null;
    if (head) {
      h = head;
      head = null;
    }
    streamOut.enqueue(encodeFrame(data, h));
  };

  const emitMux = (sessionId, status, option, data) => {
    let h = null;
    if (head) {
      h = head;
      head = null;
    }
    streamOut.enqueue(encodeGrpcMuxFrame(sessionId, status, option, data, h));
  };

  const saveReplay = (target, chunk) => {
    if (!target.replayChunks || target.hasData || target.fallbackUsed || !chunk.byteLength) return -1;
    if (target.replayBytes + chunk.byteLength > MAX_REPLAY_BYTES) return -1;
    target.replayBytes += chunk.byteLength;
    return target.replayChunks.push(chunk.slice()) - 1;
  };

  const pipeSocket = async (socket, sess, isMuxSession) => {
    const sockReader = socket.readable.getReader();
    try {
      for (;;) {
        const w = streamOut.waitReady();
        if (w) await w;
        if (streamOut.isClosed() || state.closed || sess.closed) break;

        const { done, value } = await sockReader.read();
        if (done) break;
        if (!value || !value.byteLength) continue;

        sess.hasData = true;
        sess.replayChunks = null;

        if (!isMuxSession) {
          emitGrpc(value);
        } else {
          const len = value.byteLength;
          if (len <= MUX_CHUNK_SIZE) {
            emitMux(sess.id, 2, 1, value);
          } else {
            for (let off = 0; off < len; off += MUX_CHUNK_SIZE) {
              const end = off + MUX_CHUNK_SIZE < len ? off + MUX_CHUNK_SIZE : len;
              emitMux(sess.id, 2, 1, value.subarray(off, end));
            }
          }
        }
      }

      if (!sess.hasData && sess.allowRetry && TARGET_HOST && !sess.fallbackUsed && !state.closed && !sess.closed && !streamOut.isClosed()) {
        try {
          sockReader.releaseLock();
        } catch {}
        try {
          socket.close();
        } catch {}
        await sess.switchFallback();
        return;
      }

      if (isMuxSession) {
        muxSessions.delete(sess.id);
        emitMux(sess.id, 3, 0, null);
      } else {
        if (head) emitGrpc(EMPTY);
        streamOut.close();
      }
    } catch (err) {
      if (!sess.hasData && sess.allowRetry && TARGET_HOST && !sess.fallbackUsed && !state.closed && !sess.closed && !streamOut.isClosed()) {
        try {
          sockReader.releaseLock();
        } catch {}
        try {
          socket.close();
        } catch {}
        try {
          await sess.switchFallback();
          return;
        } catch {}
      }
      if (isMuxSession) {
        muxSessions.delete(sess.id);
        emitMux(sess.id, 3, 2, null);
      } else {
        streamOut.abort(err);
      }
    } finally {
      try {
        sockReader.releaseLock();
      } catch {}
      if (sess.socket === socket) {
        try {
          socket.close();
        } catch {}
        if (!isMuxSession) stopReader();
      }
    }
  };

  const makeFallbackSwitcher = (sess, isMuxSession) => () => {
    if (sess.fallbackPromise) return sess.fallbackPromise;
    sess.fallbackUsed = true;
    sess.fallbackPromise = (async () => {
      if (sess.sink) {
        try {
          sess.sink.releaseLock();
        } catch {}
        sess.sink = null;
      }
      if (sess.socket) {
        try {
          sess.socket.close();
        } catch {}
      }
      const sock = await openProxyFallback(sess.port);
      sess.socket = sock;
      sess.sink = sock.writable.getWriter();
      sess.allowRetry = false;
      sess.downlink = pipeSocket(sock, sess, isMuxSession);
      const chunks = sess.replayChunks;
      sess.replayChunks = null;
      if (chunks) {
        sess.replayedCount = chunks.length;
        for (let i = 0; i < chunks.length; i++) {
          await sess.sink.write(chunks[i]);
        }
      }
    })();
    return sess.fallbackPromise;
  };

  state.switchFallback = makeFallbackSwitcher(state, false);

  const openMuxUdpSession = (id) => {
    const sess = {
      id,
      socket: null,
      sink: null,
      downlink: null,
      closed: false,
      txMap: new Map(),
      writeChain: Promise.resolve(),
      async ensureSocket() {
        if (sess.socket) return;
        const sock = await open('8.8.4.4', 53, CONNECT_TIMEOUT_MS);
        if (sess.closed || state.closed) {
          try {
            sock.close();
          } catch {}
          return;
        }
        sess.socket = sock;
        sess.sink = sock.writable.getWriter();
        sess.downlink = (async () => {
          const r = sock.readable.getReader();
          let dbuf = null;
          let dlen = 0;
          try {
            for (;;) {
              const { done, value } = await r.read();
              if (done) break;
              if (!value || !value.byteLength) continue;
              let src;
              let total;
              if (dlen === 0) {
                src = value;
                total = value.byteLength;
              } else {
                dbuf = ensureCapacity(dbuf, dlen, value.byteLength, 4096);
                dbuf.set(value, dlen);
                dlen += value.byteLength;
                src = dbuf;
                total = dlen;
              }
              let doff = 0;
              while (total - doff >= 2) {
                const msgLen = (src[doff] << 8) | src[doff + 1];
                if (total - doff < 2 + msgLen) break;
                const pkt = src.subarray(doff + 2, doff + 2 + msgLen);
                doff += 2 + msgLen;
                if (pkt.byteLength >= 2) {
                  const txId = (pkt[0] << 8) | pkt[1];
                  const qKey = sess.txMap.get(txId);
                  if (qKey) {
                    sess.txMap.delete(txId);
                    dnsCacheSet(qKey, pkt);
                  }
                }
                const w = streamOut.waitReady();
                if (w) await w;
                emitMux(id, 2, 1, pkt);
              }
              if (doff < total) {
                const rem = total - doff;
                if (src === dbuf) {
                  if (doff > 0) dbuf.copyWithin(0, doff, total);
                } else {
                  dbuf = ensureCapacity(dbuf, 0, rem, 4096);
                  dbuf.set(src.subarray(doff, total), 0);
                }
                dlen = rem;
              } else {
                dlen = 0;
              }
            }
            muxSessions.delete(id);
            emitMux(id, 3, 0, null);
          } catch {
            muxSessions.delete(id);
            emitMux(id, 3, 2, null);
          } finally {
            try {
              r.releaseLock();
            } catch {}
            try {
              sock.close();
            } catch {}
          }
        })();
      },
      sendQuery(pkt) {
        if (!pkt.byteLength || sess.closed) return;
        const cached = dnsCacheGet(pkt);
        if (cached) {
          sess.writeChain = sess.writeChain.then(() => emitMux(id, 2, 1, cached));
          return;
        }
        const outPkt = new Uint8Array(2 + pkt.byteLength);
        outPkt[0] = pkt.byteLength >>> 8;
        outPkt[1] = pkt.byteLength;
        outPkt.set(pkt, 2);
        const txId = pkt.byteLength > 12 ? (pkt[0] << 8) | pkt[1] : -1;
        const qKey = txId !== -1 ? dnsQueryKey(pkt) : '';

        sess.writeChain = sess.writeChain.then(async () => {
          if (sess.closed || state.closed) return;
          if (!sess.socket) await sess.ensureSocket();
          if (!sess.sink || sess.closed) return;
          if (qKey) {
            if (sess.txMap.size >= UDP_TX_MAX) {
              const first = sess.txMap.keys().next().value;
              if (first !== undefined) sess.txMap.delete(first);
            }
            sess.txMap.set(txId, qKey);
          }
          await sess.sink.write(outPkt);
        }).catch(() => sess.abort());
      },
      closeWrite() {
        sess.writeChain = sess.writeChain.then(async () => {
          if (sess.sink) {
            try {
              await sess.sink.close();
            } catch {}
          } else {
            muxSessions.delete(id);
            emitMux(id, 3, 0, null);
          }
        }).catch(() => sess.abort());
      },
      abort() {
        if (sess.closed) return;
        sess.closed = true;
        muxSessions.delete(id);
        try {
          sess.socket?.close();
        } catch {}
        emitMux(id, 3, 2, null);
      },
    };
    muxSessions.set(id, sess);
    return sess;
  };

  const openMuxTcpSession = (id, host, port, initialData) => {
    const initCopy = initialData.byteLength ? initialData.slice() : null;
    const sess = {
      id,
      port,
      socket: null,
      sink: null,
      downlink: null,
      hasData: false,
      allowRetry: !!TARGET_HOST,
      fallbackUsed: false,
      fallbackPromise: null,
      replayChunks: [],
      replayBytes: 0,
      replayedCount: 0,
      closed: false,
      closeRequested: false,
      switchFallback: null,
      queue: [],
      qHead: 0,
      pendingBytes: 0,
      draining: false,
      writeChain: null,
      async drain() {
        if (sess.draining) return;
        sess.draining = true;
        try {
          while (sess.qHead < sess.queue.length && !sess.closed && !state.closed) {
            const copy = sess.queue[sess.qHead];
            sess.queue[sess.qHead++] = undefined;
            if (sess.qHead >= 64 && sess.qHead * 2 >= sess.queue.length) {
              sess.queue = sess.queue.slice(sess.qHead);
              sess.qHead = 0;
            }
            sess.pendingBytes -= copy.byteLength;
            pendingMuxBytes -= copy.byteLength;
            notifyMuxDrain();

            if (sess.fallbackPromise) await sess.fallbackPromise;
            const canRetry = !sess.fallbackUsed && !!TARGET_HOST;
            const savedIdx = canRetry ? saveReplay(sess, copy) : -1;
            try {
              await sess.sink.write(copy);
            } catch (err) {
              if (sess.closed || state.closed || !canRetry) throw err;
              await sess.switchFallback();
              if (savedIdx === -1 || savedIdx >= sess.replayedCount) {
                await sess.sink.write(copy);
              }
            }
          }
          if (sess.qHead >= sess.queue.length) {
            sess.queue.length = 0;
            sess.qHead = 0;
          }
          if (sess.closeRequested && !sess.closed && sess.sink) {
            try {
              await sess.sink.close();
            } catch {}
          }
        } catch {
          sess.abort();
        } finally {
          sess.draining = false;
          if (sess.pendingBytes) {
            pendingMuxBytes -= sess.pendingBytes;
            sess.pendingBytes = 0;
            notifyMuxDrain();
          }
          if (sess.queue.length) {
            sess.queue.length = 0;
            sess.qHead = 0;
          }
        }
      },
      sendData(chunk) {
        if (!chunk.byteLength || sess.closed) return;
        const copy = chunk.slice();
        sess.queue.push(copy);
        sess.pendingBytes += copy.byteLength;
        pendingMuxBytes += copy.byteLength;
        if (sess.sink && !sess.draining) {
          sess.writeChain = sess.drain();
        }
      },
      closeWrite() {
        sess.closeRequested = true;
        if (sess.sink && !sess.draining) {
          sess.writeChain = sess.drain();
        }
      },
      abort() {
        if (sess.closed) return;
        sess.closed = true;
        sess.replayChunks = null;
        if (sess.pendingBytes) {
          pendingMuxBytes -= sess.pendingBytes;
          sess.pendingBytes = 0;
          notifyMuxDrain();
        }
        sess.queue.length = 0;
        sess.qHead = 0;
        muxSessions.delete(id);
        try {
          sess.socket?.close();
        } catch {}
        emitMux(id, 3, 2, null);
      },
    };

    sess.switchFallback = makeFallbackSwitcher(sess, true);
    muxSessions.set(id, sess);

    if (initCopy) {
      saveReplay(sess, initCopy);
      sess.queue.push(initCopy);
      sess.pendingBytes += initCopy.byteLength;
      pendingMuxBytes += initCopy.byteLength;
    }

    sess.writeChain = (async () => {
      let sock;
      try {
        sock = await open(host, port);
      } catch (err) {
        if (!sess.allowRetry) throw err;
        sess.fallbackUsed = true;
        sess.allowRetry = false;
        sess.replayChunks = null;
        sock = await openProxyFallback(port);
      }
      if (sess.closed || state.closed) {
        try {
          sock.close();
        } catch {}
        return;
      }
      sess.socket = sock;
      sess.sink = sock.writable.getWriter();
      sess.downlink = pipeSocket(sock, sess, true);
      if (sess.qHead < sess.queue.length || sess.closeRequested) {
        await sess.drain();
      }
    })().catch(() => sess.abort());

    return sess;
  };

  const feedMux = (chunk) => {
    let src;
    let total;
    if (muxLen === 0) {
      src = chunk;
      total = chunk.byteLength;
    } else {
      muxBuf = ensureCapacity(muxBuf, muxLen, chunk.byteLength, 65536);
      muxBuf.set(chunk, muxLen);
      muxLen += chunk.byteLength;
      src = muxBuf;
      total = muxLen;
    }

    let off = 0;
    while (total - off >= 2 && !state.closed) {
      const metaLen = (src[off] << 8) | src[off + 1];
      if (metaLen < 4) throw new Error('bad mux meta');
      if (total - off < 2 + metaLen) break;

      const m = off + 2;
      const metaEnd = m + metaLen;
      const id = (src[m] << 8) | src[m + 1];
      const status = src[m + 2];
      const option = src[m + 3];

      let payload = EMPTY;
      if (option & 1) {
        if (total - metaEnd < 2) break;
        const dLen = (src[metaEnd] << 8) | src[metaEnd + 1];
        if (total - metaEnd - 2 < dLen) break;
        payload = src.subarray(metaEnd + 2, metaEnd + 2 + dLen);
        off = metaEnd + 2 + dLen;
      } else {
        off = metaEnd;
      }

      if (status === 4) continue;

      if (status === 1) {
        const target = parseMuxTarget(src, m + 4, metaEnd);
        if (!target || (target.net === 2 && target.port !== 53)) {
          emitMux(id, 3, 2, null);
          continue;
        }
        const existing = muxSessions.get(id);
        if (existing) existing.abort();
        if (target.net === 2) {
          const s = openMuxUdpSession(id);
          if (payload.byteLength) s.sendQuery(payload);
        } else {
          openMuxTcpSession(id, target.host, target.port, payload);
        }
      } else if (status === 2) {
        const s = muxSessions.get(id);
        if (s && payload.byteLength) {
          if (s.sendQuery) s.sendQuery(payload);
          else s.sendData(payload);
        }
      } else if (status === 3) {
        const s = muxSessions.get(id);
        if (s) {
          if (option & 2) {
            s.abort();
          } else {
            if (payload.byteLength) {
              if (s.sendQuery) s.sendQuery(payload);
              else s.sendData(payload);
            }
            s.closeWrite();
          }
        }
      }
    }

    if (off < total) {
      const rem = total - off;
      if (src === muxBuf) {
        if (off > 0) muxBuf.copyWithin(0, off, total);
      } else {
        muxBuf = ensureCapacity(muxBuf, 0, rem, 65536);
        muxBuf.set(src.subarray(off, total), 0);
      }
      muxLen = rem;
    } else {
      muxLen = 0;
    }
  };

  const initConnection = async (rawBytes) => {
    headerBuf = headerBuf.byteLength ? concat(headerBuf, rawBytes) : rawBytes;
    const header = parseHeader(headerBuf);
    if (!header) throw new Error('bad request');
    if (header.needMore) return;

    state.header = header;
    head = new Uint8Array([header.version, 0]);
    const initialData = headerBuf.subarray(header.offset);
    headerBuf = EMPTY;

    if (header.cmd === 3) {
      state.isMux = true;
      if (initialData.byteLength) feedMux(initialData);
      return;
    }

    const isUDP = header.cmd === 2;
    const destHost = isUDP ? '8.8.4.4' : header.host;
    const destPort = isUDP ? 53 : header.port;
    state.port = destPort;
    state.allowRetry = !isUDP && !!TARGET_HOST;

    if (initialData.byteLength) saveReplay(state, initialData);

    let sock;
    try {
      sock = await open(destHost, destPort);
    } catch (err) {
      if (!state.allowRetry) throw err;
      state.fallbackUsed = true;
      state.allowRetry = false;
      state.replayChunks = null;
      sock = await openProxyFallback(destPort);
    }

    state.socket = sock;
    state.sink = sock.writable.getWriter();
    state.downlink = pipeSocket(sock, state, false);
    if (initialData.byteLength) {
      await state.sink.write(initialData);
    }
  };

  const writeUpstream = async (chunk) => {
    if (!chunk.byteLength) return;
    if (state.fallbackPromise) await state.fallbackPromise;
    const canRetry = !state.fallbackUsed && !!TARGET_HOST;
    const savedIdx = canRetry ? saveReplay(state, chunk) : -1;
    try {
      await state.sink.write(chunk);
    } catch (err) {
      if (state.closed || !canRetry) throw err;
      await state.switchFallback();
      if (savedIdx === -1 || savedIdx >= state.replayedCount) {
        await state.sink.write(chunk);
      }
    }
  };

  state.cancel = () => {
    state.closed = true;
    stopReader();
    for (const sess of muxSessions.values()) {
      try {
        sess.socket?.close();
      } catch {}
    }
    muxSessions.clear();
    try {
      state.socket?.close();
    } catch {}
  };

  try {
    if (earlyData) {
      await initConnection(earlyData);
    }
    for (;;) {
      const drainWait = waitMuxDrain();
      if (drainWait) await drainWait;
      if (state.closed || streamOut.isClosed()) break;

      const { done, value } = await reader.read();
      if (done) break;
      if (!value || !value.byteLength) continue;

      let src;
      let total;
      if (grpcLen === 0) {
        src = value;
        total = value.byteLength;
      } else {
        grpcBuf = ensureCapacity(grpcBuf, grpcLen, value.byteLength, 65536);
        grpcBuf.set(value, grpcLen);
        grpcLen += value.byteLength;
        src = grpcBuf;
        total = grpcLen;
      }

      let off = 0;
      while (total - off >= 5) {
        if (src[off] !== 0) throw new Error('compressed');
        const length = ((src[off + 1] << 24) | (src[off + 2] << 16) | (src[off + 3] << 8) | src[off + 4]) >>> 0;
        if (length > MAX_FRAME) throw new Error('frame too large');
        if (total - off < 5 + length) break;
        const msgEnd = off + 5 + length;
        let i = off + 5;
        off = msgEnd;
        while (i < msgEnd) {
          const tag = src[i++];
          let n = 0;
          let shift = 0;
          let byte;
          for (;;) {
            if (i >= msgEnd) throw new Error('bad message');
            byte = src[i++];
            n |= (byte & 127) << shift;
            if ((byte & 128) === 0) break;
            shift += 7;
            if (shift > 28) throw new Error('bad message');
          }
          if (n < 0 || i + n > msgEnd) throw new Error('bad message');
          if (tag === 10) {
            const data = src.subarray(i, i + n);
            if (!state.header) {
              await initConnection(data);
            } else if (state.isMux) {
              if (n) feedMux(data);
            } else if (n) {
              await writeUpstream(data);
            }
          }
          i += n;
        }
      }

      if (off < total) {
        const rem = total - off;
        if (src === grpcBuf) {
          if (off > 0) grpcBuf.copyWithin(0, off, total);
        } else {
          grpcBuf = ensureCapacity(grpcBuf, 0, rem, 65536);
          grpcBuf.set(src.subarray(off, total), 0);
        }
        grpcLen = rem;
      } else {
        grpcLen = 0;
      }
    }

    state.closed = true;
    if (state.isMux) {
      const active = [...muxSessions.values()];
      for (let i = 0; i < active.length; i++) active[i].closeWrite();
      for (let i = 0; i < active.length; i++) {
        await active[i].writeChain;
        while (active[i].downlink) {
          const p = active[i].downlink;
          await p;
          if (active[i].downlink === p) break;
        }
      }
      if (head) emitGrpc(EMPTY);
      streamOut.close();
    } else {
      if (state.fallbackPromise) await state.fallbackPromise;
      if (state.sink) {
        await state.sink.close().catch(() => {});
        while (state.downlink) {
          const p = state.downlink;
          await p;
          if (state.downlink === p) break;
        }
      } else {
        streamOut.close();
      }
    }
  } catch (err) {
    state.cancel();
    streamOut.abort(err);
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
        const state = {
          socket: null,
          sink: null,
          downlink: null,
          header: null,
          port: 0,
          allowRetry: false,
          isMux: false,
          hasData: false,
          fallbackUsed: false,
          fallbackPromise: null,
          replayChunks: [],
          replayBytes: 0,
          replayedCount: 0,
          closed: false,
          muxSessions: new Map(),
          cancel: null,
        };
        const streamOut = createGrpcResponseStream(() => state.cancel?.());
        ctx.waitUntil(tunnel(request, streamOut, earlyData, state));
        return new Response(streamOut.readable, { headers: GRPC_HEADERS });
      }
    }

    if ((request.method === 'GET' || request.method === 'HEAD') && (pathname === '/' || pathname === '/index.html')) {
      return new Response(request.method === 'HEAD' ? null : NGINX_BODY, {
        status: 200,
        headers: HTML_CACHE_HEADERS,
      });
    }

    return new Response(request.method === 'HEAD' ? null : NOT_FOUND_BODY, {
      status: 404,
      headers: HTML_CACHE_HEADERS,
    });
  },
};
