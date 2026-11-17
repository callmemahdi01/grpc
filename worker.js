import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = 'proxyip.fxxk.dedyn.io';
const TARGET_PORT = 443;
const CONNECT_TIMEOUT_MS = 2500;
const FALLBACK_TIMEOUT_MS = 1500;
const PARALLEL_DIALS = 3;
const MAX_FRAME = 1 << 20;
const MAX_REPLAY_BYTES = 65536;

const USER_ID = Uint8Array.from(UUID.replace(/-/g, '').match(/../g), (h) => parseInt(h, 16));
const PATHS = new Set([`/${SERVICE_NAME}/Tun`, `/${SERVICE_NAME}/TunMulti`]);
const decoder = new TextDecoder();

let proxyCacheKey = '';
let proxyCacheList = null;
let proxyCacheAt = 0;
let proxyIndex = 0;

const concat = (a, b) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

const formatHost = (host) => {
  const h = String(host || '').trim();
  const bare = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  return bare.includes(':') ? `[${bare}]` : bare;
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
  if (d.length < 18) return { needMore: true };
  if (d[0] !== 0) return null;
  for (let i = 0; i < 16; i++) if (d[1 + i] !== USER_ID[i]) return null;
  let p = 18 + d[17];
  if (p + 4 > d.length) return { needMore: true };
  const cmd = d[p];
  const port = (d[p + 1] << 8) | d[p + 2];
  const type = d[p + 3];
  p += 4;
  let host;
  if (type === 1) {
    if (p + 4 > d.length) return { needMore: true };
    host = d.subarray(p, p + 4).join('.');
    p += 4;
  } else if (type === 2) {
    if (p + 1 > d.length) return { needMore: true };
    const length = d[p++];
    if (!length) return null;
    if (p + length > d.length) return { needMore: true };
    host = decoder.decode(d.subarray(p, p + length));
    p += length;
  } else if (type === 3) {
    if (p + 16 > d.length) return { needMore: true };
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((d[p + i] << 8) | d[p + i + 1]).toString(16));
    host = groups.join(':');
    p += 16;
  } else {
    return null;
  }
  return { version: d[0], cmd, port, host, offset: p };
};

const dohQuery = async (name, type) => {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers: { accept: 'application/dns-json' } }
    );
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.Answer) ? data.Answer : [];
  } catch {
    return [];
  }
};

const parseHostPort = (entry, defaultPort) => {
  let host = entry;
  let port = defaultPort;
  if (entry.includes(']:')) {
    const parts = entry.split(']:');
    host = parts[0] + ']';
    port = parseInt(parts[1], 10) || defaultPort;
  } else if ((entry.match(/:/g) || []).length === 1 && !entry.startsWith('[')) {
    const idx = entry.lastIndexOf(':');
    host = entry.slice(0, idx);
    port = parseInt(entry.slice(idx + 1), 10) || defaultPort;
  }
  return [host, port];
};

const resolveProxyList = async (destHost, fallbackPort) => {
  const defaultPort = TARGET_PORT || fallbackPort || 443;
  const key = `${TARGET_HOST}|${defaultPort}`;
  if (proxyCacheList && proxyCacheKey === key && Date.now() - proxyCacheAt < 300000) {
    return proxyCacheList;
  }

  const ipv4Re = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;
  const ipv6Re = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
  const entries = String(TARGET_HOST || '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const list = [];
  for (const raw of entries) {
    let [host, port] = parseHostPort(raw, defaultPort);
    if (raw.includes('.tp')) {
      const m = raw.match(/\.tp(\d+)/);
      if (m) port = parseInt(m[1], 10) || port;
    }
    if (ipv4Re.test(host) || ipv6Re.test(host)) {
      list.push([host, port]);
      continue;
    }
    const [txtAns, aAns] = await Promise.all([dohQuery(host, 'TXT'), dohQuery(host, 'A')]);
    const txtList = txtAns
      .filter((r) => r.type === 16 && typeof r.data === 'string')
      .flatMap((r) => {
        let s = r.data.trim();
        if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
        return s.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map((x) => x.trim()).filter(Boolean);
      })
      .map((item) => parseHostPort(item, defaultPort));
    if (txtList.length) {
      list.push(...txtList);
      continue;
    }
    const aList = aAns.filter((r) => r.type === 1 && typeof r.data === 'string').map((r) => [r.data, port]);
    if (aList.length) {
      list.push(...aList);
      continue;
    }
    const aaaaAns = await dohQuery(host, 'AAAA');
    const aaaaList = aaaaAns.filter((r) => r.type === 28 && typeof r.data === 'string').map((r) => [`[${r.data}]`, port]);
    list.push(...(aaaaList.length ? aaaaList : [[host, port]]));
  }

  const domain = destHost.includes('.') ? destHost.split('.').slice(-2).join('.') : destHost;
  let seed = [...(domain + UUID)].reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  proxyCacheList = [...list]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .sort(() => ((seed = (seed * 1103515245 + 12345) & 2147483647) / 2147483647) - 0.5)
    .slice(0, 8);
  proxyCacheKey = key;
  proxyCacheAt = Date.now();
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
  } catch (error) {
    try {
      socket.close();
    } catch {}
    throw error;
  } finally {
    clearTimeout(timer);
  }
};

const openProxyFallback = async (destHost, fallbackPort) => {
  if (!TARGET_HOST) throw new Error('No fallback proxy configured');
  const targets = await resolveProxyList(destHost, fallbackPort);
  for (let i = 0; i < targets.length; i += PARALLEL_DIALS) {
    const batch = [];
    for (let j = 0; j < PARALLEL_DIALS && i + j < targets.length; j++) {
      const idx = (proxyIndex + i + j) % targets.length;
      batch.push({ host: targets[idx][0], port: targets[idx][1], idx });
    }
    const attempts = batch.map((t) => open(t.host, t.port, FALLBACK_TIMEOUT_MS).then((sock) => ({ sock, idx: t.idx })));
    try {
      const winner = await Promise.any(attempts);
      proxyIndex = winner.idx;
      for (const p of attempts) {
        p.then(({ sock }) => {
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
  throw new Error('All proxy targets failed');
};

const tunnel = async (request, writable) => {
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
    closed: false,
  };

  let buf = new Uint8Array(0);
  let headerBuf = new Uint8Array(0);

  const saveReplay = (chunk) => {
    if (state.hasData || state.fallbackUsed || !chunk.length) return;
    if (state.replayBytes + chunk.length > MAX_REPLAY_BYTES) return;
    state.replayChunks.push(chunk.slice());
    state.replayBytes += chunk.length;
  };

  const pipeDown = async (socket, allowRetry) => {
    const sockReader = socket.readable.getReader();
    let head = new Uint8Array([state.header.version, 0]);
    try {
      for (;;) {
        const { done, value } = await sockReader.read();
        if (done) break;
        if (!value || !value.length) continue;
        state.hasData = true;
        state.replayChunks = [];
        await out.write(encodeFrame(head ? concat(head, value) : value));
        head = null;
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
    } catch (error) {
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
        await out.abort(error);
      } catch {}
    } finally {
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
      const sock = await openProxyFallback(state.header.host, state.header.port);
      state.socket = sock;
      state.sink = sock.writable.getWriter();
      state.downlink = pipeDown(sock, false);
      for (const chunk of state.replayChunks) {
        await state.sink.write(chunk);
      }
    })();
    return state.fallbackPromise;
  };

  const writeUpstream = async (chunk) => {
    if (!chunk.length) return;
    if (state.fallbackPromise) await state.fallbackPromise;
    saveReplay(chunk);
    try {
      await state.sink.write(chunk);
    } catch (err) {
      if (!state.fallbackUsed && TARGET_HOST && !state.closed) {
        await switchToFallback();
        await state.sink.write(chunk);
      } else {
        throw err;
      }
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
          if (!state.header) {
            headerBuf = headerBuf.length ? concat(headerBuf, data) : data;
            const header = parseHeader(headerBuf);
            if (!header) throw new Error('bad request');
            if (header.needMore) continue;
            if (header.cmd !== 1 && !(header.cmd === 2 && header.port === 53)) {
              throw new Error('bad command');
            }
            const destHost = header.cmd === 2 ? '8.8.4.4' : header.host;
            const destPort = header.cmd === 2 ? 53 : header.port;
            state.header = { version: header.version, host: destHost, port: destPort, isUDP: header.cmd === 2 };
            const initialData = headerBuf.subarray(header.offset);
            headerBuf = new Uint8Array(0);

            if (initialData.length) saveReplay(initialData);

            let sock;
            let allowRetry = !state.header.isUDP && !!TARGET_HOST;
            try {
              sock = await open(destHost, destPort);
            } catch (err) {
              if (!allowRetry) throw err;
              state.fallbackUsed = true;
              allowRetry = false;
              sock = await openProxyFallback(destHost, destPort);
            }
            state.socket = sock;
            state.sink = sock.writable.getWriter();
            state.downlink = pipeDown(sock, allowRetry);
            if (initialData.length) await state.sink.write(initialData);
          } else if (n) {
            await writeUpstream(data);
          }
        }
      }
      buf = off < buf.length ? buf.slice(off) : new Uint8Array(0);
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
