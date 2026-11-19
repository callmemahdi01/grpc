import { connect } from 'cloudflare:sockets';

const UUID = '00000000-0000-4000-8000-000000000000';
const SERVICE_NAME = 'grpc';
const TARGET_HOST = 'proxyip.fxxk.dedyn.io';
const TARGET_PORT = 0; // اگر 0 باشد از پورت درخواست استفاده می‌کند (مثلاً 443). برای اجبار پورت 443 عدد 443 بگذارید.
const FALLBACK_HOSTS = [
  // در صورت نیاز ProxyIP یا IP تمیز جایگزین را اینجا اضافه کنید (پشتیبانی از فرمت host یا host:port):
  // 'proxyip.example.com:443',
];
const CONNECT_TIMEOUT_MS = 5000;
const MAX_FRAME = 1 << 20;
const MAX_INITIAL_BUFFER = 65536;

const USER_ID = Uint8Array.from(
  UUID.replace(/-/g, '').match(/../g),
  (h) => parseInt(h, 16)
);
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
    for (let i = 0; i < 16; i += 2) {
      groups.push(((d[p + i] << 8) | d[p + i + 1]).toString(16));
    }
    host = groups.join(':');
    p += 16;
  } else {
    return null;
  }
  return { version: d[0], cmd, port, host, offset: p };
};

const isIP = (host) =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');

const parseTarget = (entry, defaultPort) => {
  const s = entry.trim();
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end !== -1) {
      const hostname = s.slice(1, end);
      const port = s[end + 1] === ':' ? Number(s.slice(end + 2)) : defaultPort;
      return { hostname, port: port || defaultPort };
    }
  }
  const firstColon = s.indexOf(':');
  if (firstColon !== -1 && firstColon === s.lastIndexOf(':')) {
    const hostname = s.slice(0, firstColon);
    const port = Number(s.slice(firstColon + 1));
    return { hostname, port: port || defaultPort };
  }
  return { hostname: s, port: defaultPort };
};

const resolveIPv4 = async (hostname) => {
  if (isIP(hostname)) return [hostname];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2000);
  try {
    const res = await fetch(
      `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      {
        headers: { accept: 'application/dns-json' },
        signal: controller.signal,
      }
    );
    if (!res.ok) return [hostname];
    const json = await res.json();
    const ips = (json.Answer || [])
      .filter((a) => a.type === 1 && typeof a.data === 'string')
      .map((a) => a.data);
    return ips.length ? [...new Set(ips), hostname] : [hostname];
  } catch {
    return [hostname];
  } finally {
    clearTimeout(timer);
  }
};

const getFallbackTargets = async (port) => {
  const entries = [TARGET_HOST, ...FALLBACK_HOSTS].filter(
    (x) => typeof x === 'string' && x.trim()
  );
  const targets = [];
  for (const entry of entries) {
    const { hostname, port: p } = parseTarget(entry, TARGET_PORT || port);
    const hosts = await resolveIPv4(hostname);
    for (const h of hosts.slice(0, 5)) {
      targets.push({ hostname: h, port: p });
    }
  }
  return targets;
};

const open = async (hostname, port) => {
  const socket = connect({ hostname, port });
  socket.opened.catch(() => {});
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
    return { socket: await open(host, port), candidates: null, candidateIdx: 0 };
  } catch (error) {
    const candidates = await getFallbackTargets(port);
    if (!candidates.length) throw error;
    let lastError = error;
    for (let i = 0; i < candidates.length; i++) {
      try {
        const socket = await open(candidates[i].hostname, candidates[i].port);
        return { socket, candidates, candidateIdx: i + 1 };
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError;
  }
};

const tunnel = async (request, writable) => {
  const out = writable.getWriter();
  const reader = request.body.getReader();
  const stop = () => reader.cancel().catch(() => {});

  let socket;
  let sink;
  let downlink;
  let candidates = null;
  let candidateIdx = 0;
  let reconnecting = null;
  let initialChunks = [];
  let initialSize = 0;
  let uplinkClosed = false;
  let buf = new Uint8Array(0);

  const runDownlink = async (version, targetPort) => {
    let head = new Uint8Array([version, 0]);
    try {
      for (;;) {
        let received = false;
        const sReader = socket.readable.getReader();
        try {
          for (;;) {
            const { done, value } = await sReader.read();
            if (done) break;
            if (value && value.length > 0) {
              received = true;
              initialChunks = null;
              await out.write(encodeFrame(head ? concat(head, value) : value));
              head = null;
            }
          }
        } catch {
          // در صورت خطا قبل از دریافت داده، به سراغ ProxyIP بعدی می‌رود
        } finally {
          try {
            sReader.releaseLock();
          } catch {}
          try {
            socket.close();
          } catch {}
        }

        if (received) {
          await out.close();
          stop();
          return;
        }

        if (!initialChunks) break;
        if (!candidates) {
          candidates = await getFallbackTargets(targetPort);
        }

        let nextSocket = null;
        while (candidateIdx < candidates.length) {
          const t = candidates[candidateIdx++];
          try {
            nextSocket = await open(t.hostname, t.port);
            break;
          } catch {}
        }
        if (!nextSocket) break;

        let resolveReconnect;
        reconnecting = new Promise((r) => {
          resolveReconnect = r;
        });
        try {
          try {
            sink.abort().catch(() => {});
            sink.releaseLock();
          } catch {}
          socket = nextSocket;
          sink = socket.writable.getWriter();
          for (const chunk of initialChunks) {
            await sink.write(chunk);
          }
          if (uplinkClosed) {
            await sink.close().catch(() => {});
          }
        } catch {
          resolveReconnect();
          reconnecting = null;
          continue;
        }
        resolveReconnect();
        reconnecting = null;
      }

      if (head) await out.write(encodeFrame(head));
      await out.close();
    } catch (error) {
      try {
        await out.abort(error);
      } catch {}
    } finally {
      try {
        socket?.close();
      } catch {}
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
        const length = new DataView(
          buf.buffer,
          buf.byteOffset + off + 1,
          4
        ).getUint32(0);
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
          if (byte & 128 || i + n > message.length) {
            throw new Error('bad message');
          }
          const data = message.subarray(i, i + n);
          i += n;

          if (!sink) {
            const header = parseHeader(data);
            if (!header || header.cmd !== 1) throw new Error('bad request');
            const dialed = await dial(header);
            socket = dialed.socket;
            candidates = dialed.candidates;
            candidateIdx = dialed.candidateIdx;
            sink = socket.writable.getWriter();

            if (header.offset < data.length) {
              const initData = data.subarray(header.offset);
              if (initData.length <= MAX_INITIAL_BUFFER) {
                initialChunks.push(initData);
                initialSize += initData.length;
              } else {
                initialChunks = null;
              }
              await sink.write(initData);
            }
            downlink = runDownlink(header.version, header.port);
          } else if (n) {
            if (reconnecting) await reconnecting;
            if (initialChunks) {
              if (initialSize + data.length <= MAX_INITIAL_BUFFER) {
                initialChunks.push(data);
                initialSize += data.length;
              } else {
                initialChunks = null;
              }
            }
            await sink.write(data);
          }
        }
      }
      buf = off < buf.length ? buf.slice(off) : new Uint8Array(0);
    }

    uplinkClosed = true;
    if (sink) {
      if (reconnecting) await reconnecting;
      try {
        await sink.close();
      } catch {}
      await downlink;
    } else {
      await out.close();
    }
  } catch {
    uplinkClosed = true;
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
      headers: {
        'content-type': 'application/grpc',
        'cache-control': 'no-store',
      },
    });
  },
};
