import { connect } from "cloudflare:sockets";

const UUID = "00000000-0000-4000-8000-000000000000";
const GRPC_SERVICE_NAME = "GunService";
const TARGET_HOST = "proxyip.fxxk.dedyn.io";
const TARGET_PORT = 443;

const CHUNK_SIZE = 65536;
const MAX_QUEUE_BYTES = 32 * 1024 * 1024;
const MAX_QUEUE_ITEMS = 8192;
const PARALLEL_DIALS = 3;
const DIAL_TIMEOUT_MS = 1000;
const EMPTY = new Uint8Array(0);
const decoder = new TextDecoder();

let cachedProxyKey = "";
let cachedProxyTargets = null;
let cachedProxyIndex = 0;

function toUint8(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}

function concatBytes(...parts) {
  const list = parts.map(toUint8).filter((p) => p.byteLength > 0);
  if (!list.length) return EMPTY;
  if (list.length === 1) return list[0];
  let total = 0;
  for (const p of list) total += p.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of list) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

function parseUuid(uuid) {
  const hex = String(uuid || "").replace(/-/g, "");
  if (hex.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(hex)) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function matchUuid(buf, offset, expected) {
  if (buf.byteLength < offset + 16) return false;
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= buf[offset + i] ^ expected[i];
  return diff === 0;
}

function parseVless(buf, expectedUuid) {
  const len = buf.byteLength;
  if (len < 18) return { needMore: true };
  if (!matchUuid(buf, 1, expectedUuid)) return { hasError: true, message: "Invalid UUID" };
  const addonsLen = buf[17];
  const cmdPos = 18 + addonsLen;
  if (len < cmdPos + 4) return { needMore: true };
  const cmd = buf[cmdPos];
  if (cmd !== 1 && cmd !== 2) return { hasError: true, message: "Invalid command" };
  const port = (buf[cmdPos + 1] << 8) | buf[cmdPos + 2];
  const addrType = buf[cmdPos + 3];
  const addrPos = cmdPos + 4;
  let hostname = "";
  let dataPos = 0;

  if (addrType === 1) {
    if (len < addrPos + 4) return { needMore: true };
    hostname = `${buf[addrPos]}.${buf[addrPos + 1]}.${buf[addrPos + 2]}.${buf[addrPos + 3]}`;
    dataPos = addrPos + 4;
  } else if (addrType === 2) {
    if (len < addrPos + 1) return { needMore: true };
    const domLen = buf[addrPos];
    if (len < addrPos + 1 + domLen) return { needMore: true };
    hostname = decoder.decode(buf.subarray(addrPos + 1, addrPos + 1 + domLen));
    dataPos = addrPos + 1 + domLen;
  } else if (addrType === 3) {
    if (len < addrPos + 16) return { needMore: true };
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buf[addrPos + i] << 8) | buf[addrPos + i + 1]).toString(16));
    }
    hostname = parts.join(":");
    dataPos = addrPos + 16;
  } else {
    return { hasError: true, message: "Invalid address type" };
  }

  if (!hostname) return { hasError: true, message: "Empty address" };

  return {
    hasError: false,
    version: buf[0],
    port,
    hostname,
    isUDP: cmd === 2,
    rawClientData: buf.subarray(dataPos)
  };
}

function formatHost(hostname) {
  const h = String(hostname || "").trim();
  const bare = h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
  return bare.includes(":") ? `[${bare}]` : bare;
}

function getDialer(request) {
  const fetcher = request && request.fetcher;
  if (fetcher && typeof fetcher.connect === "function") {
    return (opts) => fetcher.connect({ ...opts, hostname: formatHost(opts.hostname) });
  }
  return (opts) => connect({ ...opts, hostname: formatHost(opts.hostname) });
}

async function dohQuery(name, type) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers: { accept: "application/dns-json" } }
    );
    if (!res.ok) return [];
    const json = await res.json();
    return Array.isArray(json.Answer) ? json.Answer : [];
  } catch {
    return [];
  }
}

async function resolveProxyTargets(proxySpec, destHost) {
  const key = `${proxySpec}|${TARGET_PORT}`;
  if (cachedProxyTargets && cachedProxyKey === key) return cachedProxyTargets;

  const parseEntry = (entry) => {
    let host = entry;
    let port = TARGET_PORT;
    if (entry.includes("]:")) {
      const parts = entry.split("]:");
      host = parts[0] + "]";
      port = parseInt(parts[1], 10) || TARGET_PORT;
    } else if ((entry.match(/:/g) || []).length === 1 && !entry.startsWith("[")) {
      const idx = entry.lastIndexOf(":");
      host = entry.slice(0, idx);
      port = parseInt(entry.slice(idx + 1), 10) || TARGET_PORT;
    }
    return [host, port];
  };

  const entries = String(proxySpec || "")
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const ipv4Re = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;
  const ipv6Re = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;
  const out = [];

  for (const raw of entries) {
    let [host, port] = parseEntry(raw);
    if (raw.includes(".tp")) {
      const m = raw.match(/\.tp(\d+)/);
      if (m) port = parseInt(m[1], 10) || port;
    }
    if (ipv4Re.test(host) || ipv6Re.test(host)) {
      out.push([host, port]);
      continue;
    }
    const [txtAns, aAns] = await Promise.all([dohQuery(host, "TXT"), dohQuery(host, "A")]);
    const txtIps = txtAns
      .filter((r) => r.type === 16 && typeof r.data === "string")
      .flatMap((r) => {
        let s = r.data.trim();
        if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
        return s.replace(/\\010/g, ",").replace(/\n/g, ",").split(",").map((x) => x.trim()).filter(Boolean);
      })
      .map(parseEntry);
    if (txtIps.length > 0) {
      out.push(...txtIps);
      continue;
    }
    const aIps = aAns.filter((r) => r.type === 1 && typeof r.data === "string").map((r) => [r.data, port]);
    if (aIps.length > 0) {
      out.push(...aIps);
      continue;
    }
    const aaaaAns = await dohQuery(host, "AAAA");
    const aaaaIps = aaaaAns.filter((r) => r.type === 28 && typeof r.data === "string").map((r) => [`[${r.data}]`, port]);
    if (aaaaIps.length > 0) {
      out.push(...aaaaIps);
    } else {
      out.push([host, port]);
    }
  }

  out.sort((a, b) => a[0].localeCompare(b[0]));
  const domain = destHost.includes(".") ? destHost.split(".").slice(-2).join(".") : destHost;
  let seed = [...(domain + UUID)].reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
  cachedProxyTargets = [...out]
    .sort(() => ((seed = (seed * 1103515245 + 12345) & 2147483647) / 2147483647) - 0.5)
    .slice(0, 8);
  cachedProxyKey = key;
  return cachedProxyTargets;
}

function createUplinkQueue({ getWriter, releaseWriter, retryConnect, closeConn }) {
  let queue = [];
  let head = 0;
  let queuedBytes = 0;
  let draining = false;
  let closed = false;
  let mergeBuf = null;
  let drainWaiters = [];
  let activeCompletions = null;

  const resolveList = (list, err = null) => {
    if (!list) return;
    for (const item of list) err ? item.reject(err) : item.resolve();
  };

  const compact = () => {
    if (head > 32 && head * 2 >= queue.length) {
      queue = queue.slice(head);
      head = 0;
    }
  };

  const notifyEmpty = () => {
    if (queuedBytes || draining || !drainWaiters.length) return;
    const waiters = drainWaiters;
    drainWaiters = [];
    for (const fn of waiters) fn();
  };

  const clearQueue = (err = null) => {
    const reason = err || (closed ? new Error("Queue closed") : null);
    if (reason) {
      for (let i = head; i < queue.length; i++) {
        resolveList(queue[i]?.completions, reason);
      }
      resolveList(activeCompletions, reason);
      activeCompletions = null;
    }
    queue = [];
    head = 0;
    queuedBytes = 0;
    notifyEmpty();
  };

  const nextBatch = () => {
    if (head >= queue.length) return null;
    const first = queue[head];
    queue[head++] = undefined;
    queuedBytes -= first.chunk.byteLength;
    compact();
    if (head >= queue.length || first.chunk.byteLength >= CHUNK_SIZE) return first;
    let total = first.chunk.byteLength;
    let idx = head;
    let allowRetry = first.allowRetry;
    let completions = first.completions || null;
    while (idx < queue.length) {
      const nxt = queue[idx];
      if (total + nxt.chunk.byteLength > CHUNK_SIZE) break;
      total += nxt.chunk.byteLength;
      allowRetry = allowRetry && nxt.allowRetry;
      if (nxt.completions) completions = completions ? completions.concat(nxt.completions) : nxt.completions;
      idx++;
    }
    if (idx === head) return first;
    if (!mergeBuf) mergeBuf = new Uint8Array(CHUNK_SIZE);
    mergeBuf.set(first.chunk, 0);
    let off = first.chunk.byteLength;
    while (head < idx) {
      const item = queue[head];
      queue[head++] = undefined;
      queuedBytes -= item.chunk.byteLength;
      mergeBuf.set(item.chunk, off);
      off += item.chunk.byteLength;
    }
    compact();
    return { chunk: mergeBuf.subarray(0, total), allowRetry, completions };
  };

  const pump = async () => {
    if (draining || closed) return;
    draining = true;
    try {
      while (!closed) {
        const batch = nextBatch();
        if (!batch) break;
        let writer = getWriter();
        if (!writer) throw new Error("Remote writer unavailable");
        activeCompletions = batch.completions || null;
        try {
          try {
            await writer.write(batch.chunk);
          } catch (err) {
            releaseWriter();
            if (!batch.allowRetry || typeof retryConnect !== "function") throw err;
            await retryConnect();
            writer = getWriter();
            if (!writer) throw err;
            await writer.write(batch.chunk);
          }
          resolveList(activeCompletions);
        } catch (err) {
          resolveList(activeCompletions, err);
          throw err;
        } finally {
          activeCompletions = null;
        }
      }
    } catch (err) {
      closed = true;
      clearQueue(err);
      closeConn();
    } finally {
      draining = false;
      if (!closed && head < queue.length) queueMicrotask(pump);
      else notifyEmpty();
    }
  };

  return {
    write(chunk, allowRetry = true) {
      if (closed || !getWriter()) return Promise.resolve(false);
      const bytes = toUint8(chunk);
      if (!bytes.byteLength) return Promise.resolve(true);
      const nextBytes = queuedBytes + bytes.byteLength;
      const nextCount = queue.length - head + 1;
      if (nextBytes > MAX_QUEUE_BYTES || nextCount > MAX_QUEUE_ITEMS) {
        closed = true;
        const err = new Error("Upload queue overflow");
        clearQueue(err);
        closeConn();
        return Promise.reject(err);
      }
      let pResolve, pReject;
      const done = new Promise((res, rej) => {
        pResolve = res;
        pReject = rej;
      });
      queue.push({
        chunk: bytes,
        allowRetry,
        completions: [{ resolve: pResolve, reject: pReject }]
      });
      queuedBytes = nextBytes;
      if (!draining) queueMicrotask(pump);
      return done.then(() => true);
    },
    async drain() {
      if (!queuedBytes && !draining) return;
      await new Promise((res) => drainWaiters.push(res));
    },
    close() {
      closed = true;
      clearQueue();
    }
  };
}

async function pumpSocket(socket, grpcOut, retryFn) {
  let hasData = false;
  let reader = null;
  let useByob = false;
  try {
    reader = socket.readable.getReader({ mode: "byob" });
    useByob = true;
  } catch {
    reader = socket.readable.getReader();
  }
  try {
    if (useByob) {
      let buf = new ArrayBuffer(CHUNK_SIZE);
      for (;;) {
        const { done, value } = await reader.read(new Uint8Array(buf, 0, CHUNK_SIZE));
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        grpcOut.send(value);
        buf = value.buffer.byteLength >= CHUNK_SIZE ? value.buffer : new ArrayBuffer(CHUNK_SIZE);
      }
    } else {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;
        hasData = true;
        const bytes = toUint8(value);
        for (let off = 0; off < bytes.byteLength; off += CHUNK_SIZE) {
          grpcOut.send(bytes.subarray(off, Math.min(off + CHUNK_SIZE, bytes.byteLength)));
        }
      }
    }
    if (!hasData && retryFn) {
      await retryFn();
      return;
    }
    grpcOut.close();
  } catch {
    if (!hasData && retryFn) {
      try {
        await retryFn();
        return;
      } catch {}
    }
    grpcOut.close();
  } finally {
    try {
      reader.cancel();
    } catch {}
    try {
      reader.releaseLock();
    } catch {}
  }
}

async function openTcpWithRace(dial, candidates, initialData) {
  const tryOne = async (cand) => {
    const sock = dial({ hostname: cand.hostname, port: cand.port });
    let timer;
    try {
      await Promise.race([
        sock.opened,
        new Promise((_, rej) => {
          timer = setTimeout(() => rej(new Error("Connect timeout")), DIAL_TIMEOUT_MS);
        })
      ]);
      return { socket: sock, candidate: cand };
    } catch (err) {
      try {
        sock.close();
      } catch {}
      throw err;
    } finally {
      clearTimeout(timer);
    }
  };

  if (candidates.length === 1) {
    const res = await tryOne(candidates[0]);
    if (initialData && initialData.byteLength > 0) {
      const w = res.socket.writable.getWriter();
      try {
        await w.write(initialData);
      } finally {
        try {
          w.releaseLock();
        } catch {}
      }
    }
    return res.socket;
  }

  const attempts = candidates.map(tryOne);
  let winner = null;
  try {
    winner = await Promise.any(attempts);
  } finally {
    if (winner) {
      for (const p of attempts) {
        p.then(({ socket }) => {
          if (socket !== winner.socket) {
            try {
              socket.close();
            } catch {}
          }
        }).catch(() => {});
      }
    }
  }
  if (initialData && initialData.byteLength > 0) {
    const w = winner.socket.writable.getWriter();
    try {
      await w.write(initialData);
    } finally {
      try {
        w.releaseLock();
      } catch {}
    }
  }
  return winner.socket;
}

async function connectTcp(hostname, port, initialData, grpcOut, state, dial) {
  let initialSent = false;

  const dialDirect = (host, p, data) => {
    const lanes = Array.from({ length: PARALLEL_DIALS }, () => ({ hostname: host, port: p }));
    return openTcpWithRace(dial, lanes, data);
  };

  const dialFallback = async (allowInitial = true) => {
    if (state.connectingPromise) {
      await state.connectingPromise;
      return;
    }
    const sendInit = allowInitial && !initialSent && initialData && initialData.byteLength > 0;
    const data = sendInit ? initialData : null;
    const job = (async () => {
      let sock = null;
      if (TARGET_HOST) {
        const list = await resolveProxyTargets(TARGET_HOST, hostname);
        for (let i = 0; i < list.length; i += PARALLEL_DIALS) {
          const batch = [];
          for (let j = 0; j < PARALLEL_DIALS && i + j < list.length; j++) {
            const idx = (cachedProxyIndex + i + j) % list.length;
            batch.push({ hostname: list[idx][0], port: list[idx][1], idx });
          }
          try {
            sock = await openTcpWithRace(dial, batch, data);
            cachedProxyIndex = batch[0].idx;
            break;
          } catch {}
        }
      }
      if (!sock) {
        sock = await dialDirect(hostname, port, data);
      }
      if (sendInit) initialSent = true;
      state.socket = sock;
      sock.closed.catch(() => {}).finally(() => grpcOut.close());
      pumpSocket(sock, grpcOut, null);
    })();
    state.connectingPromise = job;
    try {
      await job;
    } finally {
      if (state.connectingPromise === job) state.connectingPromise = null;
    }
  };

  state.retryConnect = () => dialFallback(!initialSent);

  try {
    const sock = await dialDirect(hostname, port, initialData);
    if (initialData && initialData.byteLength > 0) initialSent = true;
    state.socket = sock;
    pumpSocket(sock, grpcOut, async () => {
      if (state.socket === sock) await dialFallback(!initialSent);
    });
  } catch {
    await dialFallback(!initialSent);
  }
}

async function forwardDnsUdp(payload, grpcOut, dial) {
  const bytes = toUint8(payload);
  if (!bytes.byteLength) return;
  const sock = dial({ hostname: "8.8.4.4", port: 53 });
  const w = sock.writable.getWriter();
  await w.write(bytes);
  w.releaseLock();
  await sock.readable.pipeTo(
    new WritableStream({
      write(chunk) {
        const b = toUint8(chunk);
        if (b.byteLength && grpcOut.readyState === 1) grpcOut.send(b);
      }
    })
  );
}

function handleGrpc(request, expectedUuid) {
  const dial = getDialer(request);
  const reqReader = request.body.getReader();
  const state = { socket: null, connectingPromise: null, retryConnect: null };
  let isUDP = false;
  let activeWriter = null;
  let activeSocket = null;
  let uplinkQueue = null;

  const headers = new Headers({
    "Content-Type": "application/grpc",
    "grpc-status": "0",
    "X-Accel-Buffering": "no",
    "Cache-Control": "no-store"
  });

  const body = new ReadableStream({
    async start(controller) {
      let closed = false;
      let pending = [];
      let pendingBytes = 0;
      let flushTimer = null;
      let flushQueued = false;

      const flush = (force = false) => {
        flushQueued = false;
        if (flushTimer) {
          clearTimeout(flushTimer);
          flushTimer = null;
        }
        if ((!force && closed) || pendingBytes === 0) return;
        const out = new Uint8Array(pendingBytes);
        let off = 0;
        for (const chunk of pending) {
          out.set(chunk, off);
          off += chunk.byteLength;
        }
        pending = [];
        pendingBytes = 0;
        try {
          controller.enqueue(out);
        } catch {
          closed = true;
          grpcOut.readyState = 3;
        }
      };

      const scheduleFlush = () => {
        if (pendingBytes >= CHUNK_SIZE) {
          flush();
          return;
        }
        if (flushQueued || flushTimer) return;
        flushQueued = true;
        queueMicrotask(() => {
          flushQueued = false;
          if (!closed && pendingBytes > 0 && !flushTimer) {
            flushTimer = setTimeout(() => flush(), 1);
          }
        });
      };

      const grpcOut = {
        readyState: 1,
        send(data) {
          if (closed) return;
          const bytes = toUint8(data);
          const varint = [];
          let len = bytes.byteLength >>> 0;
          while (len > 127) {
            varint.push((len & 127) | 128);
            len >>>= 7;
          }
          varint.push(len);
          const protoLen = 1 + varint.length + bytes.byteLength;
          const frame = new Uint8Array(5 + protoLen);
          frame[0] = 0;
          frame[1] = (protoLen >>> 24) & 255;
          frame[2] = (protoLen >>> 16) & 255;
          frame[3] = (protoLen >>> 8) & 255;
          frame[4] = protoLen & 255;
          frame[5] = 10;
          frame.set(varint, 6);
          frame.set(bytes, 6 + varint.length);
          pending.push(frame);
          pendingBytes += frame.byteLength;
          scheduleFlush();
        },
        close() {
          if (this.readyState === 3) return;
          flush(true);
          closed = true;
          this.readyState = 3;
          if (flushTimer) clearTimeout(flushTimer);
          if (activeWriter) {
            try {
              activeWriter.releaseLock();
            } catch {}
            activeWriter = null;
          }
          activeSocket = null;
          try {
            reqReader.cancel().catch(() => {});
          } catch {}
          try {
            reqReader.releaseLock();
          } catch {}
          try {
            state.socket?.close();
          } catch {}
          try {
            controller.close();
          } catch {}
        }
      };

      const releaseWriter = () => {
        if (activeWriter) {
          try {
            activeWriter.releaseLock();
          } catch {}
          activeWriter = null;
        }
        activeSocket = null;
      };

      const getWriter = () => {
        const s = state.socket;
        if (!s) return null;
        if (s !== activeSocket) {
          releaseWriter();
          activeSocket = s;
          activeWriter = s.writable.getWriter();
        }
        return activeWriter;
      };

      uplinkQueue = createUplinkQueue({
        getWriter,
        releaseWriter,
        retryConnect: async () => {
          if (typeof state.retryConnect !== "function") throw new Error("Retry unavailable");
          await state.retryConnect();
        },
        closeConn: () => {
          try {
            state.socket?.close();
          } catch {}
          grpcOut.close();
        }
      });

      let grpcBuf = EMPTY;
      let vlessParsed = false;
      let vlessBuf = EMPTY;

      const handlePayload = async (chunk) => {
        if (isUDP) {
          await forwardDnsUdp(chunk, grpcOut, dial);
          return;
        }
        if (vlessParsed) {
          if (!(await uplinkQueue.write(chunk, true))) {
            throw new Error("Remote socket is not ready");
          }
          return;
        }
        vlessBuf = concatBytes(vlessBuf, chunk);
        const parsed = parseVless(vlessBuf, expectedUuid);
        if (parsed.needMore) return;
        if (parsed.hasError) throw new Error(parsed.message);
        vlessParsed = true;
        vlessBuf = EMPTY;
        if (parsed.isUDP) {
          if (parsed.port !== 53) throw new Error("UDP is not supported");
          isUDP = true;
        }
        grpcOut.send(new Uint8Array([parsed.version, 0]));
        if (isUDP) {
          if (parsed.rawClientData.byteLength > 0) {
            await forwardDnsUdp(parsed.rawClientData, grpcOut, dial);
          }
        } else {
          await connectTcp(parsed.hostname, parsed.port, parsed.rawClientData, grpcOut, state, dial);
        }
      };

      try {
        while (!closed) {
          const { done, value } = await reqReader.read();
          if (done) break;
          if (!value || value.byteLength === 0) continue;
          grpcBuf = concatBytes(grpcBuf, toUint8(value));
          while (grpcBuf.byteLength >= 5 && !closed) {
            const frameLen =
              5 +
              (((grpcBuf[1] << 24) >>> 0) |
                (grpcBuf[2] << 16) |
                (grpcBuf[3] << 8) |
                grpcBuf[4]);
            if (grpcBuf.byteLength < frameLen) break;
            const payload = grpcBuf.subarray(5, frameLen);
            grpcBuf = grpcBuf.byteLength === frameLen ? EMPTY : grpcBuf.subarray(frameLen);
            if (!payload.byteLength) continue;
            let off = 0;
            while (off < payload.byteLength && !closed) {
              if (payload[off] !== 10) {
                await handlePayload(payload.subarray(off));
                break;
              }
              off++;
              let fieldLen = 0;
              let shift = 0;
              let valid = false;
              while (off < payload.byteLength) {
                const b = payload[off++];
                fieldLen += (b & 0x7f) * (1 << shift);
                if ((b & 0x80) === 0) {
                  valid = true;
                  break;
                }
                shift += 7;
                if (shift > 28) break;
              }
              if (!valid || off + fieldLen > payload.byteLength) {
                throw new Error("Malformed protobuf payload");
              }
              if (fieldLen > 0) {
                await handlePayload(payload.subarray(off, off + fieldLen));
              }
              off += fieldLen;
            }
          }
        }
        flush();
        await uplinkQueue.drain();
        if (state.socket) {
          const w = getWriter();
          if (w) {
            activeWriter = null;
            try {
              await w.close();
            } catch {}
            try {
              w.releaseLock();
            } catch {}
          }
          await state.socket.closed.catch(() => {});
        }
      } catch {
      } finally {
        uplinkQueue.close();
        releaseWriter();
        grpcOut.close();
      }
    },
    cancel() {
      uplinkQueue?.close();
      try {
        state.socket?.close();
      } catch {}
      try {
        reqReader.cancel().catch(() => {});
      } catch {}
    }
  });

  return new Response(body, { status: 200, headers });
}

export default {
  async fetch(request) {
    const expectedUuid = parseUuid(UUID);
    if (!expectedUuid) return new Response("Invalid UUID", { status: 500 });
    const url = new URL(request.url);
    const svc = GRPC_SERVICE_NAME.replace(/^\/+|\/+$/g, "");
    const tunPath = svc ? `/${svc}/Tun` : "/Tun";
    const tunMultiPath = svc ? `/${svc}/TunMulti` : "/TunMulti";
    const contentType = (request.headers.get("content-type") || "").toLowerCase();

    if (
      request.method === "POST" &&
      contentType.startsWith("application/grpc") &&
      (url.pathname === tunPath || url.pathname === tunMultiPath)
    ) {
      if (!request.body) return new Response("Bad Request", { status: 400 });
      return handleGrpc(request, expectedUuid);
    }

    return new Response("Not Found", { status: 404 });
  }
};
