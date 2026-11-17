import { connect } from "cloudflare:sockets";

const UUID = "00000000-0000-4000-8000-000000000000";
const GRPC_SERVICE_NAME = "GunService";
const TARGET_HOST = "proxyip.fxxk.dedyn.io";
const TARGET_PORT = 443;

const MAX_CHUNK = 65536;
const MAX_GRPC_FRAME = 16777216;
const CONNECT_TIMEOUT_MS = 5000;
const EMPTY = new Uint8Array(0);
const decoder = new TextDecoder();

function toUint8(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}

function concatBytes(a, b) {
  if (!a.byteLength) return b;
  if (!b.byteLength) return a;
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
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
  for (let i = 0; i < 16; i++) {
    diff |= buf[offset + i] ^ expected[i];
  }
  return diff === 0;
}

function parseVlessHeader(buf, expectedUuid) {
  const len = buf.byteLength;
  if (len < 18) return null;
  const version = buf[0];
  if (!matchUuid(buf, 1, expectedUuid)) throw new Error("Invalid UUID");
  const addonsLen = buf[17];
  const cmdOffset = 18 + addonsLen;
  if (len < cmdOffset + 4) return null;
  const cmd = buf[cmdOffset];
  if (cmd !== 1 && cmd !== 2) throw new Error("Unsupported command");
  const port = (buf[cmdOffset + 1] << 8) | buf[cmdOffset + 2];
  const addrType = buf[cmdOffset + 3];
  const addrOffset = cmdOffset + 4;
  let hostname = "";
  let dataOffset = 0;

  if (addrType === 1) {
    if (len < addrOffset + 4) return null;
    hostname = `${buf[addrOffset]}.${buf[addrOffset + 1]}.${buf[addrOffset + 2]}.${buf[addrOffset + 3]}`;
    dataOffset = addrOffset + 4;
  } else if (addrType === 2) {
    if (len < addrOffset + 1) return null;
    const domLen = buf[addrOffset];
    if (domLen === 0) throw new Error("Empty domain");
    if (len < addrOffset + 1 + domLen) return null;
    hostname = decoder.decode(buf.subarray(addrOffset + 1, addrOffset + 1 + domLen));
    dataOffset = addrOffset + 1 + domLen;
  } else if (addrType === 3) {
    if (len < addrOffset + 16) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buf[addrOffset + i] << 8) | buf[addrOffset + i + 1]).toString(16));
    }
    hostname = parts.join(":");
    dataOffset = addrOffset + 16;
  } else {
    throw new Error("Invalid address type");
  }

  return {
    version,
    cmd,
    port,
    hostname,
    payload: buf.subarray(dataOffset)
  };
}

function encodeGrpcHunk(data) {
  const len = data.byteLength;
  const varint = [];
  let n = len >>> 0;
  while (n > 0x7f) {
    varint.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  varint.push(n);
  const protoLen = 1 + varint.length + len;
  const frame = new Uint8Array(5 + protoLen);
  frame[0] = 0;
  frame[1] = (protoLen >>> 24) & 0xff;
  frame[2] = (protoLen >>> 16) & 0xff;
  frame[3] = (protoLen >>> 8) & 0xff;
  frame[4] = protoLen & 0xff;
  frame[5] = 0x0a;
  frame.set(varint, 6);
  frame.set(data, 6 + varint.length);
  return frame;
}

function formatHost(hostname) {
  const h = String(hostname || "").trim();
  if (h.startsWith("[") && h.endsWith("]")) return h;
  return h.includes(":") ? `[${h}]` : h;
}

async function openSocketWithTimeout(hostname, port) {
  const socket = connect({ hostname: formatHost(hostname), port });
  let timer;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Connection timeout")), CONNECT_TIMEOUT_MS);
      })
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
}

async function openTarget(hostname, port) {
  try {
    return await openSocketWithTimeout(hostname, port);
  } catch (err) {
    if (!TARGET_HOST) throw err;
    return await openSocketWithTimeout(TARGET_HOST, TARGET_PORT);
  }
}

function handleGrpc(request, expectedUuid) {
  const reqReader = request.body.getReader();
  let closed = false;
  let socket = null;
  let writer = null;
  let sockReader = null;
  let streamController = null;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    if (writer) {
      try {
        writer.releaseLock();
      } catch {}
      writer = null;
    }
    if (sockReader) {
      try {
        sockReader.cancel().catch(() => {});
      } catch {}
      try {
        sockReader.releaseLock();
      } catch {}
      sockReader = null;
    }
    if (socket) {
      try {
        socket.close();
      } catch {}
      socket = null;
    }
    try {
      reqReader.cancel().catch(() => {});
    } catch {}
    try {
      reqReader.releaseLock();
    } catch {}
    if (streamController) {
      try {
        streamController.close();
      } catch {}
    }
  };

  const sendChunk = (data) => {
    if (closed || !streamController) return;
    const bytes = toUint8(data);
    for (let off = 0; off < bytes.byteLength; off += MAX_CHUNK) {
      if (closed) return;
      const slice = bytes.subarray(off, Math.min(off + MAX_CHUNK, bytes.byteLength));
      streamController.enqueue(encodeGrpcHunk(slice));
    }
  };

  const pumpDownlink = async () => {
    try {
      sockReader = socket.readable.getReader();
      while (!closed) {
        const { done, value } = await sockReader.read();
        if (done) break;
        if (value && value.byteLength > 0) sendChunk(value);
      }
    } catch {
    } finally {
      cleanup();
    }
  };

  const body = new ReadableStream({
    start(controller) {
      streamController = controller;
      let grpcBuf = EMPTY;
      let vlessParsed = false;
      let vlessBuf = EMPTY;

      const onGrpcData = async (chunk) => {
        if (closed) return;
        if (!vlessParsed) {
          vlessBuf = concatBytes(vlessBuf, chunk);
          const parsed = parseVlessHeader(vlessBuf, expectedUuid);
          if (!parsed) return;
          vlessParsed = true;
          vlessBuf = EMPTY;
          if (parsed.cmd === 2 && parsed.port !== 53) {
            throw new Error("UDP is only supported on port 53");
          }
          const destHost = parsed.cmd === 2 ? "8.8.4.4" : parsed.hostname;
          const destPort = parsed.cmd === 2 ? 53 : parsed.port;
          socket = await openTarget(destHost, destPort);
          if (closed) {
            try {
              socket.close();
            } catch {}
            return;
          }
          writer = socket.writable.getWriter();
          sendChunk(new Uint8Array([parsed.version, 0]));
          pumpDownlink();
          if (parsed.payload.byteLength > 0) {
            await writer.write(parsed.payload);
          }
        } else if (chunk.byteLength > 0 && writer) {
          await writer.write(chunk);
        }
      };

      const decodeAndForward = async () => {
        while (grpcBuf.byteLength >= 5 && !closed) {
          if (grpcBuf[0] !== 0) throw new Error("Compressed gRPC is not supported");
          const frameLen =
            ((grpcBuf[1] << 24) >>> 0) |
            (grpcBuf[2] << 16) |
            (grpcBuf[3] << 8) |
            grpcBuf[4];
          if (frameLen > MAX_GRPC_FRAME) throw new Error("gRPC frame too large");
          if (grpcBuf.byteLength < 5 + frameLen) break;
          const payload = grpcBuf.subarray(5, 5 + frameLen);
          grpcBuf = grpcBuf.byteLength === 5 + frameLen ? EMPTY : grpcBuf.subarray(5 + frameLen);

          let off = 0;
          while (off < payload.byteLength && !closed) {
            const tag = payload[off++];
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
              if (shift > 28) throw new Error("Varint overflow");
            }
            if (!valid || off + fieldLen > payload.byteLength) {
              throw new Error("Malformed protobuf payload");
            }
            if (tag === 0x0a && fieldLen > 0) {
              await onGrpcData(payload.subarray(off, off + fieldLen));
            }
            off += fieldLen;
          }
        }
      };

      (async () => {
        try {
          while (!closed) {
            const { done, value } = await reqReader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;
            grpcBuf = concatBytes(grpcBuf, toUint8(value));
            await decodeAndForward();
          }
          if (!closed) {
            if (!vlessParsed) {
              cleanup();
            } else if (writer) {
              const w = writer;
              writer = null;
              try {
                await w.close();
              } catch {}
              try {
                w.releaseLock();
              } catch {}
            }
          }
        } catch {
          cleanup();
        }
      })();
    },
    cancel() {
      cleanup();
    }
  });

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "application/grpc",
      "grpc-status": "0",
      "X-Accel-Buffering": "no",
      "Cache-Control": "no-store"
    }
  });
}

export default {
  async fetch(request) {
    const uuidBytes = parseUuid(UUID);
    if (!uuidBytes) return new Response("Invalid UUID configuration", { status: 500 });
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
      return handleGrpc(request, uuidBytes);
    }

    return new Response("Not Found", { status: 404 });
  }
};
