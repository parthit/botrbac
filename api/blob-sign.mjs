// Signs Vercel Blob URLs for held files (drops), so the browser uploads and downloads
// pieces straight to and from Blob instead of through the Python function, and upload
// URLs for files an assistant sends (uploads.py, start_upload with direct), so the
// assistant's sandbox uploads the file itself instead of copying it into tool calls. The Python SDK
// has no issueSignedToken/presignUrl; @vercel/blob does.
//
// Not public. Only the Python app (src/scoped_drive_mcp/drop_storage.py, HttpBlobSigner)
// calls it, and it decides who may send or read what. Each request carries
//   x-botrbac-timestamp: <unix seconds>
//   x-botrbac-signature: hex HMAC-SHA256(key, "<timestamp>.<raw body>")
// with key = HMAC-SHA256(ENCRYPTION_KEY, "botrbac blob signer v1"), so no new secret is
// needed. Older than 60 seconds is refused. The body is JSON:
//   {op: "put", pathname, maxBytes, validForSeconds, ttlDays}
//   {op: "get", pathname, validForSeconds}
// and only pathnames of held-file pieces (drops/<expiry>/<id>/<n>) or of assistant
// uploads (uploads/<expiry>/<id>, "put" only: the Python app reads them back with its
// own token) whose expiry has not passed are signed. An upload URL is for that one pathname, at most maxBytes, as
// application/octet-stream, and never over a blob that is already there.
// The answer is {url} (plus {headers} the browser sends with a PUT).

import { createHmac, timingSafeEqual } from "node:crypto";

// The same shape as drop_storage._BLOB_PATH; the first number is the drop's expiry.
export const PATHNAME = /^drops\/(\d{1,12})\/[A-Za-z0-9_-]{1,64}\/\d{1,4}$/;
// The same shape as uploads.blob_path; the number is when the upload expires.
export const UPLOAD_PATHNAME = /^uploads\/(\d{1,12})\/[A-Za-z0-9_-]{16,64}$/;
export const MAX_AGE_SECONDS = 60;
// One sealed piece (drop_storage.PIECE_BYTES + SEAL_OVERHEAD).
export const MAX_PIECE_BYTES = 4 * 1024 * 1024 + 29;
// One whole file an assistant uploads: the most MAX_BYTES may be (config.py).
export const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const CONTENT_TYPE = "application/octet-stream";
// Blob's CDN may keep a piece this long after it is deleted (the least Blob allows).
const CACHE_SECONDS = 60;
export const MAX_VALID_SECONDS = 15 * 60;
export const MAX_TTL_DAYS = 30;
const MAX_BODY_BYTES = 4096;
// The Blob API version @vercel/blob 2.9.0 sends with an upload (x-api-version).
const BLOB_API_VERSION = "13";
// The delegation token is asked for once and reused until this close to its expiry
// (issueSignedToken calls Blob's control API). Every URL it signs ends before it does.
const TOKEN_LIFETIME_MS = 2 * 60 * 60 * 1000;
const TOKEN_REFRESH_MS = MAX_VALID_SECONDS * 1000 + 5 * 60 * 1000;

export function signerKey(encryptionKey) {
  return createHmac("sha256", encryptionKey.trim()).update("botrbac blob signer v1").digest();
}

export function sign(key, timestamp, body) {
  return createHmac("sha256", key).update(`${timestamp}.`).update(body).digest("hex");
}

function isInt(value, min, max) {
  return Number.isInteger(value) && value >= min && value <= max;
}

/** Why this request may not be signed, or null. `body` is the raw request body. */
export function authError(headers, body, encryptionKey, nowSeconds) {
  if (!encryptionKey || !encryptionKey.trim()) return "not configured";
  const timestamp = headers.get("x-botrbac-timestamp") || "";
  const given = headers.get("x-botrbac-signature") || "";
  if (!/^\d{1,12}$/.test(timestamp) || !/^[0-9a-f]{64}$/.test(given)) return "unauthorized";
  if (Math.abs(nowSeconds - Number(timestamp)) > MAX_AGE_SECONDS) return "expired";
  const expected = Buffer.from(sign(signerKey(encryptionKey), timestamp, body), "hex");
  const actual = Buffer.from(given, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return "unauthorized";
  }
  return null;
}

/** The checked request, or a string saying what is wrong with it. */
export function parseRequest(body, nowSeconds) {
  let req;
  try {
    req = JSON.parse(body);
  } catch {
    return "invalid json";
  }
  if (!req || typeof req !== "object" || Array.isArray(req)) return "invalid request";
  const { op, pathname, validForSeconds } = req;
  if (op !== "put" && op !== "get") return "invalid op";
  const held = typeof pathname === "string" ? PATHNAME.exec(pathname) : null;
  const upload = typeof pathname === "string" ? UPLOAD_PATHNAME.exec(pathname) : null;
  const match = held || upload;
  if (!match) return "invalid pathname";
  // Nobody is given a read URL for an assistant's upload.
  if (upload && op !== "put") return "invalid op";
  // Nothing for a file whose hold has ended, and no upload held longer than Blob keeps it.
  const expiry = Number(match[1]);
  if (expiry <= nowSeconds) return "expired pathname";
  if (!isInt(validForSeconds, 1, MAX_VALID_SECONDS)) return "invalid validForSeconds";
  if (op === "get") return { op, pathname, validForSeconds };
  const { maxBytes, ttlDays } = req;
  if (!isInt(maxBytes, 1, upload ? MAX_UPLOAD_BYTES : MAX_PIECE_BYTES)) return "invalid maxBytes";
  if (!isInt(ttlDays, 1, MAX_TTL_DAYS)) return "invalid ttlDays";
  if (expiry > nowSeconds + ttlDays * 86400) return "invalid pathname";
  return { op, pathname, validForSeconds, maxBytes, ttlDays };
}

/** The body as text, read at most `limit` bytes (null past that, whatever
 * content-length said). */
export async function readCapped(request, limit) {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** {delegationToken, ...} in base64url JSON, then "."; the store id is in it. */
function storeIdOf(delegationToken) {
  try {
    const payload = delegationToken.slice(0, delegationToken.indexOf("."));
    return String(JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).storeId || "");
  } catch {
    return "";
  }
}

/**
 * The request handler, with the Blob SDK passed in (tests pass a fake).
 * `blob` is {issueSignedToken, presignUrl}.
 */
export function makeHandler({ blob, env = process.env, now = () => Date.now() }) {
  let cached = null;

  async function token() {
    if (!cached || cached.validUntil - now() < TOKEN_REFRESH_MS) {
      // A token is for one pathname or for all of them (Blob has no prefix scope), so
      // this one is for all: its signing key never leaves this function, and each URL
      // is signed for one checked pathname only, with its own size cap. No delete, no
      // head, one whole assistant upload at most.
      cached = await blob.issueSignedToken({
        pathname: "*",
        operations: ["put", "get"],
        validUntil: now() + TOKEN_LIFETIME_MS,
        maximumSizeInBytes: MAX_UPLOAD_BYTES,
      });
    }
    return cached;
  }

  const reply = (status, data) => Response.json(data, { status, headers: { "cache-control": "no-store" } });

  return async function handle(request) {
    if (request.method !== "POST") return reply(405, { error: "method not allowed" });
    const length = Number(request.headers.get("content-length") || "0");
    if (length > MAX_BODY_BYTES) return reply(413, { error: "too large" });
    const body = await readCapped(request, MAX_BODY_BYTES);
    if (body === null) return reply(413, { error: "too large" });
    const nowSeconds = Math.floor(now() / 1000);
    const denied = authError(request.headers, body, env.ENCRYPTION_KEY, nowSeconds);
    if (denied === "not configured") return reply(503, { error: denied });
    if (denied) return reply(401, { error: denied });
    const req = parseRequest(body, nowSeconds);
    if (typeof req === "string") return reply(400, { error: req });
    try {
      const signed = await token();
      const validUntil = now() + req.validForSeconds * 1000;
      if (req.op === "get") {
        const { presignedUrl } = await blob.presignUrl(signed, {
          operation: "get",
          pathname: req.pathname,
          access: "private",
          validUntil,
        });
        return reply(200, { url: presignedUrl });
      }
      const { presignedUrl } = await blob.presignUrl(signed, {
        operation: "put",
        pathname: req.pathname,
        access: "private",
        validUntil,
        maximumSizeInBytes: req.maxBytes,
        allowedContentTypes: [CONTENT_TYPE],
        addRandomSuffix: false,
        allowOverwrite: false,
        cacheControlMaxAge: CACHE_SECONDS,
        ttlDays: req.ttlDays,
      });
      // What @vercel/blob's own upload sends along with a presigned URL.
      const headers = {
        "x-vercel-blob-access": "private",
        "x-api-version": BLOB_API_VERSION,
        "x-content-type": CONTENT_TYPE,
      };
      const storeId = storeIdOf(signed.delegationToken || "");
      if (storeId) headers["x-vercel-blob-store-id"] = storeId;
      return reply(200, { url: presignedUrl, headers });
    } catch (err) {
      cached = null;
      console.error("blob-sign failed:", err && err.name, err && err.message);
      return reply(502, { error: "signing failed" });
    }
  };
}

let handler = null;

export async function POST(request) {
  if (!handler) {
    const { issueSignedToken, presignUrl } = await import("@vercel/blob");
    handler = makeHandler({ blob: { issueSignedToken, presignUrl } });
  }
  return handler(request);
}

export function GET() {
  return Response.json({ error: "method not allowed" }, { status: 405 });
}
