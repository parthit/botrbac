// api/blob-sign.mjs: only the Python app may ask, only for held-file pieces.
// Run with `npm test` (node --test). @vercel/blob's control API is never called: the
// signed token is a fake; presignUrl is the real one when it is installed.

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";

import { makeHandler, sign, signerKey } from "../../api/blob-sign.mjs";

const KEY = "test-encryption-key-0123456789abcdefghijkl";
const NOW = Date.UTC(2026, 10, 24, 12, 0, 0);
const PATH = "drops/1795000000/AbC_d-9/0";

function fakeToken(validUntil) {
  const payload = { storeId: "store123", pathname: "*", operations: ["put", "get"], validUntil };
  const seg = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return { delegationToken: `${seg}.sig`, clientSigningToken: "client-secret", validUntil };
}

function fakeBlob() {
  const calls = { issued: 0, presigned: [] };
  return {
    calls,
    blob: {
      async issueSignedToken(options) {
        calls.issued += 1;
        calls.issueOptions = options;
        return fakeToken(options.validUntil);
      },
      async presignUrl(_token, options) {
        calls.presigned.push(options);
        return { presignedUrl: `https://vercel.com/api/blob/?pathname=${options.pathname}` };
      },
    },
  };
}

function request(payload, { key = KEY, at = NOW, method = "POST", raw, signature } = {}) {
  const body = raw ?? JSON.stringify(payload);
  const ts = String(Math.floor(at / 1000));
  const headers = {
    "content-type": "application/json",
    "x-botrbac-timestamp": ts,
    "x-botrbac-signature": signature ?? sign(signerKey(key), ts, body),
  };
  return new Request("https://example.test/api/blob-sign", {
    method,
    headers,
    body: method === "POST" ? body : undefined,
  });
}

const put = { op: "put", pathname: PATH, maxBytes: 1024, validForSeconds: 900, ttlDays: 2 };

function handler(extra = {}) {
  const fake = fakeBlob();
  const handle = makeHandler({ blob: fake.blob, env: { ENCRYPTION_KEY: KEY }, now: () => NOW, ...extra });
  return { fake, handle };
}

test("the key matches the Python derivation", () => {
  // drop_storage.signer_key: HMAC-SHA256(ENCRYPTION_KEY.strip(), "botrbac blob signer v1").
  const expected = createHmac("sha256", KEY).update("botrbac blob signer v1").digest("hex");
  assert.equal(signerKey(`  ${KEY}\n`).toString("hex"), expected);
});

test("a signed put is answered with a URL and the upload headers", async () => {
  const { fake, handle } = handler();
  const res = await handle(request(put));
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.match(data.url, /^https:\/\/vercel\.com\/api\/blob\//);
  assert.equal(data.headers["x-vercel-blob-access"], "private");
  assert.equal(data.headers["x-vercel-blob-store-id"], "store123");
  const [options] = fake.calls.presigned;
  assert.equal(options.operation, "put");
  assert.equal(options.maximumSizeInBytes, 1024);
  assert.equal(options.ttlDays, 2);
  assert.equal(options.allowOverwrite, false);
  assert.equal(options.access, "private");
  assert.equal(options.validUntil, NOW + 900 * 1000);
});

test("the token is reused until near its expiry", async () => {
  let now = NOW;
  const { fake, handle } = handler({ now: () => now });
  await handle(request(put, { at: now }));
  await handle(request({ op: "get", pathname: PATH, validForSeconds: 300 }, { at: now }));
  assert.equal(fake.calls.issued, 1);
  now += 2 * 60 * 60 * 1000 - 10 * 60 * 1000; // 10 minutes left: less than one URL's life
  await handle(request(put, { at: now }));
  assert.equal(fake.calls.issued, 2);
});

test("a wrong signature, another key, or no signature is refused", async () => {
  const { fake, handle } = handler();
  assert.equal((await handle(request(put, { key: "another-key" }))).status, 401);
  assert.equal((await handle(request(put, { signature: "0".repeat(64) }))).status, 401);
  assert.equal((await handle(request(put, { signature: "nothex" }))).status, 401);
  const bare = new Request("https://example.test/api/blob-sign", { method: "POST", body: "{}" });
  assert.equal((await handle(bare)).status, 401);
  assert.equal(fake.calls.issued, 0);
});

test("a body changed after signing is refused", async () => {
  const { handle } = handler();
  const body = JSON.stringify(put);
  const ts = String(Math.floor(NOW / 1000));
  const signature = sign(signerKey(KEY), ts, body);
  const tampered = JSON.stringify({ ...put, maxBytes: 4 * 1024 * 1024 });
  const res = await handle(request(null, { raw: tampered, signature }));
  assert.equal(res.status, 401);
});

test("a request older or newer than 60 seconds is refused", async () => {
  const { handle } = handler();
  assert.equal((await handle(request(put, { at: NOW - 61_000 }))).status, 401);
  assert.equal((await handle(request(put, { at: NOW + 61_000 }))).status, 401);
  assert.equal((await handle(request(put, { at: NOW - 59_000 }))).status, 200);
});

test("only held-file piece pathnames are signed", async () => {
  const { fake, handle } = handler();
  for (const pathname of [
    "other/1/abc/0",
    "drops/1/abc/0/../../secret",
    "drops/1/abc",
    "drops/x/abc/0",
    "drops/1/a.b/0",
    "drops/1/abc/12345",
    `drops/1/${"a".repeat(65)}/0`,
    "*",
  ]) {
    const res = await handle(request({ ...put, pathname }));
    assert.equal(res.status, 400, pathname);
  }
  assert.equal(fake.calls.presigned.length, 0);
});

test("sizes, lifetimes and operations are bounded", async () => {
  const { handle } = handler();
  const bad = [
    { ...put, op: "delete" },
    { ...put, maxBytes: 4 * 1024 * 1024 + 1 },
    { ...put, maxBytes: 0 },
    { ...put, maxBytes: undefined },
    { ...put, validForSeconds: 901 },
    { ...put, ttlDays: 0 },
    { ...put, ttlDays: 1.5 },
    { op: "get", pathname: PATH, validForSeconds: 0 },
  ];
  for (const payload of bad) {
    assert.equal((await handle(request(payload))).status, 400, JSON.stringify(payload));
  }
  assert.equal((await handle(request(null, { raw: "not json" }))).status, 400);
  assert.equal((await handle(request(null, { raw: "[1]" }))).status, 400);
});

test("only POST, and nothing without ENCRYPTION_KEY", async () => {
  const { handle } = handler();
  assert.equal((await handle(request(put, { method: "GET" }))).status, 405);
  const fake = fakeBlob();
  const unset = makeHandler({ blob: fake.blob, env: {}, now: () => NOW });
  assert.equal((await unset(request(put))).status, 503);
});

test("a large body is refused before it is read", async () => {
  const { handle } = handler();
  const res = await handle(request(null, { raw: `{"pad":"${"x".repeat(5000)}"}` }));
  assert.equal(res.status, 413);
});

test("a failure from Blob is a 502 and the next request asks for a new token", async () => {
  const fake = fakeBlob();
  let fail = true;
  const blob = {
    ...fake.blob,
    async presignUrl(token, options) {
      if (fail) throw new Error("boom");
      return fake.blob.presignUrl(token, options);
    },
  };
  const handle = makeHandler({ blob, env: { ENCRYPTION_KEY: KEY }, now: () => NOW });
  assert.equal((await handle(request(put))).status, 502);
  fail = false;
  assert.equal((await handle(request(put))).status, 200);
  assert.equal(fake.calls.issued, 2);
});

test("the real presignUrl accepts what is asked of it", async (t) => {
  let real;
  try {
    real = await import("@vercel/blob");
  } catch {
    t.skip("@vercel/blob is not installed (npm ci)");
    return;
  }
  const fake = fakeBlob();
  const blob = { issueSignedToken: fake.blob.issueSignedToken, presignUrl: real.presignUrl };
  // The real presignUrl checks expiry against the real clock.
  const handle = makeHandler({ blob, env: { ENCRYPTION_KEY: KEY } });
  const at = Date.now();
  const res = await handle(request(put, { at }));
  assert.equal(res.status, 200);
  const upload = new URL((await res.json()).url);
  assert.equal(upload.origin, "https://vercel.com");
  assert.equal(upload.searchParams.get("pathname"), PATH);
  assert.equal(upload.searchParams.get("vercel-blob-maximum-size-in-bytes"), "1024");
  assert.equal(upload.searchParams.get("vercel-blob-ttl-days"), "2");
  assert.equal(upload.searchParams.get("vercel-blob-allow-overwrite"), "false");
  const got = await handle(request({ op: "get", pathname: PATH, validForSeconds: 300 }, { at }));
  assert.equal(got.status, 200);
  const download = new URL((await got.json()).url);
  assert.equal(download.origin, "https://store123.private.blob.vercel-storage.com");
  assert.equal(download.pathname, `/${PATH}`);
});
