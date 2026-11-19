import { afterAll, describe, expect, test } from "vitest";
import { Access } from "../src/access.js";
import { Bridge } from "../src/bridge.js";
import { createApp, safeNext } from "../src/app.js";
import { newId } from "../src/ids.js";
import { MemoryStore } from "../src/store/memory.js";
import { PgStore } from "../src/store/pg-store.js";
import { createPgliteDb, type PgliteDb } from "../src/store/pglite.js";
import type { Store } from "../src/store/types.js";
import type { UserRow } from "../src/types.js";

const BASE = "http://bridge.test";
const FILES: Record<string, { name: string; mimeType: string; parents: string[]; trashed?: boolean; text?: string }> = {
  folder: { name: "Shared", mimeType: "application/vnd.google-apps.folder", parents: ["root"] },
  child: { name: "Notes", mimeType: "text/plain", parents: ["folder"], text: "hello from drive" },
  outside: { name: "Private", mimeType: "text/plain", parents: ["root"], text: "secret" },
  root: { name: "My Drive", mimeType: "application/vnd.google-apps.folder", parents: [] },
};

function driveFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = String(input);
  const params = new URLSearchParams(typeof init?.body === "string" ? init.body : "");
  if (url.includes("userinfo")) return Promise.resolve(Response.json({ sub: "ada", email: "ada@example.com" }));
  if (url.includes("oauth2.googleapis.com/token") && params.get("grant_type") === "refresh_token") {
    return Promise.resolve(Response.json({ access_token: "drive-access" }));
  }
  if (url.includes("oauth2.googleapis.com/token")) {
    return Promise.resolve(Response.json({ access_token: "once", refresh_token: "refresh-secret", scope: "https://www.googleapis.com/auth/drive.readonly" }));
  }
  if (url.includes("/drive/v3/about")) return Promise.resolve(Response.json({ user: { emailAddress: "ada@example.com" } }));
  const fileMatch = url.match(/\/drive\/v3\/files\/([^/?]+)/);
  if (fileMatch && !url.includes("alt=media")) {
    const file = FILES[decodeURIComponent(fileMatch[1]!)];
    if (!file) return Promise.resolve(new Response("missing", { status: 404 }));
    return Promise.resolve(Response.json({ id: decodeURIComponent(fileMatch[1]!), ...file }));
  }
  if (fileMatch && url.includes("alt=media")) {
    const file = FILES[decodeURIComponent(fileMatch[1]!)];
    return Promise.resolve(new Response(file?.text ?? "", { status: file ? 200 : 404 }));
  }
  if (url.includes("/drive/v3/files?")) {
    return Promise.resolve(Response.json({ files: [{ id: "child", name: "Notes", mimeType: "text/plain" }, { id: "outside", name: "Private", mimeType: "text/plain" }] }));
  }
  return Promise.resolve(new Response("missing", { status: 404 }));
}

describe("drive card", () => {
  test("a granted folder exposes its child and hides the rest", async () => {
    const store = new MemoryStore();
    const user: UserRow = { user_id: newId("usr"), email: null, created_at: new Date() };
    await store.insertUser(user);
    const bridge = new Bridge(store);
    const registered = await bridge.register({ displayName: "Alex", userId: user.user_id }, BASE);
    if (!registered.ok) throw new Error(registered.message);
    const bot = await bridge.authenticate(registered.data.token);
    if (!bot) throw new Error("bot missing");
    const access = new Access(store, {
      encryptionKey: "test-key",
      fetch: driveFetch,
      googleDrive: { clientId: "gid", clientSecret: "gsecret" },
    });
    const empty = await access.catalog(bot);
    expect(empty.ok && empty.data.integrations).toEqual([]);

    const connected = await access.finishDriveConnect({
      bot,
      code: "code",
      verifier: "verifier",
      redirectUri: `${BASE}/integrations/google-drive/callback`,
      capabilities: ["list", "read"],
    });
    expect(connected.ok).toBe(true);
    const stored = JSON.stringify(await store.listConnections(bot.bot_id));
    expect(stored).not.toContain("refresh-secret");

    await access.grant(bot, { kind: "folder", externalId: "folder", name: "Shared" });
    expect(await access.toolNames(bot)).toEqual(["drive_list_folder", "drive_search", "drive_get_metadata", "drive_read_file"]);
    const read = await access.call(bot, "drive_read_file", { file_id: "child" }, BASE);
    expect(read.ok).toBe(true);
    if (read.ok) expect(read.data).toMatchObject({ text: "hello from drive" });

    const denied = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.error).toBe("access_required");
      expect(String(denied.details?.approval_url)).toContain("/access/ar_");
      const token = String(denied.details?.approval_url).split("/").pop() ?? "";
      const approved = await access.decideAccess(token, user.user_id, "approve");
      expect(approved.ok && approved.data.status).toBe("approved");
    }
    const allowed = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
    expect(allowed.ok).toBe(true);

    const other = await bridge.register({ displayName: "Blair", userId: user.user_id }, BASE);
    if (!other.ok) throw new Error(other.message);
    const second = await bridge.authenticate(other.data.token);
    if (!second) throw new Error("second bot missing");
    const separate = await access.catalog(second);
    expect(separate.ok && separate.data.integrations).toEqual([]);
    const catalog = await access.catalog(bot);
    expect(catalog.ok && catalog.data.integrations[0]?.resources).toEqual([
      { kind: "folder", id: "folder", name: "Shared" },
      { kind: "file", id: "outside", name: "outside" },
    ]);
    expect(catalog.ok && JSON.stringify(catalog.data)).not.toContain("refresh");

    const write = await access.setCapabilities(bot, ["list", "read", "trash"]);
    expect(write.ok).toBe(false);
    if (!write.ok) expect(write.error).toBe("needs_reconnect");
    expect(await access.toolNames(bot)).not.toContain("drive_trash_file");
  });
});

describe("drive http", () => {
  test("the integrations page connects a drive card for one bot", async () => {
    const server = createApp({
      store: new MemoryStore(),
      baseUrl: BASE,
      sessionSecret: "test-session-secret",
      encryptionKey: "test-key",
      oauth: { google: { clientId: "gid", clientSecret: "gsecret" } },
      googleDrive: { clientId: "gid", clientSecret: "gsecret" },
      fetch: driveFetch,
    });
    const start = await server.request(`${BASE}/auth/google`);
    const location = new URL(start.headers.get("location") ?? "", "https://accounts.google.com");
    const state = location.searchParams.get("state") ?? "";
    const oauthCookie = start.headers.getSetCookie().find((item) => item.startsWith("bb_oauth="))?.split(";")[0] ?? "";
    const callback = await server.request(`${BASE}/auth/google/callback?code=ada&state=${encodeURIComponent(state)}`, { headers: { cookie: oauthCookie } });
    const session = callback.headers.getSetCookie().find((item) => item.startsWith("bb_session="))?.split(";")[0] ?? "";
    const created = await server.request(`${BASE}/register`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ display_name: "Alex" }),
    });
    const bot = (await created.json()) as { bot_id: string };
    const page = await server.request(`${BASE}/bots/${bot.bot_id}`, { headers: { cookie: session } });
    const html = await page.text();
    expect(html).toContain("Google Drive");
    expect(html).toContain("Integrations");
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
    const connect = await server.request(`${BASE}/bots/${bot.bot_id}/drive/connect`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf, capability: "list" }),
    });
    expect(connect.status).toBe(302);
    expect(connect.headers.get("location")).toContain("drive.readonly");
  });
});

async function driveBot(store: Store, fetchImpl: typeof fetch = driveFetch) {
  const user: UserRow = { user_id: newId("usr"), email: null, created_at: new Date() };
  await store.insertUser(user);
  const bridge = new Bridge(store);
  const registered = await bridge.register({ displayName: "Alex", userId: user.user_id }, BASE);
  if (!registered.ok) throw new Error(registered.message);
  const bot = await bridge.authenticate(registered.data.token);
  if (!bot) throw new Error("bot missing");
  const access = new Access(store, { encryptionKey: "test-key", fetch: fetchImpl, googleDrive: { clientId: "gid", clientSecret: "gsecret" } });
  const connected = await access.finishDriveConnect({ bot, code: "code", verifier: "v", redirectUri: `${BASE}/cb`, capabilities: ["list", "read"] });
  if (!connected.ok) throw new Error(connected.message);
  await access.grant(bot, { kind: "folder", externalId: "folder", name: "Shared" });
  return { user, bot, access };
}

function registerAccessRequestTests(name: string, makeStore: () => Promise<Store>) {
  describe(name, () => {
    test("overlapping out-of-scope calls share one approval request", async () => {
      const { bot, access } = await driveBot(await makeStore());
      const results = await Promise.all([
        access.call(bot, "drive_read_file", { file_id: "outside" }, BASE),
        access.call(bot, "drive_read_file", { file_id: "outside" }, BASE),
        access.call(bot, "drive_get_metadata", { file_id: "outside" }, BASE),
      ]);
      const ids = results.map((result) => {
        expect(result.ok).toBe(false);
        if (result.ok) return null;
        expect(result.error).toBe("access_required");
        return result.details?.request_id;
      });
      expect(ids[0]).toBeTruthy();
      expect(new Set(ids).size).toBe(1);
    });

    test("only the first decision on a request counts", async () => {
      const { user, bot, access } = await driveBot(await makeStore());
      const denied = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
      if (denied.ok) throw new Error("expected access_required");
      const token = String(denied.details?.approval_url).split("/").pop() ?? "";
      const first = await access.decideAccess(token, user.user_id, "deny");
      expect(first.ok && first.data.status).toBe("denied");
      const second = await access.decideAccess(token, user.user_id, "approve");
      expect(second.ok && second.data.status).toBe("denied");
      const still = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
      expect(still.ok).toBe(false);
    });
  });
}

registerAccessRequestTests("memory access requests", async () => new MemoryStore());

let pglite: PgliteDb | null = null;
registerAccessRequestTests("postgres access requests", async () => {
  if (!pglite) {
    pglite = await createPgliteDb();
    await new PgStore(pglite).ensureSchema();
  }
  return new PgStore(pglite);
});

afterAll(async () => {
  await pglite?.close();
});

describe("drive writes", () => {
  function writeFetch(calls: string[], uploadStatus: number): typeof fetch {
    return (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("oauth2.googleapis.com/token")) {
        return Response.json({ access_token: "a", refresh_token: "r", scope: "https://www.googleapis.com/auth/drive" });
      }
      if (url.includes("/upload/drive/v3/files/")) return new Response("nope", { status: uploadStatus });
      if (init?.method === "POST" && url.includes("/drive/v3/files?")) return Response.json({ id: "new-file", name: "n.txt" });
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      return driveFetch(input, init);
    }) as typeof fetch;
  }

  test("a rejected upload is reported and the empty file is removed", async () => {
    const calls: string[] = [];
    const { bot, access } = await driveBot(new MemoryStore(), writeFetch(calls, 403));
    expect((await access.setCapabilities(bot, ["list", "read", "write"])).ok).toBe(true);
    const upload = await access.call(bot, "drive_upload_file", { name: "n.txt", content: "hi", parent_id: "folder" }, BASE);
    expect(upload.ok).toBe(false);
    if (!upload.ok) expect(upload.error).toBe("drive_write_failed");
    expect(calls.some((call) => call.startsWith("DELETE ") && call.includes("/files/new-file"))).toBe(true);

    const update = await access.call(bot, "drive_update_file", { file_id: "child", content: "hi" }, BASE);
    expect(update.ok).toBe(false);
    if (!update.ok) expect(update.error).toBe("drive_write_failed");
  });

  test("a successful upload reports the new file", async () => {
    const calls: string[] = [];
    const { bot, access } = await driveBot(new MemoryStore(), writeFetch(calls, 200));
    expect((await access.setCapabilities(bot, ["list", "read", "write"])).ok).toBe(true);
    const upload = await access.call(bot, "drive_upload_file", { name: "n.txt", content: "hi", parent_id: "folder" }, BASE);
    expect(upload.ok && upload.data).toEqual({ id: "new-file", name: "n.txt" });
    expect(calls.some((call) => call.startsWith("DELETE "))).toBe(false);
  });
});

describe("drive oauth http", () => {
  function app(store: Store) {
    return createApp({
      store,
      baseUrl: BASE,
      sessionSecret: "test-session-secret",
      encryptionKey: "test-key",
      oauth: { google: { clientId: "gid", clientSecret: "gsecret" } },
      googleDrive: { clientId: "gid", clientSecret: "gsecret" },
      fetch: driveFetch,
    });
  }

  async function signIn(server: ReturnType<typeof createApp>, next?: string) {
    const start = await server.request(`${BASE}/auth/google${next ? `?next=${encodeURIComponent(next)}` : ""}`);
    const location = new URL(start.headers.get("location") ?? "", "https://accounts.google.com");
    const state = location.searchParams.get("state") ?? "";
    const oauthCookie = start.headers.getSetCookie().find((item) => item.startsWith("bb_oauth="))?.split(";")[0] ?? "";
    const callback = await server.request(`${BASE}/auth/google/callback?code=ada&state=${encodeURIComponent(state)}`, { headers: { cookie: oauthCookie } });
    const session = callback.headers.getSetCookie().find((item) => item.startsWith("bb_session="))?.split(";")[0] ?? "";
    return { state, oauthCookie, callback, session };
  }

  async function newBot(server: ReturnType<typeof createApp>, session: string) {
    const created = await server.request(`${BASE}/register`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ display_name: "Alex" }),
    });
    return (await created.json()) as { bot_id: string; token: string };
  }

  test("the OAuth state does not carry the PKCE verifier", async () => {
    const server = app(new MemoryStore());
    const { state, oauthCookie, callback } = await signIn(server);
    expect(state).not.toContain(".");
    expect(oauthCookie).not.toContain(state);
    expect(callback.status).toBe(303);

    const start = await server.request(`${BASE}/auth/google`);
    const cookie = start.headers.getSetCookie().find((item) => item.startsWith("bb_oauth="))?.split(";")[0] ?? "";
    const forged = await server.request(`${BASE}/auth/google/callback?code=ada&state=${encodeURIComponent(cookie.slice("bb_oauth=".length))}`, {
      headers: { cookie },
    });
    expect(forged.status).toBe(400);
  });

  test("every ticked capability survives the connect and save forms", async () => {
    const store = new MemoryStore();
    const server = app(store);
    const { session } = await signIn(server);
    const bot = await newBot(server, session);
    const page = await server.request(`${BASE}/bots/${bot.bot_id}`, { headers: { cookie: session } });
    const csrf = /name="csrf" value="([^"]+)"/.exec(await page.text())?.[1] ?? "";
    const form = new URLSearchParams();
    form.append("csrf", csrf);
    form.append("capability", "list");
    form.append("capability", "read");
    const connect = await server.request(`${BASE}/bots/${bot.bot_id}/drive/connect`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/x-www-form-urlencoded" },
      body: form,
    });
    const location = new URL(connect.headers.get("location") ?? "");
    const state = location.searchParams.get("state") ?? "";
    const oauthCookie = connect.headers.getSetCookie().find((item) => item.startsWith("bb_oauth="))?.split(";")[0] ?? "";
    const callback = await server.request(`${BASE}/integrations/google-drive/callback?code=x&state=${encodeURIComponent(state)}`, {
      headers: { cookie: `${session}; ${oauthCookie}` },
    });
    expect(callback.status).toBe(303);
    const connection = await store.findConnection(bot.bot_id, "google_drive");
    expect(connection).toBeTruthy();
    expect((await store.listCapabilities(connection!.connection_id)).sort()).toEqual(["list", "read"]);

    await store.setCapabilities(connection!.connection_id, ["read"]);
    const save = await server.request(`${BASE}/bots/${bot.bot_id}/drive/capabilities`, {
      method: "POST",
      headers: { cookie: session, "content-type": "application/x-www-form-urlencoded" },
      body: form,
    });
    expect(save.status).toBe(303);
    expect((await store.listCapabilities(connection!.connection_id)).sort()).toEqual(["list", "read"]);
  });

  test("a signed-out approval link returns to the approval page after sign-in", async () => {
    const store = new MemoryStore();
    const server = app(store);
    const { session } = await signIn(server);
    const created = await newBot(server, session);
    const bot = await new Bridge(store).authenticate(created.token);
    if (!bot) throw new Error("bot missing");
    const access = new Access(store, { encryptionKey: "test-key", fetch: driveFetch, googleDrive: { clientId: "gid", clientSecret: "gsecret" } });
    await access.finishDriveConnect({ bot, code: "c", verifier: "v", redirectUri: `${BASE}/cb`, capabilities: ["read"] });
    const denied = await access.call(bot, "drive_read_file", { file_id: "outside" }, BASE);
    if (denied.ok) throw new Error("expected access_required");
    const path = new URL(String(denied.details?.approval_url)).pathname;

    const signedOut = await server.request(`${BASE}${path}`);
    expect(signedOut.status).toBe(303);
    const login = signedOut.headers.get("location") ?? "";
    expect(login).toBe(`/login?next=${encodeURIComponent(path)}`);
    const loginHtml = await (await server.request(`${BASE}${login}`)).text();
    expect(loginHtml).toContain(`/auth/google?next=${encodeURIComponent(path)}`);

    const { callback, session: again } = await signIn(server, path);
    expect(callback.headers.get("location")).toBe(path);
    const approval = await server.request(`${BASE}${path}`, { headers: { cookie: again } });
    expect(approval.status).toBe(200);
    expect(await approval.text()).toContain("Approve");
  });

  test("sign-in never redirects off site", async () => {
    expect(safeNext("/access/ar_x")).toBe("/access/ar_x");
    for (const bad of ["//evil.example", "https://evil.example", "/\\evil.example", "evil", "", null, "/a\nb"]) {
      expect(safeNext(bad)).toBeNull();
    }
    const server = app(new MemoryStore());
    const { callback } = await signIn(server, "//evil.example/x");
    expect(callback.headers.get("location")).toBe("/");
  });
});
