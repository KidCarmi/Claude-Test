// 2F-F real-binary browser journeys: the Upstream Proxies surface at
// /app/network/upstream over the actual CULVERT binary on the AUTH appliance
// (never a mock). Written on the FROZEN 2F-E baseline (ba2d852b) before the
// surface exists — every journey fails there on the missing route.
//
// Directive §7 proofs, each against the frozen 2F-C/2F-D backend truth:
//   J1  viewer: the surface renders mode/coverage/node-local truth with ZERO
//       write controls and ZERO non-GET requests; no cross-surface calls.
//   J2  admin lifecycle: create (T2) → unprobed row → replace credential
//       (T2, canary password) → the canary and the sealed ciphertext reach
//       NO browser sink (wire bodies, request URLs, DOM, web storage, page
//       URL) → authority edit refused credential_bound → delete refused
//       credential_present → clear (T3, typed id) → delete (T2) → gone.
//   J3  STALE WRITE: a concurrent API edit bumps the entry revision; the
//       page's edit carries the revision it loaded; the appliance refuses
//       409 stale; the page renders the server's current token and issues
//       exactly one PUT (no auto-retry); after Refresh the edit lands.
//   J4  MANUAL PROBE: the accepted run re-arms the appliance's 10 s window;
//       the page's probe inside it is refused 429 with Retry-After, rendered
//       from the structured body, never retried by the page; after the
//       SERVER-DECLARED Retry-After the next probe is accepted and the
//       counts-only summary renders.
//   J5  requiresReplacement (C12): a version-2 import declaring a
//       credential this node never held lands the entry in the distinct
//       requiresReplacement state; the page renders the count banner and
//       the row state; T2 replace resolves it to configured; T3 clear +
//       delete restore the appliance.
//
// Everything created is removed in finally blocks through the fenced API
// (clear → delete), so the shared appliance ends the spec unchanged.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page, Response } from "@playwright/test";
import { AUTH_DATA_DIR, AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

const ROUTE = "/app/network/upstream";
const SUFFIX = Date.now().toString(36).slice(-6);
const HOST2 = `parent-2ff-${SUFFIX}-j2.test`;
const HOST3 = `parent-2ff-${SUFFIX}-j3.test`;
const HOST5 = `parent-2ff-${SUFFIX}-j5.test`;
const PORT = 3128;
const CANARY_PW = `Canary-Browser-PW-2ff-${SUFFIX}`;
const SETTINGS = join(AUTH_DATA_DIR, "admin_settings.json");

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function newAdminClient(xff: string): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok()).toBe(true);
  return ctx;
}

async function readModel(
  api: APIRequestContext,
): Promise<Record<string, unknown>> {
  const resp = await api.get("/api/upstream");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad /api/upstream envelope");
  return v;
}

async function docRevision(api: APIRequestContext): Promise<number> {
  const v = await readModel(api);
  if (typeof v["revision"] !== "number") throw new Error("no revision");
  return v["revision"];
}

interface Entry {
  id: string;
  revision: number;
  credentialState: string;
  username: string;
}

async function findEntry(
  api: APIRequestContext,
  host: string,
): Promise<Entry | null> {
  const v = await readModel(api);
  if (!Array.isArray(v["entries"])) return null;
  for (const e of v["entries"]) {
    if (isRecord(e) && e["host"] === host) {
      return {
        id: String(e["id"]),
        revision: Number(e["revision"]),
        credentialState: String(e["credentialState"]),
        username: typeof e["username"] === "string" ? e["username"] : "",
      };
    }
  }
  return null;
}

async function createViaApi(
  api: APIRequestContext,
  host: string,
  username: string,
): Promise<Entry> {
  const resp = await api.post("/api/upstream/entries", {
    data: {
      scheme: "http",
      host,
      port: PORT,
      username,
      revision: await docRevision(api),
    },
  });
  expect(resp.status(), await resp.text()).toBe(201);
  const e = await findEntry(api, host);
  if (e === null) throw new Error("created entry not listed");
  return e;
}

/** Restore: Tier-3 clear (typed confirm) then delete, both fenced. */
async function removeEntry(
  api: APIRequestContext,
  host: string,
): Promise<void> {
  const cur = await findEntry(api, host);
  if (cur === null) return;
  if (cur.credentialState !== "none") {
    const clr = await api.post(`/api/upstream/entries/${cur.id}/credential`, {
      data: { action: "clear", confirm: cur.id, revision: cur.revision },
    });
    expect(clr.status(), await clr.text()).toBe(200);
  }
  const fresh = await findEntry(api, host);
  if (fresh !== null) {
    const del = await api.delete(
      `/api/upstream/entries/${fresh.id}?revision=${String(fresh.revision)}`,
    );
    expect(del.status(), await del.text()).toBe(200);
  }
  expect(await findEntry(api, host)).toBeNull();
}

/** Ciphertexts sealed for host on the appliance disk (same-host harness). */
function ciphertextsOnDisk(host: string): string[] | null {
  if (!existsSync(SETTINGS)) return null;
  try {
    const s: unknown = JSON.parse(readFileSync(SETTINGS, "utf8"));
    if (!isRecord(s)) return null;
    const doc = s["upstream_proxies_v2"];
    if (!isRecord(doc) || !Array.isArray(doc["entries"])) return [];
    const out: string[] = [];
    for (const e of doc["entries"]) {
      if (!isRecord(e) || e["host"] !== host) continue;
      const c = e["credential"];
      if (isRecord(c) && typeof c["ciphertext"] === "string")
        out.push(c["ciphertext"]);
    }
    return out;
  } catch {
    return null;
  }
}

async function storageDump(page: Page): Promise<string> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k !== null) out.push(`${k}=${sessionStorage.getItem(k) ?? ""}`);
    }
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null) out.push(`${k}=${localStorage.getItem(k) ?? ""}`);
    }
    return out.join("\n");
  });
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

function trackApiRequests(
  page: Page,
): Array<{ method: string; path: string; url: string }> {
  const calls: Array<{ method: string; path: string; url: string }> = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/")) {
      calls.push({ method: r.method(), path: u.pathname, url: r.url() });
    }
  });
  return calls;
}

const ALLOWED_PREFIXES = [
  "/api/upstream",
  "/api/auth/",
  "/api/setup/",
  "/api/session",
];
function assertNoCrossSurface(
  calls: ReadonlyArray<{ method: string; path: string }>,
): void {
  for (const c of calls) {
    expect(
      ALLOWED_PREFIXES.some((p) => c.path.startsWith(p)),
      `unexpected cross-surface call ${c.method} ${c.path}`,
    ).toBe(true);
  }
}

const MUTATION_WORDS = [
  "New entry",
  "Edit",
  "Delete",
  "Replace",
  "Clear",
  "Probe",
  "Save",
  "Seal",
];

async function openSurface(page: Page): Promise<void> {
  await page.goto(ROUTE);
  await expect(
    page.getByRole("heading", { name: "Upstream Proxies", exact: false }),
  ).toBeVisible();
  await expect(page.getByTestId("upstream-mode")).toBeVisible();
}

function rowFor(page: Page, host: string) {
  return page.locator("tr[data-entry-id]", { hasText: host });
}

// ── J1: viewer ──────────────────────────────────────────────────────────────
test.describe("viewer posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("viewer reads mode, coverage and node-local truth; zero mutation controls; zero non-GET requests", async ({
    page,
  }) => {
    const api = await newAdminClient("198.51.100.120");
    try {
      await createViaApi(api, HOST2, "svc");
      const calls = trackApiRequests(page);
      await page.goto(ROUTE);
      await login(page, USERS.viewer.user, USERS.viewer.pass);
      await expect(
        page.getByRole("heading", { name: "Upstream Proxies", exact: false }),
      ).toBeVisible();
      await expect(rowFor(page, HOST2)).toBeVisible();
      await expect(page.getByTestId("upstream-mode")).toBeVisible();
      await expect(page.getByText(/plain HTTP/).first()).toBeVisible();
      await expect(page.getByText(/node-local/i).first()).toBeVisible();
      const texts = await page.getByRole("button").allTextContents();
      const offending = texts.filter((t) =>
        MUTATION_WORDS.some((w) => t.includes(w)),
      );
      expect(offending).toEqual([]);
      expect(await rowFor(page, HOST2).getByRole("button").count()).toBe(0);
      const mutating = calls.filter(
        (c) => c.method !== "GET" && !c.path.startsWith("/api/auth/"),
      );
      expect(mutating).toEqual([]);
      assertNoCrossSurface(calls);
    } finally {
      await removeEntry(api, HOST2);
      await api.dispose();
    }
  });
});

// ── J2: admin lifecycle + leak sweep ────────────────────────────────────────
test("admin: create → seal credential (canary) → no browser sink carries it → credential_bound → credential_present → T3 clear → delete", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.121");
  await removeEntry(api, HOST2); // stale fixture from an aborted run
  const bodies: Array<{ url: string; body: string }> = [];
  page.on("response", (r: Response) => {
    const url = r.url();
    if (!url.startsWith(AUTH_URL)) return;
    void r
      .text()
      .then((t) => bodies.push({ url, body: t }))
      .catch(() => undefined);
  });
  const calls = trackApiRequests(page);
  try {
    await openSurface(page);
    // create (T2)
    await page.getByRole("button", { name: "New entry" }).click();
    await page.getByLabel("Host").fill(HOST2);
    await page.getByLabel("Port").fill(String(PORT));
    await page.getByLabel("Username").fill("svc");
    await page.getByRole("button", { name: "Create entry" }).click();
    const row = rowFor(page, HOST2);
    await expect(row).toBeVisible();
    await expect(row).toHaveAttribute("data-credential-state", "none");
    await expect(row).toContainText(/unprobed/i);
    const created = await findEntry(api, HOST2);
    expect(created?.credentialState).toBe("none");
    const id = created?.id ?? "";
    expect(id).not.toBe("");

    // replace (T2) with the canary
    await row.getByRole("button", { name: "Replace credential" }).click();
    const pw = page.getByLabel("Password");
    await expect(pw).toHaveAttribute("type", "password");
    await pw.fill(CANARY_PW);
    await page.getByRole("button", { name: "Seal credential" }).click();
    await expect(rowFor(page, HOST2)).toHaveAttribute(
      "data-credential-state",
      "configured",
    );
    expect((await findEntry(api, HOST2))?.credentialState).toBe("configured");
    const cts = ciphertextsOnDisk(HOST2);
    if (cts !== null) expect(cts.length).toBe(1);

    // authority edit → credential_bound (exactly one PUT)
    const putsBefore = calls.filter((c) => c.method === "PUT").length;
    await rowFor(page, HOST2).getByRole("button", { name: "Edit" }).click();
    await page.getByLabel("Host").fill(`moved-${HOST2}`);
    await page.getByRole("button", { name: "Save entry" }).click();
    await expect(page.getByText("credential_bound").first()).toBeVisible();
    expect(calls.filter((c) => c.method === "PUT").length - putsBefore).toBe(1);
    expect((await findEntry(api, HOST2))?.id).toBe(id);

    // delete → credential_present (exactly one DELETE, token in the query)
    await rowFor(page, HOST2)
      .getByRole("button", { name: "Delete entry" })
      .click();
    await page.getByRole("button", { name: "Delete now" }).click();
    await expect(page.getByText("credential_present").first()).toBeVisible();
    const dels = calls.filter((c) => c.method === "DELETE");
    expect(dels).toHaveLength(1);
    expect(dels[0]?.url).toContain(`/api/upstream/entries/${id}?revision=`);
    expect((await findEntry(api, HOST2))?.credentialState).toBe("configured");

    // sweep every browser sink for the canary + the sealed ciphertext
    await page.evaluate(async () => {
      await fetch("/api/upstream");
    });
    await page.waitForLoadState("networkidle");
    const needles = [
      { label: "canary password", value: CANARY_PW },
      ...(cts ?? []).map((c) => ({ label: "sealed ciphertext", value: c })),
    ];
    const dom = await page.content();
    const storage = await storageDump(page);
    const leaks: string[] = [];
    for (const n of needles) {
      for (const b of bodies)
        if (b.body.includes(n.value))
          leaks.push(`${n.label} in response body of ${b.url}`);
      for (const c of calls)
        if (c.url.includes(n.value))
          leaks.push(`${n.label} in request URL ${c.url}`);
      if (dom.includes(n.value)) leaks.push(`${n.label} in DOM`);
      if (storage.includes(n.value)) leaks.push(`${n.label} in web storage`);
      if (page.url().includes(n.value)) leaks.push(`${n.label} in page URL`);
    }
    expect(leaks).toEqual([]);
    expect(
      bodies.some(
        (b) => b.url.includes("/api/upstream") && b.body.includes(HOST2),
      ),
    ).toBe(true);
    const credResp = bodies.find((b) =>
      b.url.includes(`/entries/${id}/credential`),
    );
    expect(credResp).toBeDefined();
    expect(credResp?.body ?? "").not.toContain(CANARY_PW);
    if (cts === null) {
      test.info().annotations.push({
        type: "note",
        description: `ciphertext needle skipped: ${SETTINGS} not reachable from the runner`,
      });
    }

    // clear (T3): the exact entry id must be typed
    await rowFor(page, HOST2)
      .getByRole("button", { name: "Clear credential" })
      .click();
    const clearNow = page.getByRole("button", { name: "Clear now" });
    await expect(clearNow).toBeDisabled();
    await page.getByLabel("Type the entry id").fill("not-the-id");
    await expect(clearNow).toBeDisabled();
    await page.getByLabel("Type the entry id").fill(id);
    await expect(clearNow).toBeEnabled();
    await clearNow.click();
    await expect(rowFor(page, HOST2)).toHaveAttribute(
      "data-credential-state",
      "none",
    );
    expect((await findEntry(api, HOST2))?.credentialState).toBe("none");

    // delete (T2) — now permitted
    await rowFor(page, HOST2)
      .getByRole("button", { name: "Delete entry" })
      .click();
    await page.getByRole("button", { name: "Delete now" }).click();
    await expect(rowFor(page, HOST2)).toHaveCount(0);
    expect(await findEntry(api, HOST2)).toBeNull();
    assertNoCrossSurface(calls);
  } finally {
    await removeEntry(api, HOST2);
    await api.dispose();
  }
});

// ── J3: stale write ─────────────────────────────────────────────────────────
test("admin: a concurrent API edit makes the page's edit stale; the server token renders, exactly one PUT; after Refresh the edit lands", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.122");
  await removeEntry(api, HOST3);
  try {
    const seeded = await createViaApi(api, HOST3, "svc");
    const calls = trackApiRequests(page);
    await openSurface(page);
    await expect(rowFor(page, HOST3)).toBeVisible();
    // concurrent admin: username change through the API bumps the revision
    const bump = await api.put(`/api/upstream/entries/${seeded.id}`, {
      data: {
        scheme: "http",
        host: HOST3,
        port: PORT,
        username: "other",
        revision: seeded.revision,
      },
    });
    expect(bump.status(), await bump.text()).toBe(200);
    const moved = await findEntry(api, HOST3);
    expect(moved?.revision).toBe(seeded.revision + 1);
    // the page still holds the revision it loaded
    await rowFor(page, HOST3).getByRole("button", { name: "Edit" }).click();
    await page.getByLabel("Port").fill("3129");
    await page.getByRole("button", { name: "Save entry" }).click();
    await expect(page.getByText("Stale write refused")).toBeVisible();
    await expect(
      page.getByText(`current revision ${String(seeded.revision + 1)}`),
    ).toBeVisible();
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(1);
    const unchanged = await findEntry(api, HOST3);
    expect(unchanged?.username).toBe("other");
    // fresh truth, then the edit lands against the current revision
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await expect(rowFor(page, HOST3)).toContainText("other");
    await rowFor(page, HOST3).getByRole("button", { name: "Edit" }).click();
    await page.getByLabel("Port").fill("3129");
    await page.getByRole("button", { name: "Save entry" }).click();
    await expect(rowFor(page, HOST3)).toContainText("3129");
    expect(calls.filter((c) => c.method === "PUT")).toHaveLength(2);
    assertNoCrossSurface(calls);
  } finally {
    await removeEntry(api, HOST3);
    await api.dispose();
  }
});

// ── J4: manual probe rate limit ─────────────────────────────────────────────
test("admin: a manual probe inside the appliance's window is refused 429 (rendered, never retried); after the server-declared Retry-After it is accepted", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.123");
  try {
    const calls = trackApiRequests(page);
    await openSurface(page);
    // Prime: an ACCEPTED run re-arms the 10 s window at this instant. The
    // poll observes the appliance's own window (a refused run does not
    // re-arm it), so the page's click below lands inside a fresh window.
    await expect
      .poll(async () => (await api.post("/api/upstream/health")).status(), {
        timeout: 20_000,
        intervals: [500],
      })
      .toBe(200);
    const refused = page.waitForResponse(
      (r) =>
        r.url().includes("/api/upstream/health") &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Probe now" }).click();
    const resp = await refused;
    expect(resp.status()).toBe(429);
    const retryAfter = Number(resp.headers()["retry-after"] ?? "0");
    expect(retryAfter).toBeGreaterThan(0);
    await expect(
      page.getByText(/probe_(rate_limited|in_flight)/).first(),
    ).toBeVisible();
    await expect(
      page.getByText(new RegExp(`${String(retryAfter)}\\s*s`)).first(),
    ).toBeVisible();
    expect(calls.filter((c) => c.path === "/api/upstream/health")).toHaveLength(
      1,
    );
    // The SERVER-declared Retry-After is the protocol's own instruction —
    // waiting exactly that long is channel-controlled, not a guess.
    await page.waitForTimeout(retryAfter * 1000);
    await page.getByRole("button", { name: "Probe now" }).click();
    await expect(page.getByText(/probed \d+/i).first()).toBeVisible();
    expect(calls.filter((c) => c.path === "/api/upstream/health")).toHaveLength(
      2,
    );
    assertNoCrossSurface(calls);
  } finally {
    await api.dispose();
  }
});

// ── J5: requiresReplacement (C12) ───────────────────────────────────────────
function ulid(): string {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytes = randomBytes(23);
  let s = "01J";
  for (const b of bytes) s += alphabet[b % 32];
  return s;
}

test("admin: an imported declared credential lands in requiresReplacement; the banner + row state render; T2 replace resolves it", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.124");
  await removeEntry(api, HOST5);
  const id = ulid();
  const doc = {
    version: 2,
    exportedAt: "2026-09-07T00:00:00Z",
    upstream_proxies_v2: {
      entries: [
        {
          id,
          scheme: "http",
          host: HOST5,
          port: PORT,
          username: "svc",
          credentialState: "configured",
        },
      ],
    },
    upstream_credentials: "omitted",
  };
  try {
    const dry = await api.post("/api/config/import?dryRun=1", { data: doc });
    expect(dry.status(), await dry.text()).toBe(200);
    const plan: unknown = await dry.json();
    const digest =
      isRecord(plan) && typeof plan["importDigest"] === "string"
        ? plan["importDigest"]
        : "";
    expect(digest).not.toBe("");
    const commit = await api.post(
      `/api/config/import?importDigest=${encodeURIComponent(digest)}`,
      { data: doc },
    );
    expect(commit.status(), await commit.text()).toBe(200);
    const landed = await findEntry(api, HOST5);
    expect(landed?.id).toBe(id);
    expect(landed?.credentialState).toBe("requiresReplacement");
    const model = await readModel(api);
    expect(model["credentialsRequiringReplacement"]).toBeGreaterThanOrEqual(1);

    const calls = trackApiRequests(page);
    await openSurface(page);
    const banner = page.getByRole("alert").filter({ hasText: /replacement/i });
    await expect(banner.first()).toBeVisible();
    await expect(banner.first()).not.toContainText(/bypass/i);
    const row = rowFor(page, HOST5);
    await expect(row).toHaveAttribute(
      "data-credential-state",
      "requiresReplacement",
    );
    await expect(row).toContainText(/replacement/i);
    // T2 replace resolves the marker
    await row.getByRole("button", { name: "Replace credential" }).click();
    await page.getByLabel("Password").fill(CANARY_PW);
    await page.getByRole("button", { name: "Seal credential" }).click();
    await expect(rowFor(page, HOST5)).toHaveAttribute(
      "data-credential-state",
      "configured",
    );
    expect((await findEntry(api, HOST5))?.credentialState).toBe("configured");
    expect(calls.some((c) => c.url.includes(CANARY_PW))).toBe(false);
    assertNoCrossSurface(calls);
  } finally {
    await removeEntry(api, HOST5);
    await api.dispose();
  }
});
