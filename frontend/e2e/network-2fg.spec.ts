// 2F-G closure journeys — the final cross-surface proofs for Batch 2F that
// no earlier spec establishes (inventory in the 2F-G record). Real
// appliances only: the AUTH instance for navigation, posture, PAC, Upstream
// and CDR; the YAML-seeded instance for the read-only `yaml` posture.
//
//   N1  Network navigation: the sidebar reaches both surfaces, the routes are
//       served, an unauthenticated deep link returns to the intended route
//       after sign-in (viewer floor for PAC, admin for Upstream).
//   N2  Admin-only: an OPERATOR sees no mutation control on PAC or Upstream
//       and issues no non-GET request; the appliance refuses operator AND
//       viewer mutations with 403 and nothing changes.
//   N3  YAML read-only posture on the seeded appliance: the config.yaml row
//       is labelled read-only with no controls, survives a reload, and every
//       mutation on it is refused 409 yaml_owned.
//   N4  CDR: a lost enrollment answer leaves the non-secret recovery marker;
//       it survives a full reload (the app boots with an unresolved subject
//       before the owner is authoritative) and SPA navigation, surfaces for
//       its owner, never carries the token, and the auth boundary clears it.
//   N5  PAC: a publish that never left the browser latches the recovery
//       marker; signing out clears it; nothing else persists for Upstream.
//   N6  PAC: a raw server error body never reaches the DOM, URL or storage;
//       the outcome stays unresolved, never a success.
//   N7  Node-local labels: PAC lifecycle, PAC DIRECT exceptions and Upstream
//       health after a manual probe stay labelled after reload and Refresh.
//
// No retries, no enlarged timeouts, no skips: every assertion reads the
// appliance's own answer.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS, YAML_URL } from "./fixtures";
import { expectNavLinkReachable } from "./nav-open";

const PAC_ROUTE = "/app/network/pac";
const UP_ROUTE = "/app/network/upstream";
const CDR_ROUTE = "/app/security/cdr";
const SUFFIX = Date.now().toString(36).slice(-6);
const POOL_ID = `g2fgpool${SUFFIX}`;
const PROFILE_ID = `g2fgprof${SUFFIX}`;
const PROFILE_NAME = `E2E 2FG ${SUFFIX}`;
const UP_HOST = `parent-2fg-${SUFFIX}.invalid`;
const CDR_NAME = `e2e-2fg-${SUFFIX}`;
const CDR_TOKEN = `one-time-token-2fg-${SUFFIX}`;
const PAC_MARKER = "culvert.pac.lifecycle-recovery.v1";
const CDR_MARKER = "culvert.cdr.enroll-recovery.v1";
const RAW_CANARY = `RAWCANARY-${SUFFIX}-/srv/never/render`;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function newClient(
  base: string,
  xff: string,
  user: { user: string; pass: string },
): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: base,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: user.user, pass: user.pass },
  });
  expect(login.ok(), await login.text()).toBe(true);
  return ctx;
}

async function refusalCode(resp: {
  json: () => Promise<unknown>;
}): Promise<string> {
  const v: unknown = await resp.json();
  return isRecord(v) && typeof v["code"] === "string" ? v["code"] : "";
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

function trackApiRequests(page: Page): Array<{ method: string; path: string }> {
  const calls: Array<{ method: string; path: string }> = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/"))
      calls.push({ method: r.method(), path: u.pathname });
  });
  return calls;
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

async function sessionItem(page: Page, key: string): Promise<string | null> {
  return page.evaluate((k) => sessionStorage.getItem(k), key);
}

/** §23 hygiene: after the auth boundary nothing but the theme key remains. */
async function expectStorageClean(page: Page): Promise<void> {
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  const ls = await page.evaluate(() => Object.keys(localStorage));
  expect(ls.filter((k) => k !== "culvert-theme")).toEqual([]);
}

const PAC_MUTATION_WORDS = [
  "Publish",
  "Save draft",
  "New profile",
  "New pool",
  "Delete",
  "Roll back",
  "Acknowledge",
  "Repair",
  "Save",
  "Clear",
  "Recover",
  "Govern",
  "Edit",
];
const UP_MUTATION_WORDS = [
  "New entry",
  "Edit",
  "Delete",
  "Replace",
  "Clear",
  "Probe",
  "Save",
  "Seal",
];

async function offendingButtons(
  page: Page,
  words: readonly string[],
): Promise<string[]> {
  const texts = await page.getByRole("button").allTextContents();
  return texts.filter((t) => words.some((w) => t.includes(w)));
}

// ── PAC fixture (API, admin) ────────────────────────────────────────────────

async function pacListing(
  api: APIRequestContext,
): Promise<Record<string, unknown>> {
  const resp = await api.get("/api/pac/profiles");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad profiles listing");
  return v;
}

async function pacLifecycle(
  api: APIRequestContext,
): Promise<Record<string, unknown>> {
  const resp = await api.get(`/api/pac/profiles/${PROFILE_ID}/lifecycle`);
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad lifecycle");
  return v;
}

function num(v: Record<string, unknown>, k: string): number {
  const n = v[k];
  if (typeof n !== "number") throw new Error(`missing number ${k}`);
  return n;
}

function str(v: Record<string, unknown>, k: string): string {
  const s = v[k];
  if (typeof s !== "string") throw new Error(`missing string ${k}`);
  return s;
}

async function seedPacFixture(api: APIRequestContext): Promise<void> {
  const l = await pacListing(api);
  const pool = await api.post("/api/pac/pools", {
    data: {
      id: POOL_ID,
      name: `E2E 2FG pool ${SUFFIX}`,
      endpoints: [{ host: "proxy-a.e2e.test", port: 3128 }],
      collectionEtag: str(l, "collectionEtag"),
    },
  });
  expect(pool.status(), await pool.text()).toBe(200);
  const l2 = await pacListing(api);
  const prof = await api.post("/api/pac/profiles", {
    data: {
      id: PROFILE_ID,
      name: PROFILE_NAME,
      description: "2F-G closure journey fixture",
      enabled: true,
      poolId: POOL_ID,
      rules: [],
      privateNetworks: "proxy",
      availabilityMode: "secure",
      revision: 1,
      collectionEtag: str(l2, "collectionEtag"),
    },
  });
  expect(prof.status(), await prof.text()).toBe(200);
  const lc = await pacLifecycle(api);
  const draft = await api.post(`/api/pac/profiles/${PROFILE_ID}/lifecycle`, {
    data: {
      action: "save_draft",
      draft: {
        id: PROFILE_ID,
        name: PROFILE_NAME,
        description: "2F-G closure journey fixture",
        enabled: true,
        poolId: POOL_ID,
        rules: [
          {
            kind: "domain",
            pattern: "closure.e2e.test",
            action: "use_pool",
            poolId: POOL_ID,
          },
        ],
        privateNetworks: "proxy",
        availabilityMode: "secure",
        revision: 0,
      },
      draftRevision: num(lc, "draftRevision"),
    },
  });
  expect(draft.status(), await draft.text()).toBe(200);
}

async function cleanupPac(api: APIRequestContext): Promise<void> {
  const l = await pacListing(api);
  const profiles = Array.isArray(l["profiles"]) ? l["profiles"] : [];
  for (const p of profiles) {
    if (isRecord(p) && p["id"] === PROFILE_ID) {
      const del = await api.delete(
        `/api/pac/profiles/${PROFILE_ID}?revision=${String(p["revision"])}`,
      );
      expect([204, 404]).toContain(del.status());
    }
  }
  const etags = l["poolEtags"];
  if (isRecord(etags) && typeof etags[POOL_ID] === "string") {
    const del = await api.delete(
      `/api/pac/pools/${POOL_ID}?etag=${encodeURIComponent(etags[POOL_ID])}`,
    );
    expect([204, 404]).toContain(del.status());
  }
}

async function openProfile(page: Page): Promise<void> {
  await page.goto(PAC_ROUTE);
  await page.getByRole("tab", { name: "Profiles" }).click();
  const row = page.getByRole("row", { name: new RegExp(PROFILE_NAME) });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Open" }).click();
  await expect(page.getByText("Active revision")).toBeVisible();
}

async function clickPublish(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Publish", exact: true }).click();
  await page.getByRole("button", { name: "Publish now" }).click();
}

// ── Upstream fixture (API, admin) ───────────────────────────────────────────

interface UpEntry {
  id: string;
  revision: number;
  credentialState: string;
  source: string;
}

async function upModel(
  api: APIRequestContext,
): Promise<Record<string, unknown>> {
  const resp = await api.get("/api/upstream");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad /api/upstream envelope");
  return v;
}

async function upFind(
  api: APIRequestContext,
  match: (e: Record<string, unknown>) => boolean,
): Promise<UpEntry | null> {
  const v = await upModel(api);
  if (!Array.isArray(v["entries"])) return null;
  for (const e of v["entries"]) {
    if (isRecord(e) && match(e)) {
      return {
        id: String(e["id"]),
        revision: Number(e["revision"]),
        credentialState: String(e["credentialState"]),
        source: String(e["source"]),
      };
    }
  }
  return null;
}

async function upCreate(
  api: APIRequestContext,
  host: string,
): Promise<UpEntry> {
  const resp = await api.post("/api/upstream/entries", {
    data: {
      scheme: "http",
      host,
      port: 3128,
      username: "",
      revision: num(await upModel(api), "revision"),
    },
  });
  expect(resp.status(), await resp.text()).toBe(201);
  const e = await upFind(api, (x) => x["host"] === host);
  if (e === null) throw new Error("created entry not listed");
  return e;
}

async function upRemove(api: APIRequestContext, host: string): Promise<void> {
  const cur = await upFind(api, (x) => x["host"] === host);
  if (cur === null) return;
  const del = await api.delete(
    `/api/upstream/entries/${cur.id}?revision=${String(cur.revision)}`,
  );
  expect(del.status(), await del.text()).toBe(200);
}

function upRow(page: Page, host: string) {
  return page.locator("tr[data-entry-id]", { hasText: host });
}

// ── N1: navigation + route availability ─────────────────────────────────────

test("N1 network navigation: the sidebar reaches PAC and Upstream and both routes are served", async ({
  page,
}) => {
  await page.goto("/app/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expectNavLinkReachable(page, "PAC");
  await expectNavLinkReachable(page, "Upstream Proxies");
  await page.getByRole("link", { name: "PAC", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/network\/pac$/);
  await expect(
    page.getByRole("heading", { name: "PAC", exact: false }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Upstream Proxies" }).click();
  await expect(page).toHaveURL(/\/app\/network\/upstream$/);
  await expect(
    page.getByRole("heading", { name: "Upstream Proxies", exact: false }),
  ).toBeVisible();
  await expect(page.getByTestId("upstream-mode")).toBeVisible();
  // The appliance serves both routes as the SPA document (no 404, no
  // redirect to the legacy UI).
  for (const route of [PAC_ROUTE, UP_ROUTE]) {
    const resp = await page.request.get(route);
    expect(resp.status(), route).toBe(200);
    expect(resp.headers()["content-type"] ?? "").toContain("text/html");
  }
});

test.describe("N1 unauthenticated deep links return to the intended route", () => {
  test.use({ storageState: EMPTY_STATE });
  test("Upstream (admin) and PAC (viewer floor)", async ({ page }) => {
    await page.goto(UP_ROUTE);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(/\/app\/network\/upstream$/);
    await expect(
      page.getByRole("heading", { name: "Upstream Proxies", exact: false }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

    await page.goto(PAC_ROUTE);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page).toHaveURL(/\/app\/network\/pac$/);
    await expect(
      page.getByRole("heading", { name: "PAC", exact: false }),
    ).toBeVisible();
  });
});

// ── N2: admin-only — operator posture + server-authoritative 403s ───────────

test.describe("N2 admin-only mutations", () => {
  test.use({ storageState: EMPTY_STATE });
  test("an operator sees no mutation control on PAC or Upstream; the appliance refuses operator and viewer mutations with 403 and nothing changes", async ({
    page,
  }) => {
    const admin = await newClient(AUTH_URL, "198.51.100.130", USERS.admin);
    const op = await newClient(AUTH_URL, "198.51.100.131", USERS.operator);
    const viewer = await newClient(AUTH_URL, "198.51.100.132", USERS.viewer);
    try {
      await seedPacFixture(admin);
      await upCreate(admin, UP_HOST);
      const before = {
        profiles: await pacListing(admin),
        upstream: await upModel(admin),
      };

      const calls = trackApiRequests(page);
      await page.goto(PAC_ROUTE);
      await login(page, USERS.operator.user, USERS.operator.pass);
      await expect(
        page.getByRole("heading", { name: "PAC", exact: false }),
      ).toBeVisible();
      await expect(page.getByText("operator", { exact: true })).toBeVisible();
      for (const tab of [
        "Profiles",
        "Pools",
        "DIRECT Exceptions",
        "Legacy PAC",
      ]) {
        await page.getByRole("tab", { name: tab }).click();
        expect(await offendingButtons(page, PAC_MUTATION_WORDS)).toEqual([]);
      }
      await page.getByRole("tab", { name: "Profiles" }).click();
      const row = page.getByRole("row", { name: new RegExp(PROFILE_NAME) });
      await expect(row).toBeVisible();
      await row.getByRole("button", { name: "Open" }).click();
      await expect(page.getByText("Active revision")).toBeVisible();
      expect(await offendingButtons(page, PAC_MUTATION_WORDS)).toEqual([]);

      await page.goto(UP_ROUTE);
      await expect(page.getByTestId("upstream-mode")).toBeVisible();
      await expect(upRow(page, UP_HOST)).toBeVisible();
      expect(await offendingButtons(page, UP_MUTATION_WORDS)).toEqual([]);
      expect(await upRow(page, UP_HOST).getByRole("button").count()).toBe(0);
      const mutating = calls.filter(
        (c) => c.method !== "GET" && !c.path.startsWith("/api/auth/"),
      );
      expect(mutating).toEqual([]);

      // Server-authoritative: every PAC / Upstream mutation is admin-only.
      const entry = await upFind(admin, (x) => x["host"] === UP_HOST);
      if (entry === null) throw new Error("fixture entry missing");
      const lc = await pacLifecycle(admin);
      const attempts = async (
        c: APIRequestContext,
        role: string,
      ): Promise<void> => {
        const tries = [
          c.post("/api/upstream/entries", {
            data: {
              scheme: "http",
              host: `denied-${role}-${SUFFIX}.invalid`,
              port: 3128,
              username: "",
              revision: num(before.upstream, "revision"),
            },
          }),
          c.put(`/api/upstream/entries/${entry.id}`, {
            data: {
              scheme: "http",
              host: `renamed-${role}-${SUFFIX}.invalid`,
              port: 3128,
              username: "",
              revision: entry.revision,
            },
          }),
          c.delete(
            `/api/upstream/entries/${entry.id}?revision=${String(entry.revision)}`,
          ),
          c.post(`/api/upstream/entries/${entry.id}/credential`, {
            data: {
              action: "replace",
              password: `denied-${role}`,
              revision: entry.revision,
            },
          }),
          c.post("/api/upstream/health"),
          c.post("/api/pac/profiles", {
            data: { id: `denied${role}${SUFFIX}`, name: "denied" },
          }),
          c.post(`/api/pac/profiles/${PROFILE_ID}/lifecycle`, {
            data: {
              action: "publish",
              operationId: crypto.randomUUID(),
              draft: lc["draft"],
              expectedActiveRevision: num(lc, "activeRevision"),
              collectionEtag: str(lc, "collectionEtag"),
              reason: `denied ${role}`,
            },
          }),
          c.delete(`/api/pac/profiles/${PROFILE_ID}?revision=1`),
          c.put(`/api/pac/posture/exceptions/${PROFILE_ID}`, {
            data: { owner: role, reason: "denied" },
          }),
        ];
        for (const t of tries) {
          const r = await t;
          expect(r.status(), `${role}: ${r.url()}`).toBe(403);
        }
      };
      await attempts(op, "operator");
      await attempts(viewer, "viewer");
      // Nothing changed on either surface.
      const afterUp = await upModel(admin);
      expect(afterUp["revision"]).toBe(before.upstream["revision"]);
      const still = await upFind(admin, (x) => x["host"] === UP_HOST);
      expect(still?.revision).toBe(entry.revision);
      expect(still?.credentialState).toBe("none");
      const afterPac = await pacListing(admin);
      expect(afterPac["collectionEtag"]).toBe(
        before.profiles["collectionEtag"],
      );
      expect(num(await pacLifecycle(admin), "activeRevision")).toBe(
        num(lc, "activeRevision"),
      );
    } finally {
      await upRemove(admin, UP_HOST);
      await cleanupPac(admin);
      await admin.dispose();
      await op.dispose();
      await viewer.dispose();
    }
  });
});

// ── N3: YAML read-only posture on the seeded appliance ──────────────────────

test.describe("N3 YAML read-only posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("the config.yaml entry is labelled read-only with no controls, survives a reload, and every mutation on it is refused yaml_owned", async ({
    page,
  }) => {
    const api = await newClient(YAML_URL, "198.51.100.133", USERS.admin);
    try {
      const yamlEntry = await upFind(api, (x) => x["source"] === "yaml");
      if (yamlEntry === null) throw new Error("no yaml-sourced entry seeded");
      expect(yamlEntry.id).toMatch(/^yaml-/);
      expect(yamlEntry.credentialState).toBe("none");

      const calls = trackApiRequests(page);
      await page.goto(`${YAML_URL}${UP_ROUTE}`);
      await login(page, USERS.admin.user, USERS.admin.pass);
      await expect(page.getByTestId("upstream-mode")).toBeVisible();
      const row = page.locator('tr[data-source="yaml"]');
      await expect(row).toHaveCount(1);
      await expect(row).toContainText("yaml-parent.invalid:3128");
      await expect(row).toContainText("config.yaml");
      await expect(row).toContainText("read-only");
      await expect(row).toContainText("edit the YAML and reload");
      expect(await row.getByRole("button").count()).toBe(0);
      await expect(page.getByText(/node-local/i).first()).toBeVisible();
      // The admin toolbar exists (managed entries stay creatable) — the
      // read-only posture is per row, not a downgraded page.
      await expect(
        page.getByRole("button", { name: "New entry" }),
      ).toBeVisible();

      await page.reload();
      await expect(page.getByTestId("upstream-mode")).toBeVisible();
      await expect(page.locator('tr[data-source="yaml"]')).toHaveCount(1);
      await expect(page.locator('tr[data-source="yaml"]')).toContainText(
        "read-only",
      );
      const mutating = calls.filter(
        (c) => c.method !== "GET" && !c.path.startsWith("/api/auth/"),
      );
      expect(mutating).toEqual([]);

      // On the wire the row is YAML-owned for every mutation shape.
      const put = await api.put(`/api/upstream/entries/${yamlEntry.id}`, {
        data: {
          scheme: "http",
          host: "renamed.invalid",
          port: 3128,
          username: "",
          revision: yamlEntry.revision,
        },
      });
      expect(put.status()).toBe(409);
      expect(await refusalCode(put)).toBe("yaml_owned");
      const del = await api.delete(
        `/api/upstream/entries/${yamlEntry.id}?revision=${String(yamlEntry.revision)}`,
      );
      expect(del.status()).toBe(409);
      expect(await refusalCode(del)).toBe("yaml_owned");
      const cred = await api.post(
        `/api/upstream/entries/${yamlEntry.id}/credential`,
        {
          data: {
            action: "replace",
            password: "never-sealed",
            revision: yamlEntry.revision,
          },
        },
      );
      expect(cred.status()).toBe(409);
      expect(await refusalCode(cred)).toBe("yaml_owned");
      const again = await upFind(api, (x) => x["source"] === "yaml");
      expect(again?.id).toBe(yamlEntry.id);
      expect(again?.revision).toBe(yamlEntry.revision);
      expect(again?.credentialState).toBe("none");
    } finally {
      await api.dispose();
    }
  });
});

// ── N4: CDR recovery marker across reload / navigation / boundary ───────────

// N4 and N5 end in a real Sign out, which revokes the server session; they
// therefore authenticate explicitly instead of using the suite-wide admin
// storage state (whose cookie a sign-out would revoke for every later test).
test.describe("N4 CDR recovery marker across reload, navigation and the auth boundary", () => {
  test.use({ storageState: EMPTY_STATE });
  test("the marker survives a reload and SPA navigation, surfaces for its owner without the token, and the auth boundary clears it", async ({
    page,
  }) => {
    const api = await newClient(AUTH_URL, "198.51.100.134", USERS.admin);
    try {
      await page.goto(CDR_ROUTE);
      await login(page, USERS.admin.user, USERS.admin.pass);
      await page.getByRole("tab", { name: "Instances" }).click();
      await expect(page.getByText("Enroll a new instance")).toBeVisible();
      // The enrollment never leaves the browser: no receipt, no credential,
      // exactly the "answer lost" shape the marker exists for.
      await page.route("**/api/cdr/instances/enroll", async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        await route.abort("connectionreset");
      });
      await page.getByLabel("Instance name").fill(CDR_NAME);
      await page.getByLabel("Endpoint (host:port)").fill("127.0.0.1:19443");
      await page
        .getByLabel("Server certificate fingerprint (TOFU pin)")
        .fill("ab".repeat(32));
      await page.getByLabel("Enrollment token (single-use)").fill(CDR_TOKEN);
      await page.getByRole("button", { name: "Enroll instance…" }).click();
      await page
        .getByRole("button", { name: "Enroll instance", exact: true })
        .click();
      await expect(page.getByText("Enrollment outcome unknown")).toBeVisible();
      await page.unroute("**/api/cdr/instances/enroll");

      const raw = await sessionItem(page, CDR_MARKER);
      expect(raw).not.toBeNull();
      const marker: unknown = JSON.parse(raw ?? "{}");
      const opId = isRecord(marker) ? String(marker["operationId"]) : "";
      expect(opId).toMatch(/^[0-9a-f]{32}$/);
      expect(raw).toContain(CDR_NAME);
      expect(raw).toContain(USERS.admin.user); // ownership-bound
      expect(raw).not.toContain(CDR_TOKEN); // never the secret
      expect(await storageDump(page)).not.toContain(CDR_TOKEN);

      // Full reload: the app boots, the subject is unresolved until the
      // status read lands, then the owner's marker must still be there.
      await page.reload();
      await page.getByRole("tab", { name: "Instances" }).click();
      await expect(page.getByText("Resolve enrollment")).toBeVisible();
      await expect(page.getByText(CDR_NAME).first()).toBeVisible();
      await expect(page.getByText(opId).first()).toBeVisible();
      expect(await sessionItem(page, CDR_MARKER)).toBe(raw);
      expect(await page.content()).not.toContain(CDR_TOKEN);
      expect(await storageDump(page)).not.toContain(CDR_TOKEN);
      await expect(
        page.getByRole("button", { name: "Enroll instance…" }),
      ).toBeDisabled();

      // SPA navigation away and back keeps it too.
      await page.getByRole("link", { name: "PAC", exact: true }).click();
      await expect(
        page.getByRole("heading", { name: "PAC", exact: false }),
      ).toBeVisible();
      await page.getByRole("link", { name: "CDR Integration" }).click();
      await page.getByRole("tab", { name: "Instances" }).click();
      await expect(page.getByText("Resolve enrollment")).toBeVisible();
      expect(await sessionItem(page, CDR_MARKER)).toBe(raw);

      // The appliance never saw an enrollment.
      const names = await api.get("/api/cdr/instances");
      expect(await names.text()).not.toContain(CDR_NAME);

      // The auth boundary clears it.
      await page.getByRole("button", { name: "Sign out" }).click();
      await expect(
        page.getByRole("heading", { name: "Sign in" }),
      ).toBeVisible();
      await expectStorageClean(page);
      expect(await page.content()).not.toContain(CDR_TOKEN);
    } finally {
      await api.dispose();
    }
  });
});

// ── N5: PAC marker at the auth boundary; Upstream persists nothing ──────────

test.describe("N5 PAC recovery marker at the auth boundary", () => {
  test.use({ storageState: EMPTY_STATE });
  test("a publish that never left the browser latches the marker; signing out clears it and the profile is untouched", async ({
    page,
  }) => {
    const api = await newClient(AUTH_URL, "198.51.100.135", USERS.admin);
    try {
      await seedPacFixture(api);
      const before = await pacLifecycle(api);
      await page.goto(PAC_ROUTE);
      await login(page, USERS.admin.user, USERS.admin.pass);
      await expect(
        page.getByRole("heading", { name: "PAC", exact: false }),
      ).toBeVisible();
      await openProfile(page);
      await page.route(
        `**/api/pac/profiles/${PROFILE_ID}/lifecycle`,
        async (route) => {
          if (route.request().method() !== "POST") {
            await route.continue();
            return;
          }
          await route.abort("connectionreset");
        },
      );
      await clickPublish(page);
      await expect(
        page.getByRole("button", { name: "Publish", exact: true }),
      ).toBeDisabled();
      const raw = await sessionItem(page, PAC_MARKER);
      expect(raw).not.toBeNull();
      await page.unroute(`**/api/pac/profiles/${PROFILE_ID}/lifecycle`);

      await page.getByRole("button", { name: "Sign out" }).click();
      await expect(
        page.getByRole("heading", { name: "Sign in" }),
      ).toBeVisible();
      await expectStorageClean(page);

      // Back in: nothing latched, nothing published (the appliance never
      // received the operation), the ceremony is open again.
      await login(page, USERS.admin.user, USERS.admin.pass);
      await expect(
        page.getByRole("heading", { name: "PAC", exact: false }),
      ).toBeVisible();
      await openProfile(page);
      expect(await sessionItem(page, PAC_MARKER)).toBeNull();
      await expect(
        page.getByRole("button", { name: "Publish", exact: true }),
      ).toBeEnabled();
      // The appliance never received the operation: nothing moved.
      const after = await pacLifecycle(api);
      expect(num(after, "activeRevision")).toBe(num(before, "activeRevision"));
      expect(num(after, "activeN")).toBe(num(before, "activeN"));
    } finally {
      await cleanupPac(api);
      await api.dispose();
    }
  });
});

// ── N6: PAC raw server error never reaches the DOM ──────────────────────────

test("N6 PAC: a raw server error body never reaches the DOM, URL or storage; the outcome stays unresolved", async ({
  page,
}) => {
  const api = await newClient(AUTH_URL, "198.51.100.136", USERS.admin);
  try {
    await seedPacFixture(api);
    const before = await pacLifecycle(api);
    await openProfile(page);
    await page.route(
      `**/api/pac/profiles/${PROFILE_ID}/lifecycle`,
      async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        await route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({
            error: `internal failure ${RAW_CANARY}`,
            detail: RAW_CANARY,
          }),
        });
      },
    );
    await clickPublish(page);
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    expect(await sessionItem(page, PAC_MARKER)).not.toBeNull();
    const content = await page.content();
    expect(content).not.toContain(RAW_CANARY);
    expect(content).not.toContain("/srv/never/render");
    expect(page.url()).not.toContain(RAW_CANARY);
    expect(await storageDump(page)).not.toContain(RAW_CANARY);
    await expect(
      page.getByText(/unresolved|unknown|not observed/i).first(),
    ).toBeVisible();
    expect(await page.getByText(/^Published/).count()).toBe(0);
    await page.unroute(`**/api/pac/profiles/${PROFILE_ID}/lifecycle`);
    // The appliance never received the operation: nothing moved.
    const after = await pacLifecycle(api);
    expect(num(after, "activeRevision")).toBe(num(before, "activeRevision"));
    expect(num(after, "activeN")).toBe(num(before, "activeN"));
  } finally {
    await cleanupPac(api);
    await api.dispose();
  }
});

// ── N7: node-local labels after reload and Refresh ──────────────────────────

test("N7 node-local labels on PAC lifecycle, PAC exceptions and Upstream health stay after reload and Refresh; Upstream persists nothing", async ({
  page,
}) => {
  const api = await newClient(AUTH_URL, "198.51.100.137", USERS.admin);
  try {
    await seedPacFixture(api);
    await openProfile(page);
    await expect(page.getByText("Publish history (node-local)")).toBeVisible();
    await page.reload();
    await page.getByRole("tab", { name: "Profiles" }).click();
    await page
      .getByRole("row", { name: new RegExp(PROFILE_NAME) })
      .getByRole("button", { name: "Open" })
      .click();
    await expect(page.getByText("Publish history (node-local)")).toBeVisible();
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await expect(page.getByText("Publish history (node-local)")).toBeVisible();

    await page.getByRole("tab", { name: "DIRECT Exceptions" }).click();
    await expect(page.getByText(/Node-local governance records/)).toBeVisible();
    await page.reload();
    await page.getByRole("tab", { name: "DIRECT Exceptions" }).click();
    await expect(page.getByText(/Node-local governance records/)).toBeVisible();

    await upCreate(api, UP_HOST);
    await page.goto(UP_ROUTE);
    await expect(upRow(page, UP_HOST)).toBeVisible();
    await expect(page.getByText(/node-local/i).first()).toBeVisible();
    await page.getByRole("button", { name: "Probe now" }).click();
    await expect(
      page.getByText("Manual probe complete (node-local)"),
    ).toBeVisible();
    await expect(upRow(page, UP_HOST)).toContainText("manual");
    await page.reload();
    await expect(upRow(page, UP_HOST)).toBeVisible();
    await expect(upRow(page, UP_HOST)).toContainText("manual");
    await expect(page.getByText(/node-local/i).first()).toBeVisible();
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await expect(upRow(page, UP_HOST)).toContainText("manual");
    // The read model is the only truth: nothing of Upstream is persisted
    // in the browser.
    expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
    expect(await storageDump(page)).not.toContain("upstream");
  } finally {
    await upRemove(api, UP_HOST);
    await cleanupPac(api);
    await api.dispose();
  }
});
