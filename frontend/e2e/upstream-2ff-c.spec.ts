// 2F-F CORRECTION real-binary journeys — the unproven-response recovery flow
// and secret-bearing answers, against the actual CULVERT binary on the AUTH
// appliance. Written on the rejected candidate d391b12f before the
// correction: every journey fails there (the page reports a confirmed
// failure and stays mutable; a password inside a refusal reaches the DOM).
//
// The appliance's real answer is CORRUPTED IN FLIGHT by a Playwright route
// (the mutation itself lands durably on the real binary — exactly the
// shape the Content-Type defect produced before aff12f91):
//   K1  create with the 2xx's media type stripped → unproven: no success
//       notice, no "failed" verdict, the ceremony closes, the page latches
//       and re-reads; the landed row then appears; exactly one POST.
//   K2  T2 replace answered by a schema-valid GENERIC view (no `entry`) →
//       unproven; the canary never reaches any browser sink; after the
//       read-back the row reads `configured`.
//   K3  a refusal whose `error` + `current.authority` carry a password →
//       the DOM never contains it; a 400 echoing the T2 password → same.
//   K4  a status/code mismatch (409 precondition_required) → not a
//       "nothing changed" verdict; unproven flow, read-back resolves.
//
// Everything created is removed in finally blocks through the fenced API.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

const ROUTE = "/app/network/upstream";
const SUFFIX = Date.now().toString(36).slice(-6);
const HOST = `parent-2ffc-${SUFFIX}.test`;
const PORT = 3128;
const CANARY_PW = `Canary-Browser-PW-2ffc-${SUFFIX}`;

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

interface Entry {
  id: string;
  revision: number;
  credentialState: string;
}

async function findEntry(
  api: APIRequestContext,
  host: string,
): Promise<Entry | null> {
  const v: unknown = await (await api.get("/api/upstream")).json();
  if (!isRecord(v) || !Array.isArray(v["entries"])) return null;
  for (const e of v["entries"]) {
    if (isRecord(e) && e["host"] === host) {
      return {
        id: String(e["id"]),
        revision: Number(e["revision"]),
        credentialState: String(e["credentialState"]),
      };
    }
  }
  return null;
}

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

function trackApiRequests(page: Page): Array<{ method: string; path: string }> {
  const calls: Array<{ method: string; path: string }> = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/"))
      calls.push({ method: r.method(), path: u.pathname });
  });
  return calls;
}

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

const UNPROVEN = /unproven|could not be verified/i;
const LATCH = /Last change unconfirmed/;

async function expectNoVerdict(page: Page): Promise<void> {
  await expect(page.getByText(LATCH)).toBeVisible();
  await expect(page.getByText(UNPROVEN).first()).toBeVisible();
  await expect(page.getByText(/Action failed/)).toHaveCount(0);
  await expect(page.getByText(/Nothing was changed/)).toHaveCount(0);
  await expect(page.getByText(/Entry .* created/)).toHaveCount(0);
  await expect(page.getByText(/Credential sealed/)).toHaveCount(0);
  await expect(page.locator("dialog")).toHaveCount(0);
}

// ── K1 + K2 ────────────────────────────────────────────────────────────────
test("K1/K2 admin: a landed create with its media type stripped, then a T2 replace answered by a generic view, are UNPROVEN and recovered by read-back", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.130");
  await removeEntry(api, HOST);
  const bodies: Array<{ url: string; body: string }> = [];
  page.on("response", (r) => {
    const url = r.url();
    if (!url.startsWith(AUTH_URL)) return;
    void r
      .text()
      .then((t) => bodies.push({ url, body: t }))
      .catch(() => undefined);
  });
  const calls = trackApiRequests(page);
  try {
    // K1: strip the media type of the REAL 201 (the mutation lands).
    await page.route("**/api/upstream/entries", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      const resp = await route.fetch();
      const headers = { ...resp.headers() };
      delete headers["content-type"];
      return route.fulfill({
        status: resp.status(),
        headers: { ...headers, "content-type": "text/plain; charset=utf-8" },
        body: await resp.body(),
      });
    });
    await openSurface(page);
    await page.getByRole("button", { name: "New entry" }).click();
    await page.getByLabel("Host").fill(HOST);
    await page.getByLabel("Port").fill(String(PORT));
    await page.getByLabel("Username").fill("svc");
    await page.getByRole("button", { name: "Create entry" }).click();
    await expectNoVerdict(page);
    // the mutation landed on the appliance; the page's read-back shows it
    expect((await findEntry(api, HOST))?.credentialState).toBe("none");
    await expect(rowFor(page, HOST)).toBeVisible();
    await expect(page.getByText(LATCH)).toHaveCount(0);
    expect(
      calls.filter(
        (c) => c.method === "POST" && c.path === "/api/upstream/entries",
      ),
    ).toHaveLength(1);
    await page.unroute("**/api/upstream/entries");

    // K2: answer the REAL replace with a generic view (no `entry`).
    const id = (await findEntry(api, HOST))?.id ?? "";
    await page.route(
      `**/api/upstream/entries/${id}/credential`,
      async (route) => {
        const resp = await route.fetch();
        const view: unknown = await (await api.get("/api/upstream")).json();
        return route.fulfill({
          status: resp.status(),
          headers: { "content-type": "application/json" },
          body: JSON.stringify(view),
        });
      },
    );
    await rowFor(page, HOST)
      .getByRole("button", { name: "Replace credential" })
      .click();
    await page.getByLabel("Password").fill(CANARY_PW);
    await page.getByRole("button", { name: "Seal credential" }).click();
    await expectNoVerdict(page);
    expect((await findEntry(api, HOST))?.credentialState).toBe("configured");
    await expect(rowFor(page, HOST)).toHaveAttribute(
      "data-credential-state",
      "configured",
    );
    await expect(page.getByText(LATCH)).toHaveCount(0);
    expect(
      calls.filter(
        (c) => c.method === "POST" && c.path.endsWith("/credential"),
      ),
    ).toHaveLength(1);
    await page.unroute(`**/api/upstream/entries/${id}/credential`);

    await page.waitForLoadState("networkidle");
    const dom = await page.content();
    const storage = await storageDump(page);
    expect(dom).not.toContain(CANARY_PW);
    expect(storage).not.toContain(CANARY_PW);
    for (const b of bodies) expect(b.body).not.toContain(CANARY_PW);
  } finally {
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await removeEntry(api, HOST);
    await api.dispose();
  }
});

// ── K3 + K4 ────────────────────────────────────────────────────────────────
test("K3/K4 admin: secret-bearing refusals never reach the DOM; a status/code mismatch is not a verdict", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.131");
  await removeEntry(api, HOST);
  try {
    const created = await api.post("/api/upstream/entries", {
      data: {
        scheme: "http",
        host: HOST,
        port: PORT,
        username: "svc",
        revision: Number(
          (await (await api.get("/api/upstream")).json())["revision"],
        ),
      },
    });
    expect(created.status(), await created.text()).toBe(201);
    const id = (await findEntry(api, HOST))?.id ?? "";
    await openSurface(page);

    // K3a: a refusal carrying a password in error + current.authority
    await page.route(`**/api/upstream/entries/${id}`, (route) => {
      if (route.request().method() !== "PUT") return route.continue();
      return route.fulfill({
        status: 409,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          error: `authority http://svc:${CANARY_PW}@${HOST}:3128 is bound`,
          code: "credential_bound",
          current: {
            id,
            revision: 1,
            authority: `http://svc:${CANARY_PW}@${HOST}:3128`,
            credentialState: "configured",
          },
        }),
      });
    });
    await rowFor(page, HOST).getByRole("button", { name: "Edit" }).click();
    await page.getByLabel("Port").fill("3129");
    await page.getByRole("button", { name: "Save entry" }).click();
    await expect(page.getByText("credential_bound").first()).toBeVisible();
    expect(await page.content()).not.toContain(CANARY_PW);
    await page.unroute(`**/api/upstream/entries/${id}`);

    // K3b: a 400 echoing the submitted T2 password
    await page.route(`**/api/upstream/entries/${id}/credential`, (route) =>
      route.fulfill({
        status: 400,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          error: `password ${CANARY_PW} rejected`,
          code: "invalid_password",
          current: {},
        }),
      }),
    );
    await rowFor(page, HOST)
      .getByRole("button", { name: "Replace credential" })
      .click();
    await page.getByLabel("Password").fill(CANARY_PW);
    await page.getByRole("button", { name: "Seal credential" }).click();
    await expect(page.getByText("invalid_password").first()).toBeVisible();
    expect(await page.content()).not.toContain(CANARY_PW);
    expect(await storageDump(page)).not.toContain(CANARY_PW);
    await page.unroute(`**/api/upstream/entries/${id}/credential`);

    // K4: status/code mismatch on the (real) update
    await page.route(`**/api/upstream/entries/${id}`, (route) => {
      if (route.request().method() !== "PUT") return route.continue();
      return route.fulfill({
        status: 409,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          error: "precondition",
          code: "precondition_required",
          current: { revision: 1 },
        }),
      });
    });
    await rowFor(page, HOST).getByRole("button", { name: "Edit" }).click();
    await page.getByLabel("Port").fill("3129");
    await page.getByRole("button", { name: "Save entry" }).click();
    await expect(page.getByText(UNPROVEN).first()).toBeVisible();
    await expect(page.getByText(/Precondition required/)).toHaveCount(0);
    await expect(page.getByText(/Nothing was changed/)).toHaveCount(0);
    await page.unroute(`**/api/upstream/entries/${id}`);
    // the read-back (a real GET) resolves the latch
    await expect(page.getByText(LATCH)).toHaveCount(0);
    await expect(
      rowFor(page, HOST).getByRole("button", { name: "Edit" }),
    ).toBeEnabled();
  } finally {
    await page.unrouteAll({ behavior: "ignoreErrors" });
    await removeEntry(api, HOST);
    await api.dispose();
  }
});
