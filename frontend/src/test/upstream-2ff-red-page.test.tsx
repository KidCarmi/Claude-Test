// 2F-F RED matrix (page) — written against the FROZEN 2F-E baseline
// (ba2d852b) BEFORE the Upstream surface exists; fails at import resolution
// there. Pins the browser-side guarantees of the 2F-F directive against
// the frozen 2F-C/2F-D backend semantics, rendered from STRUCTURED server
// facts (never prose, never frontend wording that compensates for the
// appliance):
//
//   P1  viewer mounts ZERO mutation controls and issues ZERO non-GET
//       requests; the surface says node-local; mode + coverage are shown.
//   P2  a YAML-owned entry renders READ-ONLY (no edit/delete/credential
//       control, labelled config.yaml) beside a managed entry that carries
//       the admin controls.
//   P3  create carries the DOCUMENT revision the page loaded; a 409 stale
//       renders the server's current revision and is NEVER auto-retried
//       (exactly one POST); a 428 precondition_required renders the same
//       way.
//   P4  editing the authority of a credentialed entry → 409 credential_bound
//       rendered as the server fact (clear first); deleting it → 409
//       credential_present; both exactly one request, DELETE token in the
//       query only.
//   P5  T2 replace: the password field is type=password, the password
//       travels in the body ONLY, and after the ceremony the password is in
//       neither the DOM, the request URL, nor web storage.
//   P6  T3 clear: the typed value must equal the exact entry id (wrong word
//       cannot confirm, zero requests); the body carries {action:"clear",
//       confirm, revision} and NO password key.
//   P7  manual probe: a 429 probe_rate_limited renders retryAfterSeconds
//       and is not retried (exactly one POST); a 200 renders the counts-only
//       summary.
//   P8  effective-mode truth: no_eligible_parent + requiresReplacement
//       render the critical banner (count, "requires replacement", no
//       "bypass" claim); direct_fallback says traffic is bypassing.
//   P9  a rejected stored document renders the degraded fact and the
//       structured 409 document_rejected on a mutation attempt.
//   P10 a mutation whose transport died latches the page UNKNOWN (controls
//       disabled) until a fresh successful refresh.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { UpstreamPage } from "../features/network/upstream/UpstreamPage";
import { isRecord } from "../api/decode";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

const MANAGED_ID = "01HZZMANAGED0000000000001";
const MANAGED = {
  id: MANAGED_ID,
  url: "http://parent-a.example:3128",
  authority: "http://svc@parent-a.example:3128",
  scheme: "http",
  host: "parent-a.example",
  port: 3128,
  username: "svc",
  source: "managed",
  revision: 3,
  credentialState: "configured",
  probe: { status: "healthy", reason: "none" },
  health: {
    status: "healthy",
    reason: "none",
    lastProbeAt: "2026-09-07T10:00:00Z",
    source: "periodic",
  },
  healthy: true,
  eligible: true,
  circuit: "closed",
  failures: 0,
};
const YAML = {
  id: "yaml-abcdefghijklmnop",
  url: "https://parent-y.example:443",
  authority: "https://parent-y.example:443",
  scheme: "https",
  host: "parent-y.example",
  port: 443,
  source: "yaml",
  revision: 1,
  credentialState: "none",
  probe: { status: "unprobed", reason: "none" },
  health: { status: "unprobed", reason: "none" },
  healthy: false,
  eligible: true,
  circuit: "closed",
  failures: 0,
};
function baseConfig(): Record<string, unknown> {
  return {
    enabled: true,
    mode: "chained",
    effective: {
      mode: "chained",
      entries: 2,
      eligible: 2,
      fallbackTotal: 0,
      since: "2026-09-07T09:00:00Z",
    },
    coverage: {
      plainHttp: "chained",
      connect: "direct",
      websocket: "direct",
      socks5: "direct",
      summary: "plain_http_only",
    },
    probe: { configured: true, interval: "30s" },
    revision: 5,
    entries: [MANAGED, YAML],
    proxies: [MANAGED, YAML],
    direct_fallback: { active: false, total: 0 },
    migration: { state: "none" },
    key: { state: "present", keyId: "k-1" },
    credentialsIneligible: 0,
    credentialsRequiringReplacement: 0,
    scope: "node-local",
  };
}

const CANARY = "Canary-Page-PW-2ff-7d1c";

let container: HTMLDivElement;
let root: Root;
let requested: string[];
let mutations: Array<{ method: string; url: string; body: unknown; raw: unknown }>;
let onMutate: (method: string, url: string, body: unknown) => Promise<Response>;
let config: Record<string, unknown>;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
  requested = [];
  mutations = [];
  sessionStorage.clear();
  localStorage.clear();
  config = baseConfig();
  onMutate = () => okJSON({ ...config, ok: true });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requested.push(`${method} ${url}`);
      if (method !== "GET") {
        const raw = init?.body;
        const body: unknown =
          typeof raw === "string" ? JSON.parse(raw) : undefined;
        mutations.push({ method, url, body, raw });
        return onMutate(method, url, body);
      }
      if (url === "/api/upstream") return okJSON(config);
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function machineFor(
  role: "viewer" | "operator" | "admin",
  qc: QueryClient,
): AuthMachine {
  return new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      Promise.resolve({
        loggedIn: true,
        user: `${role}-user`,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mountPage(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/network/upstream", element: <UpstreamPage /> }],
    { initialEntries: ["/network/upstream"] },
  );
  const qc = new QueryClient();
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("parent-a.example");
  });
}

async function flushUntil(cond: () => void): Promise<void> {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    cond();
  });
}

function buttons(): HTMLButtonElement[] {
  return Array.from(container.querySelectorAll("button"));
}

function buttonTexts(): string[] {
  return buttons().map((b) => b.textContent ?? "");
}

function clickButton(match: (t: string) => boolean): void {
  const b = buttons().find((el) => match(el.textContent ?? ""));
  if (b === undefined)
    throw new Error("button not found: " + buttonTexts().join("|"));
  act(() => {
    b.click();
  });
}

function inputByLabel(label: string): HTMLInputElement {
  const el = Array.from(container.querySelectorAll("input")).find((i) => {
    const l = i.labels?.[0]?.textContent ?? "";
    return l.includes(label);
  });
  if (el === undefined) throw new Error("input not found: " + label);
  return el;
}

function typeInto(label: string, value: string): void {
  const el = inputByLabel(label);
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function nonGets(): string[] {
  return requested.filter((r) => !r.startsWith("GET "));
}

function rows(): HTMLTableRowElement[] {
  return Array.from(
    container.querySelectorAll<HTMLTableRowElement>("tr[data-entry-id]"),
  );
}

function row(id: string): HTMLTableRowElement {
  const r = rows().find((x) => x.dataset["entryId"] === id);
  if (r === undefined) throw new Error("row not found: " + id);
  return r;
}

function alerts(): string {
  return Array.from(container.querySelectorAll('[role="alert"]'))
    .map((a) => a.textContent ?? "")
    .join("\n");
}

function storageDump(): string {
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
}

function refusal(status: number, code: string, current: unknown, extra = {}) {
  return okJSON(
    { error: `server refused: ${code}`, code, current, ...extra },
    status,
  );
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

// ── P1 ──────────────────────────────────────────────────────────────────────

it("P1 viewer: zero mutation controls, zero non-GET requests, node-local + mode + coverage shown", async () => {
  await mountPage("viewer");
  expect(container.textContent).toContain("node-local");
  expect(container.textContent).toContain("parent-y.example");
  const mode = container.querySelector('[data-testid="upstream-mode"]');
  expect(mode?.textContent ?? "").not.toBe("");
  expect(container.textContent).toMatch(/plain HTTP/);
  expect(container.textContent).toMatch(/CONNECT/);
  const found = buttonTexts().filter((t) =>
    MUTATION_WORDS.some((w) => t.includes(w)),
  );
  expect(found).toEqual([]);
  expect(nonGets()).toEqual([]);
});

// ── P2 ──────────────────────────────────────────────────────────────────────

it("P2 admin: a YAML-owned entry is read-only beside a managed entry with controls", async () => {
  await mountPage("admin");
  const y = row(YAML.id);
  expect(y.dataset["source"]).toBe("yaml");
  expect(y.querySelectorAll("button")).toHaveLength(0);
  expect(y.textContent).toContain("config.yaml");
  const m = row(MANAGED_ID);
  expect(m.dataset["source"]).toBe("managed");
  expect(m.dataset["credentialState"]).toBe("configured");
  const labels = Array.from(m.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
  expect(labels).toEqual(
    expect.arrayContaining([
      "Edit",
      "Delete entry",
      "Replace credential",
      "Clear credential",
    ]),
  );
  expect(buttonTexts()).toContain("New entry");
  expect(buttonTexts()).toContain("Probe now");
});

// ── P3 ──────────────────────────────────────────────────────────────────────

it("P3 admin: create carries the loaded document revision; 409 stale renders the server token and is never auto-retried", async () => {
  onMutate = () => refusal(409, "stale", { revision: 7 });
  await mountPage("admin");
  clickButton((t) => t === "New entry");
  typeInto("Host", "parent-c.example");
  clickButton((t) => t === "Create entry");
  await flushUntil(() => {
    expect(container.textContent).toContain("Stale write refused");
    expect(container.textContent).toContain("current revision 7");
  });
  expect(mutations).toHaveLength(1);
  expect(mutations[0]?.method).toBe("POST");
  expect(mutations[0]?.url).toBe("/api/upstream/entries");
  const body = mutations[0]?.body;
  expect(isRecord(body) && body["revision"]).toBe(5);
  expect(isRecord(body) && body["host"]).toBe("parent-c.example");
  expect(isRecord(body) && "credentialState" in body).toBe(false);
});

it("P3b admin: 428 precondition_required renders the server's current revision", async () => {
  onMutate = () => refusal(428, "precondition_required", { revision: 5 });
  await mountPage("admin");
  clickButton((t) => t === "New entry");
  typeInto("Host", "parent-c.example");
  clickButton((t) => t === "Create entry");
  await flushUntil(() => {
    expect(container.textContent).toContain("Precondition required");
    expect(container.textContent).toContain("current revision 5");
  });
  expect(mutations).toHaveLength(1);
});

// ── P4 ──────────────────────────────────────────────────────────────────────

it("P4a admin: editing a credentialed entry's authority renders 409 credential_bound as the server fact", async () => {
  onMutate = () =>
    refusal(409, "credential_bound", {
      id: MANAGED_ID,
      revision: 3,
      authority: MANAGED.authority,
      credentialState: "configured",
    });
  await mountPage("admin");
  clickButton((t) => t === "Edit");
  typeInto("Host", "parent-b.example");
  clickButton((t) => t === "Save entry");
  await flushUntil(() => {
    expect(container.textContent).toContain("credential_bound");
  });
  expect(mutations).toHaveLength(1);
  expect(mutations[0]?.method).toBe("PUT");
  expect(mutations[0]?.url).toBe(`/api/upstream/entries/${MANAGED_ID}`);
  const body = mutations[0]?.body;
  expect(isRecord(body) && body["revision"]).toBe(3);
  expect(isRecord(body) && body["host"]).toBe("parent-b.example");
});

it("P4b admin: deleting a credentialed entry renders 409 credential_present; the token travels in the query only", async () => {
  onMutate = () =>
    refusal(409, "credential_present", {
      id: MANAGED_ID,
      revision: 3,
      credentialState: "configured",
    });
  await mountPage("admin");
  clickButton((t) => t === "Delete entry");
  clickButton((t) => t === "Delete now");
  await flushUntil(() => {
    expect(container.textContent).toContain("credential_present");
  });
  expect(mutations).toHaveLength(1);
  expect(mutations[0]?.method).toBe("DELETE");
  expect(mutations[0]?.url).toBe(
    `/api/upstream/entries/${MANAGED_ID}?revision=3`,
  );
  expect(mutations[0]?.raw).toBeUndefined();
});

// ── P5 ──────────────────────────────────────────────────────────────────────

it("P5 admin: T2 replace — password field, body-only transport, no trace in DOM / URL / storage afterwards", async () => {
  await mountPage("admin");
  clickButton((t) => t === "Replace credential");
  const pw = inputByLabel("Password");
  expect(pw.type).toBe("password");
  typeInto("Password", CANARY);
  clickButton((t) => t === "Seal credential");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
    expect(container.textContent).toMatch(/credential (sealed|replaced)/i);
  });
  expect(mutations[0]?.method).toBe("POST");
  expect(mutations[0]?.url).toBe(
    `/api/upstream/entries/${MANAGED_ID}/credential`,
  );
  expect(mutations[0]?.url).not.toContain(CANARY);
  expect(mutations[0]?.body).toEqual({
    action: "replace",
    password: CANARY,
    revision: 3,
  });
  expect(container.innerHTML).not.toContain(CANARY);
  expect(
    Array.from(container.querySelectorAll("input")).map((i) => i.value),
  ).not.toContain(CANARY);
  expect(storageDump()).not.toContain(CANARY);
  for (const r of requested) expect(r).not.toContain(CANARY);
});

// ── P6 ──────────────────────────────────────────────────────────────────────

it("P6 admin: T3 clear needs the exact entry id typed; the body carries confirm and no password", async () => {
  await mountPage("admin");
  clickButton((t) => t === "Clear credential");
  const confirm = (): HTMLButtonElement | undefined =>
    buttons().find((b) => b.textContent === "Clear now");
  expect(confirm()?.disabled).toBe(true);
  typeInto("Type the entry id", "01HZZWRONG");
  expect(confirm()?.disabled).toBe(true);
  expect(mutations).toHaveLength(0);
  typeInto("Type the entry id", MANAGED_ID);
  expect(confirm()?.disabled).toBe(false);
  clickButton((t) => t === "Clear now");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]?.url).toBe(
    `/api/upstream/entries/${MANAGED_ID}/credential`,
  );
  expect(mutations[0]?.body).toEqual({
    action: "clear",
    confirm: MANAGED_ID,
    revision: 3,
  });
  expect(Object.keys(mutations[0]?.body as object)).not.toContain("password");
});

// ── P7 ──────────────────────────────────────────────────────────────────────

it("P7a admin: a rate-limited manual probe renders retryAfterSeconds and is not retried", async () => {
  onMutate = () =>
    refusal(429, "probe_rate_limited", {
      retryAfterSeconds: 7,
      scope: "node-local",
    });
  await mountPage("admin");
  clickButton((t) => t === "Probe now");
  await flushUntil(() => {
    expect(container.textContent).toContain("probe_rate_limited");
    expect(container.textContent).toMatch(/7\s*s/);
  });
  expect(mutations).toHaveLength(1);
  expect(mutations[0]?.url).toBe("/api/upstream/health");
  expect(mutations[0]?.raw).toBeUndefined();
});

it("P7b admin: a completed manual probe renders the counts-only summary", async () => {
  onMutate = () =>
    okJSON({
      ...config,
      ok: true,
      summary: { probed: 2, healthy: 1, unhealthy: 1, skipped: 0 },
    });
  await mountPage("admin");
  clickButton((t) => t === "Probe now");
  await flushUntil(() => {
    expect(container.textContent).toMatch(/probed 2/i);
    expect(container.textContent).toMatch(/unhealthy 1/i);
  });
  expect(mutations).toHaveLength(1);
});

// ── P8 ──────────────────────────────────────────────────────────────────────

it("P8a: no_eligible_parent + requiresReplacement render the critical banner without a bypass claim", async () => {
  config = {
    ...baseConfig(),
    mode: "no_eligible_parent",
    effective: {
      mode: "no_eligible_parent",
      entries: 1,
      eligible: 0,
      fallbackTotal: 0,
      since: "2026-09-07T09:00:00Z",
    },
    entries: [
      {
        ...MANAGED,
        credentialState: "requiresReplacement",
        eligible: false,
        healthy: false,
        probe: { status: "unprobed", reason: "credential_ineligible" },
        health: { status: "unprobed", reason: "credential_ineligible" },
      },
    ],
    proxies: [],
    credentialsIneligible: 1,
    credentialsRequiringReplacement: 1,
  };
  await mountPage("admin");
  const a = alerts();
  expect(a).toMatch(/requires? replacement/i);
  expect(a).toMatch(/no eligible parent/i);
  expect(a).not.toMatch(/bypass/i);
  expect(row(MANAGED_ID).dataset["credentialState"]).toBe("requiresReplacement");
  expect(row(MANAGED_ID).textContent).toMatch(/replacement/i);
});

it("P8b: direct_fallback says traffic is bypassing the chain", async () => {
  config = {
    ...baseConfig(),
    mode: "direct_fallback",
    effective: {
      mode: "direct_fallback",
      entries: 2,
      eligible: 0,
      fallbackTotal: 12,
      since: "2026-09-07T09:00:00Z",
    },
    direct_fallback: { active: true, total: 12 },
  };
  await mountPage("viewer");
  expect(alerts()).toMatch(/bypass/i);
  expect(alerts()).toContain("12");
});

// ── P9 ──────────────────────────────────────────────────────────────────────

it("P9 admin: a rejected stored document renders the degraded fact and the 409 document_rejected", async () => {
  config = {
    ...baseConfig(),
    degraded: { reason: "duplicate_authority", count: 2 },
  };
  onMutate = () =>
    refusal(409, "document_rejected", {
      degraded: { reason: "duplicate_authority", count: 2 },
    });
  await mountPage("admin");
  expect(alerts()).toContain("duplicate_authority");
  clickButton((t) => t === "New entry");
  typeInto("Host", "parent-c.example");
  clickButton((t) => t === "Create entry");
  await flushUntil(() => {
    expect(container.textContent).toContain("document_rejected");
  });
  expect(mutations).toHaveLength(1);
});

// ── P10 ─────────────────────────────────────────────────────────────────────

it("P10 admin: a mutation whose transport died latches the page UNKNOWN and disables further mutations", async () => {
  onMutate = () => Promise.reject(new TypeError("Failed to fetch"));
  await mountPage("admin");
  clickButton((t) => t === "New entry");
  typeInto("Host", "parent-c.example");
  clickButton((t) => t === "Create entry");
  await flushUntil(() => {
    expect(container.textContent).toContain("Last change unconfirmed");
  });
  expect(mutations).toHaveLength(1);
  const edit = buttons().find((b) => b.textContent === "Edit");
  expect(edit?.disabled).toBe(true);
  const probe = buttons().find((b) => b.textContent === "Probe now");
  expect(probe?.disabled).toBe(true);
});
