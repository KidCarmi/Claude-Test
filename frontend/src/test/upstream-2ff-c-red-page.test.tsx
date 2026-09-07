// 2F-F CORRECTION RED matrix (page) — written against the rejected candidate
// d391b12f BEFORE any correction. `UpstreamPage` exists there, so every case
// fails on its ASSERTION. Pins the frontend trust-lifecycle invariant the
// review found missing:
//
//   Q1  (5 actions × 3 shapes) a 2xx whose Content-Type is wrong, whose JSON
//       is malformed, or whose schema-valid body carries no action-specific
//       evidence is UNPROVEN: the ceremony closes (password released), no
//       success notice, no "failed"/"refused" verdict, the page latches
//       UNKNOWN, every mutation control + the manual probe is blocked, a
//       fresh authoritative GET is issued exactly once (never a retry of
//       the mutation), and the latch clears ONLY after a genuinely
//       successful read-back.
//   Q2  the manual probe: a 2xx without the explicit result is unproven.
//   Q3  secret-bearing bodies never reach the DOM: a refusal whose `error`
//       or `current.authority` carries a password, a 400 echoing the
//       submitted T2 password, a malformed 2xx carrying it, and a failed
//       initial GET whose text body carries it.
//   Q4  a malformed fence (no numeric revision) is never stringified into
//       the DOM and never rendered as "Nothing was changed".
//   Q5  a status/code mismatch (409 precondition_required) is not an
//       authoritative verdict — it enters the unproven flow.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { UpstreamPage } from "../features/network/upstream/UpstreamPage";

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
  health: { status: "healthy", reason: "none", source: "periodic" },
  healthy: true,
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
      entries: 1,
      eligible: 1,
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
    entries: [MANAGED],
    proxies: [MANAGED],
    direct_fallback: { active: false, total: 0 },
    migration: { state: "none" },
    key: { state: "present", keyId: "k-1" },
    credentialsIneligible: 0,
    credentialsRequiringReplacement: 0,
    scope: "node-local",
  };
}

const CANARY = "Canary-Page-PW-2ffc-91ab";

let container: HTMLDivElement;
let root: Root;
let requested: string[];
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string) => Promise<Response>;
let getMode: "ok" | "fail" | "failWithCanary";
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
  getMode = "ok";
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
        mutations.push({
          method,
          url,
          body: typeof raw === "string" ? JSON.parse(raw) : undefined,
        });
        return onMutate(method, url);
      }
      if (url !== "/api/upstream")
        return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
      if (getMode === "fail")
        return Promise.resolve(
          new Response("boom", {
            status: 500,
            headers: { "Content-Type": "text/plain" },
          }),
        );
      if (getMode === "failWithCanary")
        return Promise.resolve(
          new Response(`internal error: ${CANARY}`, {
            status: 500,
            headers: { "Content-Type": "text/plain" },
          }),
        );
      return okJSON(config);
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

function machineFor(qc: QueryClient): AuthMachine {
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
        user: "admin-user",
        role: "admin",
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mountPage(readyText = "parent-a.example"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/network/upstream", element: <UpstreamPage /> }],
    {
      initialEntries: ["/network/upstream"],
    },
  );
  const qc = new QueryClient();
  const machine = machineFor(qc);
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
    expect(container.textContent).toContain(readyText);
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
function button(text: string): HTMLButtonElement | undefined {
  return buttons().find((b) => b.textContent === text);
}
function clickButton(text: string): void {
  const b = button(text);
  if (b === undefined) throw new Error("button not found: " + text);
  act(() => {
    b.click();
  });
}
function typeInto(label: string, value: string): void {
  const el = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes(label),
  );
  if (el === undefined) throw new Error("input not found: " + label);
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
function gets(): number {
  return requested.filter((r) => r === "GET /api/upstream").length;
}

type Shape = "wrongType" | "malformedJSON" | "genericView";
function shaped(shape: Shape, status: number): Promise<Response> {
  switch (shape) {
    case "wrongType":
      return Promise.resolve(
        new Response(JSON.stringify({ ...config, ok: true, echo: CANARY }), {
          status,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        }),
      );
    case "malformedJSON":
      return Promise.resolve(
        new Response(`{"ok":true,"echo":"${CANARY}"`, {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    case "genericView":
      return okJSON({ ...config, ok: true, echo: CANARY }, status);
  }
}

type Action = "create" | "edit" | "delete" | "replace" | "clear";
function perform(action: Action): void {
  switch (action) {
    case "create":
      clickButton("New entry");
      typeInto("Host", "parent-c.example");
      clickButton("Create entry");
      return;
    case "edit":
      clickButton("Edit");
      typeInto("Port", "3129");
      clickButton("Save entry");
      return;
    case "delete":
      clickButton("Delete entry");
      clickButton("Delete now");
      return;
    case "replace":
      clickButton("Replace credential");
      typeInto("Password", CANARY);
      clickButton("Seal credential");
      return;
    case "clear":
      clickButton("Clear credential");
      typeInto("Type the entry id", MANAGED_ID);
      clickButton("Clear now");
      return;
  }
}
const STATUS: Record<Action, number> = {
  create: 201,
  edit: 200,
  delete: 200,
  replace: 200,
  clear: 200,
};
// The page's success notices (never the snapshot bar's "Updated HH:MM:SS"
// freshness stamp, which is not a verdict).
const SUCCESS_WORDS = [
  /Entry .* created/i,
  /Entry .* updated/i,
  /Entry .* deleted/i,
  /Credential sealed/i,
  /Credential cleared/i,
];
const VERDICT_WORDS = [/Action failed/i, /Refused/i, /Nothing was changed/i];

const MATRIX: Array<[Action, Shape]> = [];
for (const a of ["create", "edit", "delete", "replace", "clear"] as const)
  for (const s of ["wrongType", "malformedJSON", "genericView"] as const)
    MATRIX.push([a, s]);

// ── Q1 ──────────────────────────────────────────────────────────────────────
it.each(MATRIX)(
  "Q1 %s with a %s 2xx is unproven: ceremony closed, latched, read-back, no verdict",
  async (action, shape) => {
    onMutate = () => shaped(shape, STATUS[action]);
    await mountPage();
    const getsBefore = gets();
    getMode = "fail"; // the authoritative read-back fails first, so the latch must HOLD
    perform(action);
    await flushUntil(() => {
      expect(container.textContent).toContain("Last change unconfirmed");
    });
    expect(mutations).toHaveLength(1);
    // ceremony closed, password released
    expect(container.querySelector("dialog")).toBeNull();
    expect(
      Array.from(container.querySelectorAll("input")).map((i) => i.value),
    ).not.toContain(CANARY);
    // no verdict either way
    for (const re of SUCCESS_WORDS)
      expect(container.textContent ?? "").not.toMatch(re);
    for (const re of VERDICT_WORDS)
      expect(container.textContent ?? "").not.toMatch(re);
    expect(container.textContent).toMatch(/unproven|could not be verified/i);
    expect(container.innerHTML).not.toContain(CANARY);
    // exactly one fresh authoritative read was issued — never a retried mutation
    await flushUntil(() => {
      expect(gets()).toBe(getsBefore + 1);
    });
    expect(mutations).toHaveLength(1);
    // every mutation control + the probe stays blocked while the read-back has not succeeded
    expect(button("Edit")?.disabled).toBe(true);
    expect(button("New entry")?.disabled).toBe(true);
    expect(button("Probe now")?.disabled).toBe(true);
    expect(button("Replace credential")?.disabled).toBe(true);
    expect(button("Delete entry")?.disabled).toBe(true);
    // a genuinely successful read-back clears the latch
    getMode = "ok";
    clickButton("Refresh");
    await flushUntil(() => {
      expect(container.textContent).not.toContain("Last change unconfirmed");
      expect(button("Edit")?.disabled).toBe(false);
    });
    expect(mutations).toHaveLength(1);
  },
);

// ── Q2 ──────────────────────────────────────────────────────────────────────
it("Q2 a manual probe answered by a generic view (no explicit result) is unproven", async () => {
  onMutate = () => okJSON(config);
  await mountPage();
  getMode = "fail";
  clickButton("Probe now");
  await flushUntil(() => {
    expect(container.textContent).toContain("Last change unconfirmed");
  });
  expect(container.textContent ?? "").not.toMatch(/probed \d+/i);
  expect(container.textContent ?? "").not.toMatch(/Manual probe failed/i);
  expect(button("Probe now")?.disabled).toBe(true);
  expect(mutations).toHaveLength(1);
});

// ── Q3 ──────────────────────────────────────────────────────────────────────
it("Q3a a refusal whose error/authority carry a password never reaches the DOM", async () => {
  onMutate = () =>
    okJSON(
      {
        error: `authority http://svc:${CANARY}@parent-a.example:3128 is bound`,
        code: "credential_bound",
        current: {
          id: MANAGED_ID,
          revision: 3,
          authority: `http://svc:${CANARY}@parent-a.example:3128`,
          credentialState: "configured",
        },
      },
      409,
    );
  await mountPage();
  perform("edit");
  await flushUntil(() => {
    expect(container.textContent).toContain("credential_bound");
  });
  expect(container.innerHTML).not.toContain(CANARY);
  expect(container.innerHTML).not.toContain("svc:");
});

it("Q3b a 400 echoing the submitted T2 password never reaches the DOM", async () => {
  onMutate = () =>
    okJSON(
      {
        error: `password ${CANARY} rejected`,
        code: "invalid_password",
        current: {},
      },
      400,
    );
  await mountPage();
  perform("replace");
  await flushUntil(() => {
    expect(container.textContent).toContain("invalid_password");
  });
  expect(container.innerHTML).not.toContain(CANARY);
});

it("Q3c a 2xx malformed body carrying the password never reaches the DOM", async () => {
  onMutate = () =>
    Promise.resolve(
      new Response(`password=${CANARY}`, {
        status: 200,
        headers: { "Content-Type": "text/html" },
      }),
    );
  await mountPage();
  getMode = "fail"; // the read-back fails first, so the latch must HOLD
  perform("replace");
  await flushUntil(() => {
    expect(container.textContent).toContain("Last change unconfirmed");
  });
  expect(container.innerHTML).not.toContain(CANARY);
});

it("Q3d a failed initial GET whose body carries a secret never reaches the DOM", async () => {
  getMode = "failWithCanary";
  await mountPage("unavailable");
  expect(container.innerHTML).not.toContain(CANARY);
  expect(container.textContent).toContain("500");
});

// ── Q4 ──────────────────────────────────────────────────────────────────────
it("Q4 a malformed fence is never stringified and never a 'nothing changed' verdict", async () => {
  onMutate = () =>
    okJSON(
      {
        error: "stale",
        code: "stale",
        current: { blob: { nested: "LEAKED-BLOB" } },
      },
      409,
    );
  await mountPage();
  getMode = "fail";
  perform("edit");
  await flushUntil(() => {
    expect(container.textContent).toContain("Last change unconfirmed");
  });
  expect(container.innerHTML).not.toContain("LEAKED-BLOB");
  expect(container.innerHTML).not.toContain("blob");
  expect(container.textContent ?? "").not.toMatch(/Nothing was changed/);
  expect(container.textContent ?? "").not.toMatch(/Stale write refused/);
  expect(button("Edit")?.disabled).toBe(true);
});

// ── Q5 ──────────────────────────────────────────────────────────────────────
it("Q5 a status/code mismatch is not an authoritative verdict", async () => {
  onMutate = () =>
    okJSON(
      {
        error: "precondition",
        code: "precondition_required",
        current: { revision: 5 },
      },
      409,
    );
  await mountPage();
  getMode = "fail";
  perform("create");
  await flushUntil(() => {
    expect(container.textContent).toContain("Last change unconfirmed");
  });
  expect(container.textContent ?? "").not.toMatch(/Precondition required/);
  expect(container.textContent ?? "").not.toMatch(/Nothing was changed/);
  expect(mutations).toHaveLength(1);
  expect(button("New entry")?.disabled).toBe(true);
});
