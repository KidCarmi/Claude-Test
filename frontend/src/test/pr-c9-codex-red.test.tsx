// PR-C9 RED matrix — the three Codex findings on the Batch 2 PR head
// b07b0d82, written against that tree BEFORE any correction. Every import
// exists there, so each case fails on its ASSERTION.
//
//   K1  route intent: the three routes this program added last
//       (/policies/header-rewrite, /objects/url-categories,
//       /objects/file-profiles) are real router routes; a deep link or a
//       re-authentication on them must return the operator there, not to
//       Overview.
//   K2  authority binding: the appliance renders the canonical authority
//       with the username percent-escaped (url.PathEscape); a create or
//       update whose username carries a character Normalize accepts but
//       PathEscape escapes (`?`, `#`, `%`, non-ASCII) is a genuine success
//       the client must bind to — not an unproven outcome. Controls: a
//       different username, host or port stays unproven.
//   K3  manual-probe deadline: the appliance probes sequentially at 5 s per
//       eligible entry, so the request's client deadline must cover the
//       read model's entry count; the page must not abort a run the
//       appliance is still (legitimately) executing.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import * as client from "../api/client";
import { createUpstreamEntry, updateUpstreamEntry } from "../api/upstream";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { resolveRouteIntent } from "../auth/routeIntent";
import { UpstreamPage } from "../features/network/upstream/UpstreamPage";

vi.mock("../api/client", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../api/client")>();
  return { ...mod, apiRequest: vi.fn(mod.apiRequest) };
});

// ── K1 ──────────────────────────────────────────────────────────────────────
describe("K1 deep links on every route the program added are honored", () => {
  it.each([
    "/policies/header-rewrite",
    "/objects/url-categories",
    "/objects/file-profiles",
  ])("%s returns the viewer to the requested page", (path) => {
    expect(resolveRouteIntent(path, "viewer")).toBe(path);
    expect(resolveRouteIntent(path, "admin")).toBe(path);
  });
});

// ── K2 ──────────────────────────────────────────────────────────────────────
const ID = "01HZZMANAGED0000000000001";
function managed(username: string, authority: string) {
  return {
    id: ID,
    url: "http://parent-a.example:3128",
    authority,
    scheme: "http",
    host: "parent-a.example",
    port: 3128,
    username,
    source: "managed",
    revision: 3,
    credentialState: "none",
    probe: { status: "unprobed", reason: "none" },
    health: { status: "unprobed", reason: "none", source: "periodic" },
    healthy: false,
    eligible: true,
    circuit: "closed",
    failures: 0,
  };
}
function configWith(entry: ReturnType<typeof managed>, status: number) {
  return {
    status,
    body: {
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
      revision: 6,
      entries: [entry],
      proxies: [entry],
      direct_fallback: { active: false, total: 0 },
      migration: { state: "none" },
      key: { state: "present", keyId: "k-1" },
      credentialsIneligible: 0,
      credentialsRequiringReplacement: 0,
      scope: "node-local",
      entry: {
        id: ID,
        scheme: "http",
        host: "parent-a.example",
        port: 3128,
        username: entry.username,
        authority: entry.authority,
        source: "managed",
        revision: 3,
        credentialState: "none",
      },
    },
  };
}

// Exactly what Go's url.PathEscape produces for these usernames.
const ESCAPED: ReadonlyArray<[string, string]> = [
  ["a?b#c%d", "a%3Fb%23c%25d"],
  ["sérvice", "s%C3%A9rvice"],
  ["svc;x", "svc%3Bx"],
];

function stubAnswer(answer: { status: number; body: unknown }): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify(answer.body), {
          status: answer.status,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    ),
  );
}

async function rejectsUnproven(p: Promise<unknown>): Promise<void> {
  let caught: unknown;
  try {
    await p;
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(ApiError);
  if (caught instanceof ApiError) expect(caught.kind).toBe("decode");
}

describe("K2 a success whose username the appliance escaped is still bound", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each(ESCAPED)("create with username %s resolves", async (raw, esc) => {
    stubAnswer(
      configWith(managed(raw, `http://${esc}@parent-a.example:3128`), 201),
    );
    const spec = {
      scheme: "http",
      host: "parent-a.example",
      port: 3128,
      username: raw,
    };
    const cfg = await createUpstreamEntry(spec, 5);
    expect(cfg.entry?.username).toBe(raw);
  });
  it.each(ESCAPED)("update with username %s resolves", async (raw, esc) => {
    stubAnswer(
      configWith(managed(raw, `http://${esc}@parent-a.example:3128`), 200),
    );
    const spec = {
      scheme: "http",
      host: "parent-a.example",
      port: 3128,
      username: raw,
    };
    const cfg = await updateUpstreamEntry(ID, spec, 3);
    expect(cfg.entry?.id).toBe(ID);
  });
  it("control: an answer naming another username, host or port stays unproven", async () => {
    const spec = {
      scheme: "http",
      host: "parent-a.example",
      port: 3128,
      username: "a?b",
    };
    stubAnswer(
      configWith(managed("a?c", "http://a%3Fc@parent-a.example:3128"), 201),
    );
    await rejectsUnproven(createUpstreamEntry(spec, 5));
    stubAnswer(
      configWith(managed("a?b", "http://a%3Fb@parent-a.example:3129"), 200),
    );
    await rejectsUnproven(updateUpstreamEntry(ID, spec, 3));
  });
});

// ── K3 ──────────────────────────────────────────────────────────────────────
function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}
const ENTRIES = 8;
function pageConfig(): Record<string, unknown> {
  const entries = Array.from({ length: ENTRIES }, (_, i) => {
    const id = `01HZZMANAGED00000000000${String(i + 10)}`;
    const host = `parent-${String.fromCharCode(97 + i)}.example`;
    return {
      ...managed("svc", `http://svc@${host}:3128`),
      id,
      host,
      url: `http://${host}:3128`,
      credentialState: "configured",
    };
  });
  return {
    enabled: true,
    mode: "chained",
    effective: {
      mode: "chained",
      entries: ENTRIES,
      eligible: ENTRIES,
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
    entries,
    proxies: entries,
    direct_fallback: { active: false, total: 0 },
    migration: { state: "none" },
    key: { state: "present", keyId: "k-1" },
    credentialsIneligible: 0,
    credentialsRequiringReplacement: 0,
    scope: "node-local",
  };
}

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  if (root !== undefined) {
    act(() => {
      root.unmount();
    });
  }
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

describe("K3 the manual probe's deadline covers the read model", () => {
  it(`dispatches the probe with a deadline >= ${String(ENTRIES)} entries x 5 s`, async () => {
    const config = pageConfig();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const method = init?.method ?? "GET";
        if (method === "POST" && String(input) === "/api/upstream/health") {
          return okJSON({
            ...config,
            ok: true,
            summary: {
              probed: ENTRIES,
              healthy: ENTRIES,
              unhealthy: 0,
              skipped: 0,
            },
          });
        }
        return okJSON(config);
      }),
    );
    const router = createMemoryRouter(
      [{ path: "/network/upstream", element: <UpstreamPage /> }],
      { initialEntries: ["/network/upstream"] },
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
      expect(container.textContent).toContain("parent-h.example");
    });
    const probe = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent === "Probe now",
    );
    if (probe === undefined) throw new Error("button not found: Probe now");
    act(() => {
      probe.click();
    });
    await flushUntil(() => {
      expect(container.textContent).toMatch(/probed 8/i);
    });
    const call = vi
      .mocked(client.apiRequest)
      .mock.calls.find((c) => c[0] === "/api/upstream/health");
    expect(call).toBeDefined();
    const timeoutMs = call?.[2]?.timeoutMs;
    expect(typeof timeoutMs).toBe("number");
    expect(timeoutMs ?? 0).toBeGreaterThanOrEqual(ENTRIES * 5_000 + 5_000);
  });
});
