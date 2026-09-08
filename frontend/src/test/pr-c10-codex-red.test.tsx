// PR-C10 RED matrix — the second Codex round on the Batch 2 PR head
// (89c1ec2f), written against that tree BEFORE any correction. Every
// import exists there, so each case fails on its ASSERTION.
//
//   K4  IPv6 hosts: the appliance brackets a bare IPv6 literal and keeps
//       the literal AS TYPED (lower-cased, never compressed —
//       internal/upstream normalizeHost), so a create/update on
//       `2001:db8::1`, `2001:DB8::1`, `2001:0db8::1` or `[2001:0db8::1]`
//       is a genuine success the client must bind to; the client's
//       canonical host went through the URL parser, which throws on a bare
//       literal and COMPRESSES a bracketed one. Control: a different
//       literal stays unproven.
//   K5  a manual probe run and a mutation share one run owner
//       (`page.owner.begin()` aborts the predecessor), so every mutation
//       control must be disabled while a probe is in flight; otherwise a
//       confirmed mutation aborts the probe's request into an unproven
//       outcome while the appliance keeps probing.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { createUpstreamEntry, updateUpstreamEntry } from "../api/upstream";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { UpstreamPage } from "../features/network/upstream/UpstreamPage";

const ID = "01HZZMANAGED0000000000001";
function managed(host: string, authority: string) {
  return {
    id: ID,
    url: `http://${host}:3128`,
    authority,
    scheme: "http",
    host,
    port: 3128,
    username: "svc",
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
function configWith(
  entry: ReturnType<typeof managed>,
  status: number,
): { status: number; body: unknown } {
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
        host: entry.host,
        port: 3128,
        username: "svc",
        authority: entry.authority,
        source: "managed",
        revision: 3,
        credentialState: "none",
      },
    },
  };
}

// [submitted host, the host the appliance returns]
const IPV6: ReadonlyArray<[string, string]> = [
  ["2001:db8::1", "[2001:db8::1]"],
  ["2001:DB8::1", "[2001:db8::1]"],
  ["[2001:db8::1]", "[2001:db8::1]"],
  ["2001:0db8::1", "[2001:0db8::1]"],
  ["[2001:0db8::1]", "[2001:0db8::1]"],
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

describe("K4 a success on an IPv6 host is bound as the appliance normalizes it", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each(IPV6)("create with host %s resolves", async (typed, returned) => {
    stubAnswer(
      configWith(managed(returned, `http://svc@${returned}:3128`), 201),
    );
    const cfg = await createUpstreamEntry(
      { scheme: "http", host: typed, port: 3128, username: "svc" },
      5,
    );
    expect(cfg.entry?.host).toBe(returned);
  });
  it.each(IPV6)("update with host %s resolves", async (typed, returned) => {
    stubAnswer(
      configWith(managed(returned, `http://svc@${returned}:3128`), 200),
    );
    const cfg = await updateUpstreamEntry(
      ID,
      { scheme: "http", host: typed, port: 3128, username: "svc" },
      3,
    );
    expect(cfg.entry?.id).toBe(ID);
  });
  it("control: an answer naming another IPv6 literal stays unproven", async () => {
    stubAnswer(
      configWith(
        managed("[2001:db8::2]", "http://svc@[2001:db8::2]:3128"),
        201,
      ),
    );
    await rejectsUnproven(
      createUpstreamEntry(
        { scheme: "http", host: "2001:db8::1", port: 3128, username: "svc" },
        5,
      ),
    );
  });
});

// ── K5 ──────────────────────────────────────────────────────────────────────
function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root | undefined;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  if (root !== undefined) {
    const r = root;
    act(() => {
      r.unmount();
    });
    root = undefined;
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

function button(text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === text,
  );
}

describe("K5 mutations are blocked while a manual probe is in flight", () => {
  it("New entry / Edit / Delete entry stay disabled until the probe answers, then re-enable", async () => {
    const entry = managed(
      "parent-a.example",
      "http://svc@parent-a.example:3128",
    );
    const config = configWith(entry, 200).body as Record<string, unknown>;
    delete config["entry"];
    let releaseProbe: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      releaseProbe = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const method = init?.method ?? "GET";
        if (method === "POST" && String(input) === "/api/upstream/health") {
          // The appliance is still probing: the answer arrives only when
          // the test releases it.
          return gate.then(() =>
            okJSON({
              ...config,
              ok: true,
              summary: { probed: 1, healthy: 1, unhealthy: 0, skipped: 0 },
            }),
          );
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
      expect(container.textContent).toContain("parent-a.example");
      expect(button("New entry")?.disabled).toBe(false);
    });
    const probe = button("Probe now");
    if (probe === undefined) throw new Error("button not found: Probe now");
    act(() => {
      probe.click();
    });
    await flushUntil(() => {
      expect(button("Probe now")?.disabled).toBe(true);
    });
    // The probe is in flight: no mutation control may be live.
    expect(button("New entry")?.disabled).toBe(true);
    expect(button("Edit")?.disabled).toBe(true);
    expect(button("Delete entry")?.disabled).toBe(true);
    if (releaseProbe === undefined) throw new Error("probe gate not armed");
    releaseProbe();
    await flushUntil(() => {
      expect(container.textContent).toMatch(/probed 1/i);
    });
    await flushUntil(() => {
      expect(button("New entry")?.disabled).toBe(false);
      expect(button("Edit")?.disabled).toBe(false);
      expect(button("Delete entry")?.disabled).toBe(false);
    });
  });
});
