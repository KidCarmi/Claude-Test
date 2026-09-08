// PR-C15 RED matrix — the seventh Codex round on the Batch 2 PR head
// (6ec6e875), written against that tree BEFORE any correction.
//
//   K11 a manual probe run whose answer outruns the client deadline: the
//       appliance snapshots and probes the CURRENT entries sequentially
//       (5 s each), so the deadline the page sizes from its own — possibly
//       stale — entry count is not an upper bound. The page latched such a
//       completed run as unproven. The appliance now exposes whether a
//       manual run is in flight on the read model (`probe.manualInFlight`),
//       and the page resolves a timed-out probe against that truth: it
//       polls the read model until no run is in flight and at least one
//       eligible entry's health advanced, then reads the results back
//       instead of latching. Control: no run in flight AND no health
//       advanced (the request may never have reached the appliance) stays
//       unproven.

import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { decodeUpstreamConfig } from "../api/upstream";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { UpstreamPage } from "../features/network/upstream/UpstreamPage";

vi.mock("../api/upstream", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../api/upstream")>();
  return {
    ...mod,
    // The appliance is still probing when the client deadline fires: the
    // request is aborted into a timeout with no answer.
    runUpstreamProbe: vi.fn(() =>
      Promise.reject(new ApiError("timeout", "request timed out")),
    ),
  };
});

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
): { status: number; body: Record<string, unknown> } {
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

function withProbe(
  body: Record<string, unknown>,
  manualInFlight: boolean,
): Record<string, unknown> {
  return {
    ...body,
    probe: { configured: false, interval: "0s", manualInFlight },
  };
}

function probed(entry: ReturnType<typeof managed>) {
  return {
    ...entry,
    health: {
      status: "healthy",
      reason: "none",
      source: "manual",
      lastProbeAt: "2026-09-08T20:30:00Z",
    },
    probe: {
      status: "healthy",
      reason: "none",
      source: "manual",
      checkedAt: "2026-09-08T20:30:00Z",
    },
    healthy: true,
  };
}

async function mountPage(): Promise<void> {
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
}

describe("K11 the read model exposes the manual-probe state", () => {
  it("decodes probe.manualInFlight", () => {
    const entry = managed(
      "parent-a.example",
      "http://svc@parent-a.example:3128",
    );
    const cfg = decodeUpstreamConfig(
      withProbe(configWith(entry, 200).body, true),
      "$",
    );
    const probe: Record<string, unknown> = cfg.probe;
    expect(probe["manualInFlight"]).toBe(true);
  });
});

describe("K11 a probe whose answer outran the deadline is resolved against the appliance, not latched", () => {
  it("polls until no run is in flight and the health advanced, then reads the results back", async () => {
    const entry = managed(
      "parent-a.example",
      "http://svc@parent-a.example:3128",
    );
    const idle = withProbe(configWith(entry, 200).body, false);
    delete idle["entry"];
    const running = withProbe(configWith(entry, 200).body, true);
    delete running["entry"];
    const done = withProbe(configWith(probed(entry), 200).body, false);
    delete done["entry"];
    let gets = 0;
    let clicked = false;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const method = init?.method ?? "GET";
        if (method === "GET" && String(input) === "/api/upstream") {
          if (!clicked) return okJSON(idle);
          gets += 1;
          return okJSON(gets <= 2 ? running : done);
        }
        return okJSON(idle);
      }),
    );
    await mountPage();
    await flushUntil(() => {
      expect(container.textContent).toContain("parent-a.example");
      expect(button("New entry")?.disabled).toBe(false);
    });
    const probe = button("Probe now");
    if (probe === undefined) throw new Error("button not found: Probe now");
    clicked = true;
    act(() => {
      probe.click();
    });
    await vi.waitFor(
      async () => {
        await act(async () => {
          await new Promise((r) => {
            setTimeout(r, 50);
          });
        });
        expect(container.textContent).toMatch(/completed on the appliance/i);
      },
      { timeout: 15_000 },
    );
    expect(container.textContent).not.toMatch(
      /unproven|could not be verified/i,
    );
    expect(gets).toBeGreaterThanOrEqual(3);
    await flushUntil(() => {
      expect(button("New entry")?.disabled).toBe(false);
      expect(button("Probe now")?.disabled).toBe(false);
    });
  }, 20_000);

  it("control: no run in flight and no health advanced stays unproven", async () => {
    const entry = managed(
      "parent-a.example",
      "http://svc@parent-a.example:3128",
    );
    const idle = withProbe(configWith(entry, 200).body, false);
    delete idle["entry"];
    vi.stubGlobal(
      "fetch",
      vi.fn(() => okJSON(idle)),
    );
    await mountPage();
    await flushUntil(() => {
      expect(container.textContent).toContain("parent-a.example");
      expect(button("New entry")?.disabled).toBe(false);
    });
    const probe = button("Probe now");
    if (probe === undefined) throw new Error("button not found: Probe now");
    act(() => {
      probe.click();
    });
    await vi.waitFor(
      async () => {
        await act(async () => {
          await new Promise((r) => {
            setTimeout(r, 50);
          });
        });
        expect(container.textContent).toMatch(
          /unproven|could not be verified/i,
        );
      },
      { timeout: 15_000 },
    );
    expect(button("New entry")?.disabled).toBe(true);
  }, 20_000);
});
