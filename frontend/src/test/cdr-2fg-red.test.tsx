// 2F-G closure RED — the CDR enrollment recovery marker versus an UNRESOLVED
// authenticated subject. Written against the frozen 2F-F baseline 77acdd67
// (the defect recorded in the 2F-E correction record: the 2E-C marker reads
// with a possibly-empty subject on first render).
//
//   G1  readEnrollRecovery("") — an unresolved subject is NOT a foreign
//       identity: the stored marker must survive the read and the read must
//       report the unresolved state, never "none" and never "valid".
//   G2  A tab whose first render happens BEFORE the authenticated subject is
//       known must keep the marker; once the subject resolves to the OWNER,
//       the recovery surface appears with the same operation.
//   G3  (control, preserved) once the subject resolves to a DIFFERENT
//       identity the marker is discarded and never surfaced.
//   G4  While the subject is unresolved nothing may be dispatched: the enroll
//       ceremony stays disabled even with a complete form and NO POST is
//       sent; it opens once the subject resolves.
//   G5  A real logout through the auth machine clears a marker the resolved
//       owner had surfaced (the clear itself is 2E-C behaviour; on the
//       baseline the marker is already gone before logout can clear it).
//   G6  (control, preserved) the unresolved render triggers no recovery
//       call and claims no outcome.
//
// Baseline expectation: G1, G2, G4 and G5 fail (the first read with ""
// deletes the marker as foreign and the ceremony is armed against an unknown
// identity); G3 and G6 pass and pin behaviour that must not regress.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CDRInstancesTab } from "../features/security/CDRInstancesTab";
import { readEnrollRecovery } from "../features/security/enrollRecovery";

const MARKER_KEY = "culvert.cdr.enroll-recovery.v1";
const OWNER = "admin-user";

function markerFor(subject: string, name = "sluice-pending"): string {
  return JSON.stringify({
    version: 1,
    operationId: "0123456789abcdef0123456789abcdef",
    name,
    endpoint: "10.0.0.9:8443",
    serverFingerprint: "ab".repeat(32),
    startedAt: 1,
    subject,
  });
}

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root | null;
let qc: QueryClient;
let posts: string[];

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = null;
  sessionStorage.clear();
  posts = [];
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
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        posts.push(`${method} ${url}`);
        return okJSON({ ok: true });
      }
      if (url.includes("/api/cdr/instances"))
        return okJSON({ instances: [], count: 0, version: 1 });
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  if (root !== null) {
    const r = root;
    act(() => {
      r.unmount();
    });
  }
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** An auth machine whose /api/auth/status answer is held until the test
 * releases it — the deterministic "subject not yet known" window. */
function deferredMachine(): {
  machine: AuthMachine;
  resolveAs: (user: string) => void;
} {
  let release: (user: string) => void = () => undefined;
  const status = new Promise<string>((r) => {
    release = r;
  });
  qc = new QueryClient();
  const machine = new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      status.then((user) => ({
        loggedIn: true,
        user,
        role: "admin" as const,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      })),
    postLogout: () => Promise.resolve({ ok: true as const }),
  });
  return { machine, resolveAs: release };
}

function mountTab(machine: AuthMachine): void {
  const router = createMemoryRouter(
    [{ path: "/security/cdr", element: <CDRInstancesTab isAdmin /> }],
    { initialEntries: ["/security/cdr"] },
  );
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

async function flush(): Promise<void> {
  await act(async () => {
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

async function flushUntil(cond: () => void): Promise<void> {
  await vi.waitFor(async () => {
    await flush();
    cond();
  });
}

function setInput(label: string, value: string): void {
  const lab = Array.from(container.querySelectorAll("label")).find((l) =>
    (l.textContent ?? "").includes(label),
  );
  if (lab === undefined) throw new Error(`label ${label} not found`);
  const input = container.querySelector(`#${lab.getAttribute("for") ?? ""}`);
  if (!(input instanceof HTMLInputElement)) throw new Error("input missing");
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function enrollButton(): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    (el.textContent ?? "").includes("Enroll instance…"),
  );
  if (b === undefined) throw new Error("enroll button not found");
  return b;
}

it("G1 an unresolved subject never classifies or deletes the stored marker", () => {
  sessionStorage.setItem(MARKER_KEY, markerFor(OWNER));
  const read = readEnrollRecovery("");
  expect(sessionStorage.getItem(MARKER_KEY)).toBe(markerFor(OWNER));
  expect(read.kind).toBe("unresolved");
  // Whitespace is not an identity either.
  expect(readEnrollRecovery("   ").kind).toBe("unresolved");
  expect(sessionStorage.getItem(MARKER_KEY)).toBe(markerFor(OWNER));
  // The owner still reads its own marker afterwards.
  expect(readEnrollRecovery(OWNER).kind).toBe("valid");
});

it("G2 a marker survives the unresolved first render and surfaces once the owner is authoritative", async () => {
  sessionStorage.setItem(MARKER_KEY, markerFor(OWNER));
  const { machine, resolveAs } = deferredMachine();
  void machine.boot();
  mountTab(machine);
  await flushUntil(() => {
    expect(container.textContent).toContain("Enroll a new instance");
  });
  // Unresolved: nothing classified, nothing deleted, nothing claimed.
  expect(sessionStorage.getItem(MARKER_KEY)).toBe(markerFor(OWNER));
  expect(container.textContent).not.toContain("Resolve enrollment");
  expect(container.textContent).not.toContain("recovery store unreadable");
  // The subject becomes authoritative and matches the marker's owner.
  resolveAs(OWNER);
  await flushUntil(() => {
    expect(container.textContent).toContain("Resolve enrollment");
  });
  expect(container.textContent).toContain("sluice-pending");
  expect(container.textContent).toContain("0123456789abcdef0123456789abcdef");
  expect(sessionStorage.getItem(MARKER_KEY)).toBe(markerFor(OWNER));
});

it("G3 (control) a confirmed mismatch clears the marker and never surfaces it", async () => {
  sessionStorage.setItem(MARKER_KEY, markerFor("someone-else", "foreign-op"));
  const { machine, resolveAs } = deferredMachine();
  void machine.boot();
  mountTab(machine);
  await flushUntil(() => {
    expect(container.textContent).toContain("Enroll a new instance");
  });
  resolveAs(OWNER);
  await flushUntil(() => {
    expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  });
  expect(container.textContent).not.toContain("foreign-op");
  expect(container.textContent).not.toContain("Resolve enrollment");
});

it("G4 nothing is dispatched while the subject is unresolved; the ceremony opens once it resolves", async () => {
  const { machine, resolveAs } = deferredMachine();
  void machine.boot();
  mountTab(machine);
  await flushUntil(() => {
    expect(container.textContent).toContain("Enroll a new instance");
  });
  setInput("Instance name", "sluice-g4");
  setInput("Endpoint (host:port)", "10.0.0.9:8443");
  setInput("Server certificate fingerprint (TOFU pin)", "ab".repeat(32));
  setInput("Enrollment token (single-use)", "one-time-token-SECRET-G4");
  await flush();
  expect(enrollButton().disabled).toBe(true);
  act(() => {
    enrollButton().click();
  });
  await flush();
  expect(posts).toEqual([]);
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  resolveAs(OWNER);
  await flushUntil(() => {
    expect(enrollButton().disabled).toBe(false);
  });
  expect(posts).toEqual([]);
});

it("G5 a real logout through the auth machine clears the marker the owner surfaced", async () => {
  sessionStorage.setItem(MARKER_KEY, markerFor(OWNER));
  const { machine, resolveAs } = deferredMachine();
  void machine.boot();
  mountTab(machine);
  resolveAs(OWNER);
  await flushUntil(() => {
    expect(container.textContent).toContain("Resolve enrollment");
  });
  await act(async () => {
    await machine.logout();
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
});

it("G6 (control) the unresolved render triggers no recovery call and claims no outcome", async () => {
  sessionStorage.setItem(MARKER_KEY, markerFor(OWNER));
  const { machine } = deferredMachine();
  void machine.boot();
  mountTab(machine);
  await flushUntil(() => {
    expect(container.textContent).toContain("Enroll a new instance");
  });
  await flush();
  expect(posts).toEqual([]);
  // The success notice reads "Enrolled <name>"; the registry card heading
  // "Enrolled instances" is not a claim.
  expect(container.textContent).not.toMatch(/Enrolled (?!instances)/);
  expect(container.textContent).not.toContain("Enrollment failed");
  expect(container.textContent).not.toContain("Enrollment outcome unknown");
});
