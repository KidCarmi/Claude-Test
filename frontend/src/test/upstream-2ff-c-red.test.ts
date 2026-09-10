// 2F-F CORRECTION RED matrix (pure modules) — written against the rejected
// candidate d391b12f BEFORE any correction. Every import here EXISTS on that
// tree, so each case fails on its ASSERTION, not on module resolution.
//
// Blocker 2 — successful responses must be BOUND to the requested action:
//   B1  create: a 2xx whose `entry` is absent, names another entry, is not
//       managed, or carries a different authority than the submitted
//       (normalised) spec is NOT a proven create — the wrapper rejects.
//   B2  update: `entry.id` must equal the requested id and reflect the
//       submitted authority.
//   B3  T2 replace: the exact entry id with `credentialState: configured`
//       (DTO and the republished list row).
//   B4  T3 clear: the exact entry id with `credentialState: none`.
//   B5  delete: `deleted` must equal the requested id and the returned list
//       must no longer contain it.
//   B6  manual probe: `ok: true` and the counts-only `summary` are required.
//   B7  positive controls: correctly bound answers resolve.
//
// Adjacent refusal boundary — a refusal code is accepted ONLY with its
// contracted HTTP status and its required safe facts:
//   R1  status/code mismatch is never a known refusal.
//   R2  a fence without a numeric `current.revision` is not a fence.
//   R3  required facts (id, revision, retryAfterSeconds, confirmValue == id)
//       are validated; a malformed record is not an authoritative verdict.
//   R4  typed facts: an authority carrying a userinfo password is DROPPED
//       (never carried into a renderable fact); a safe authority is kept.
import { describe, expect, it, beforeEach, vi } from "vitest";
import { ApiError } from "../api/client";
import {
  asUpstreamFence,
  asUpstreamRefusal,
  clearUpstreamCredential,
  createUpstreamEntry,
  deleteUpstreamEntry,
  replaceUpstreamCredential,
  runUpstreamProbe,
  updateUpstreamEntry,
} from "../api/upstream";
import { isRecord } from "../api/decode";

const ID = "01HZZMANAGED0000000000001";
const OTHER = "01HZZOTHER00000000000002";
const MANAGED = {
  id: ID,
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
  health: { status: "healthy", reason: "none" },
  healthy: true,
  eligible: true,
  circuit: "closed",
  failures: 0,
};
const CONFIG = {
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
const DTO = {
  id: ID,
  scheme: "http",
  host: "parent-a.example",
  port: 3128,
  username: "svc",
  authority: MANAGED.authority,
  source: "managed",
  revision: 4,
  credentialState: "configured",
};

let answer: { status: number; body: unknown };
beforeEach(() => {
  answer = { status: 200, body: CONFIG };
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
});

async function rejectsUnproven(
  p: Promise<unknown>,
  status: number,
): Promise<void> {
  let caught: unknown;
  try {
    await p;
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(ApiError);
  if (caught instanceof ApiError) {
    expect(caught.kind).toBe("decode");
    expect(caught.status).toBe(status);
  }
}

const SPEC = {
  scheme: "http",
  host: "parent-a.example",
  port: 3128,
  username: "svc",
};

// ── B1 ──────────────────────────────────────────────────────────────────────
describe("B1 create is bound to the submitted authority", () => {
  it("a generic view without `entry` is unproven", async () => {
    answer = { status: 201, body: CONFIG };
    await rejectsUnproven(createUpstreamEntry(SPEC, 5), 201);
  });
  it("an `entry` naming another authority is unproven", async () => {
    answer = {
      status: 201,
      body: {
        ...CONFIG,
        entry: {
          ...DTO,
          id: OTHER,
          host: "parent-z.example",
          authority: "http://svc@parent-z.example:3128",
          credentialState: "none",
        },
      },
    };
    await rejectsUnproven(createUpstreamEntry(SPEC, 5), 201);
  });
  it("an `entry` that is not managed is unproven", async () => {
    answer = {
      status: 201,
      body: {
        ...CONFIG,
        entry: { ...DTO, source: "yaml", credentialState: "none" },
      },
    };
    await rejectsUnproven(createUpstreamEntry(SPEC, 5), 201);
  });
  it("an `entry` absent from the returned list is unproven", async () => {
    answer = {
      status: 201,
      body: {
        ...CONFIG,
        entries: [],
        proxies: [],
        entry: { ...DTO, credentialState: "none" },
      },
    };
    await rejectsUnproven(createUpstreamEntry(SPEC, 5), 201);
  });
});

// ── B2 ──────────────────────────────────────────────────────────────────────
describe("B2 update is bound to the requested id + authority", () => {
  it("a generic view without `entry` is unproven", async () => {
    answer = { status: 200, body: CONFIG };
    await rejectsUnproven(updateUpstreamEntry(ID, SPEC, 3), 200);
  });
  it("an `entry` with another id is unproven", async () => {
    answer = { status: 200, body: { ...CONFIG, entry: { ...DTO, id: OTHER } } };
    await rejectsUnproven(updateUpstreamEntry(ID, SPEC, 3), 200);
  });
  it("an `entry` that does not reflect the submitted port is unproven", async () => {
    answer = { status: 200, body: { ...CONFIG, entry: DTO } };
    await rejectsUnproven(
      updateUpstreamEntry(ID, { ...SPEC, port: 3129 }, 3),
      200,
    );
  });
});

// ── B3 / B4 ─────────────────────────────────────────────────────────────────
describe("B3/B4 credential ceremonies are bound to the exact id + state", () => {
  it("replace: an `entry` still reporting `none` is unproven", async () => {
    answer = {
      status: 200,
      body: { ...CONFIG, entry: { ...DTO, credentialState: "none" } },
    };
    await rejectsUnproven(replaceUpstreamCredential(ID, "pw", 3), 200);
  });
  it("replace: a generic view without `entry` is unproven", async () => {
    answer = { status: 200, body: CONFIG };
    await rejectsUnproven(replaceUpstreamCredential(ID, "pw", 3), 200);
  });
  it("replace: the republished list row must also read `configured`", async () => {
    answer = {
      status: 200,
      body: {
        ...CONFIG,
        entries: [{ ...MANAGED, credentialState: "none" }],
        proxies: [{ ...MANAGED, credentialState: "none" }],
        entry: DTO,
      },
    };
    await rejectsUnproven(replaceUpstreamCredential(ID, "pw", 3), 200);
  });
  it("clear: an `entry` still reporting `configured` is unproven", async () => {
    answer = { status: 200, body: { ...CONFIG, entry: DTO } };
    await rejectsUnproven(clearUpstreamCredential(ID, ID, 3), 200);
  });
  it("clear: an `entry` with another id is unproven", async () => {
    answer = {
      status: 200,
      body: {
        ...CONFIG,
        entries: [{ ...MANAGED, credentialState: "none" }],
        proxies: [{ ...MANAGED, credentialState: "none" }],
        entry: { ...DTO, id: OTHER, credentialState: "none" },
      },
    };
    await rejectsUnproven(clearUpstreamCredential(ID, ID, 3), 200);
  });
});

// ── B5 ──────────────────────────────────────────────────────────────────────
describe("B5 delete is bound to the requested id", () => {
  it("a generic view without `deleted` is unproven", async () => {
    answer = { status: 200, body: { ...CONFIG, entries: [], proxies: [] } };
    await rejectsUnproven(deleteUpstreamEntry(ID, 3), 200);
  });
  it("`deleted` naming another id is unproven", async () => {
    answer = {
      status: 200,
      body: { ...CONFIG, entries: [], proxies: [], deleted: OTHER },
    };
    await rejectsUnproven(deleteUpstreamEntry(ID, 3), 200);
  });
  it("a list that still carries the id is unproven", async () => {
    answer = { status: 200, body: { ...CONFIG, deleted: ID } };
    await rejectsUnproven(deleteUpstreamEntry(ID, 3), 200);
  });
});

// ── B6 ──────────────────────────────────────────────────────────────────────
describe("B6 manual probe needs the explicit result", () => {
  it("a generic view without `summary` is unproven", async () => {
    answer = { status: 200, body: CONFIG };
    await rejectsUnproven(runUpstreamProbe(), 200);
  });
  it("a summary without `ok: true` is unproven", async () => {
    answer = {
      status: 200,
      body: {
        ...CONFIG,
        summary: { probed: 1, healthy: 1, unhealthy: 0, skipped: 0 },
      },
    };
    await rejectsUnproven(runUpstreamProbe(), 200);
  });
});

// ── B7 controls ─────────────────────────────────────────────────────────────
describe("B7 correctly bound answers resolve", () => {
  it("create", async () => {
    answer = {
      status: 201,
      body: { ...CONFIG, entry: { ...DTO, credentialState: "none" } },
    };
    const c = await createUpstreamEntry(SPEC, 5);
    expect(c.entry?.id).toBe(ID);
  });
  it("create normalises host case, trailing dot and the default port", async () => {
    const dto = {
      ...DTO,
      port: 80,
      authority: "http://svc@parent-a.example:80",
      credentialState: "none",
    };
    answer = {
      status: 201,
      body: {
        ...CONFIG,
        entries: [{ ...MANAGED, port: 80 }],
        proxies: [],
        entry: dto,
      },
    };
    const c = await createUpstreamEntry(
      { scheme: "HTTP", host: "Parent-A.example.", port: 0, username: "svc" },
      5,
    );
    expect(c.entry?.authority).toBe("http://svc@parent-a.example:80");
  });
  it("update", async () => {
    answer = { status: 200, body: { ...CONFIG, entry: DTO } };
    expect((await updateUpstreamEntry(ID, SPEC, 3)).entry?.id).toBe(ID);
  });
  it("replace", async () => {
    answer = { status: 200, body: { ...CONFIG, entry: DTO } };
    expect(
      (await replaceUpstreamCredential(ID, "pw", 3)).entry?.credentialState,
    ).toBe("configured");
  });
  it("clear", async () => {
    answer = {
      status: 200,
      body: {
        ...CONFIG,
        entries: [{ ...MANAGED, credentialState: "none" }],
        proxies: [],
        entry: { ...DTO, credentialState: "none" },
      },
    };
    expect(
      (await clearUpstreamCredential(ID, ID, 3)).entry?.credentialState,
    ).toBe("none");
  });
  it("delete", async () => {
    answer = {
      status: 200,
      body: { ...CONFIG, entries: [], proxies: [], deleted: ID },
    };
    expect((await deleteUpstreamEntry(ID, 3)).entries).toEqual([]);
  });
  it("probe", async () => {
    answer = {
      status: 200,
      body: {
        ...CONFIG,
        ok: true,
        summary: { probed: 1, healthy: 1, unhealthy: 0, skipped: 0 },
      },
    };
    expect((await runUpstreamProbe()).summary?.probed).toBe(1);
  });
});

// ── R1–R4 refusal boundary ──────────────────────────────────────────────────
function httpErr(status: number, body: unknown): ApiError {
  return new ApiError(
    "http",
    `HTTP ${String(status)}`,
    status,
    JSON.stringify(body),
  );
}

describe("R1 a refusal code is bound to its contracted status", () => {
  it.each([
    [
      400,
      "credential_bound",
      { id: ID, revision: 3, credentialState: "configured" },
    ],
    [409, "precondition_required", { revision: 5 }],
    [428, "stale", { revision: 6 }],
    [409, "vanished", { id: ID }],
    [500, "duplicate_authority", { count: 1 }],
    [409, "probe_rate_limited", { retryAfterSeconds: 7 }],
    [429, "persist_failed", {}],
    [200, "stale", { revision: 6 }],
  ])("%d %s is NOT a known refusal", (status, code, current) => {
    expect(
      asUpstreamRefusal(httpErr(status, { error: "x", code, current })),
    ).toBeNull();
    expect(
      asUpstreamFence(httpErr(status, { error: "x", code, current })),
    ).toBeNull();
  });
});

describe("R2 a fence needs a numeric current.revision", () => {
  it.each([
    [409, "stale", {}],
    [409, "stale", { revision: "6" }],
    [409, "stale", { blob: { nested: "LEAKED" } }],
    [428, "precondition_required", { revision: null }],
    [428, "precondition_required", "not-a-record"],
  ])(
    "%d %s with %j is not a fence and not a verdict",
    (status, code, current) => {
      const err = httpErr(status, { error: "x", code, current });
      expect(asUpstreamFence(err)).toBeNull();
      expect(asUpstreamRefusal(err)).toBeNull();
    },
  );
});

describe("R3 required facts are validated", () => {
  it("vanished needs an id", () => {
    expect(
      asUpstreamRefusal(
        httpErr(404, { error: "x", code: "vanished", current: {} }),
      ),
    ).toBeNull();
  });
  it("credential_bound needs id + revision + a credential-state enum", () => {
    expect(
      asUpstreamRefusal(
        httpErr(409, {
          error: "x",
          code: "credential_bound",
          current: { id: ID },
        }),
      ),
    ).toBeNull();
    expect(
      asUpstreamRefusal(
        httpErr(409, {
          error: "x",
          code: "credential_bound",
          current: { id: ID, revision: 3, credentialState: "sealed" },
        }),
      ),
    ).toBeNull();
  });
  it("probe refusals need a numeric retryAfterSeconds", () => {
    expect(
      asUpstreamRefusal(
        httpErr(429, {
          error: "x",
          code: "probe_rate_limited",
          current: { retryAfterSeconds: "7" },
        }),
      ),
    ).toBeNull();
  });
  it("confirm_required needs confirmValue equal to the id", () => {
    expect(
      asUpstreamRefusal(
        httpErr(409, {
          error: "x",
          code: "confirm_required",
          current: {
            id: ID,
            revision: 3,
            confirmField: "confirm",
            confirmValue: OTHER,
          },
        }),
      ),
    ).toBeNull();
  });
  it("an id that is not a safe token is refused", () => {
    expect(
      asUpstreamRefusal(
        httpErr(404, {
          error: "x",
          code: "vanished",
          current: { id: "<img src=x>" },
        }),
      ),
    ).toBeNull();
  });
});

describe("R4 typed facts never carry credential material", () => {
  it("an authority with a userinfo password is dropped from the typed facts", () => {
    const r = asUpstreamRefusal(
      httpErr(409, {
        error: "x",
        code: "credential_bound",
        current: {
          id: ID,
          revision: 3,
          authority: "http://svc:Canary-PW-2ffc@parent-a.example:3128",
          credentialState: "configured",
        },
      }),
    );
    expect(r).not.toBeNull();
    const facts: unknown = isRecord(r) ? r["facts"] : undefined;
    expect(isRecord(facts)).toBe(true);
    expect(isRecord(facts) ? facts["authority"] : "leaked").toBeUndefined();
    expect(isRecord(facts) ? facts["id"] : "").toBe(ID);
    expect(isRecord(facts) ? facts["revision"] : 0).toBe(3);
    expect(isRecord(facts) ? facts["credentialState"] : "").toBe("configured");
  });
  it("a safe authority is kept", () => {
    const r = asUpstreamRefusal(
      httpErr(409, {
        error: "x",
        code: "credential_bound",
        current: {
          id: ID,
          revision: 3,
          authority: MANAGED.authority,
          credentialState: "configured",
        },
      }),
    );
    const facts: unknown = isRecord(r) ? r["facts"] : undefined;
    expect(isRecord(facts) ? facts["authority"] : "").toBe(MANAGED.authority);
  });
});
