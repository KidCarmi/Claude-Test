// 2F-F RED matrix (pure modules) — written against the FROZEN 2F-E baseline
// (ba2d852b) BEFORE any Upstream frontend code exists. On that tree every
// test fails at import resolution (`src/api/upstream`,
// `src/features/network/upstream/*` do not exist). Each assertion pins a
// contract the React surface must honour verbatim — the frozen 2F-C/2F-D
// backend semantics (C4, C6, C7, C9, C11, C12) as the appliance actually
// answers them, never a frontend re-wording:
//
//   A1  the read model (GET /api/upstream) decodes with every 2F-C/2F-D field
//       and REJECTS an unknown mode / credentialState / health status /
//       reason / source / coverage / scope value (never silently maps).
//   A2  the fence (428 precondition_required / 409 stale) is decoded
//       structurally with the server-owned `current.revision` — never
//       parsed from prose.
//   A3  every bounded 2F-C refusal code (credential_bound, credential_present,
//       yaml_owned, duplicate_authority + count, document_rejected, vanished,
//       key_unusable, confirm_required + confirmValue, no_credential,
//       persist_failed, seal_failed, probe_in_flight / probe_rate_limited +
//       retryAfterSeconds) is decoded from the body; an UNKNOWN code is
//       never classified as a known one.
//   A4  request shapes: create carries the DOCUMENT revision and exactly
//       {scheme, host, port, username, revision}; update carries the ENTRY
//       revision; DELETE carries the token in the QUERY only (no body);
//       `replace` sends {action, password, revision} with the password in
//       the BODY only (never the URL); `clear` sends {action, confirm,
//       revision} and NO password key; the manual probe is a bodiless POST.
//       No request ever carries credentialState / credential_configured.
//   A5  the decoder is FAIL-CLOSED on credential material: an entry carrying
//       `password`, `credential`, `ciphertext` or a userinfo password in
//       `url`/`authority` is REFUSED (never rendered), so a misbehaving
//       server can never put a secret into the DOM.
//   A6  the manual-probe answer decodes its counts-only `summary`.
//   A7  effective-mode / credential-state / coverage presentation is derived
//       from the server enum ONLY: both `no_eligible_parent` and
//       `direct_fallback` are critical, only `direct_fallback` says traffic
//       is bypassing (C11); coverage is always "plain HTTP only" and no copy
//       ever says "protected" or "fully chained" (C7); `requiresReplacement`
//       is a distinct, ineligible state (C12).
import { describe, expect, it, beforeEach, vi } from "vitest";
import { DecodeError, isRecord } from "../api/decode";
import {
  UPSTREAM_CREDENTIAL_STATES,
  UPSTREAM_MODES,
  asUpstreamFence,
  asUpstreamRefusal,
  clearUpstreamCredential,
  createUpstreamEntry,
  decodeUpstreamConfig,
  decodeUpstreamEntry,
  deleteUpstreamEntry,
  replaceUpstreamCredential,
  runUpstreamProbe,
  updateUpstreamEntry,
} from "../api/upstream";
import {
  coverageLine,
  credentialFacts,
  healthFacts,
  modeFacts,
} from "../features/network/upstream/upstreamFacts";
import { ApiError } from "../api/client";

const MANAGED = {
  id: "01HZZMANAGED0000000000001",
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
const CONFIG = {
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

/** The appliance's action-bound 2xx shapes for the request-shape stub. */
function boundAnswer(
  url: string,
  method: string,
  body: unknown,
): { status: number; body: unknown } {
  const spec = isRecord(body) ? body : {};
  const scheme = typeof spec["scheme"] === "string" ? spec["scheme"] : "http";
  const host = typeof spec["host"] === "string" ? spec["host"] : MANAGED.host;
  const port =
    typeof spec["port"] === "number" && spec["port"] !== 0
      ? spec["port"]
      : scheme === "https"
        ? 443
        : 80;
  const username = typeof spec["username"] === "string" ? spec["username"] : "";
  const authority = `${scheme}://${username !== "" ? `${username}@` : ""}${host.toLowerCase()}:${String(port)}`;
  const dto = (id: string, credentialState: string) => ({
    id,
    scheme,
    host: host.toLowerCase(),
    port,
    username,
    authority,
    source: "managed",
    revision: 4,
    credentialState,
  });
  const row = (id: string, credentialState: string) => ({
    ...MANAGED,
    id,
    scheme,
    host: host.toLowerCase(),
    port,
    username,
    url: `${scheme}://${host.toLowerCase()}:${String(port)}`,
    authority,
    credentialState,
  });
  if (method === "POST" && url === "/api/upstream/entries") {
    const id = "01HZZCREATED000000000000X";
    return {
      status: 201,
      body: {
        ...CONFIG,
        ok: true,
        entry: dto(id, "none"),
        entries: [MANAGED, YAML, row(id, "none")],
      },
    };
  }
  if (method === "PUT") {
    return {
      status: 200,
      body: {
        ...CONFIG,
        ok: true,
        entry: dto(MANAGED.id, "configured"),
        entries: [row(MANAGED.id, "configured"), YAML],
      },
    };
  }
  if (method === "DELETE") {
    return {
      status: 200,
      body: { ...CONFIG, ok: true, deleted: MANAGED.id, entries: [YAML] },
    };
  }
  if (method === "POST" && url.endsWith("/credential")) {
    const state = spec["action"] === "clear" ? "none" : "configured";
    return {
      status: 200,
      body: {
        ...CONFIG,
        ok: true,
        entry: {
          ...dto(MANAGED.id, state),
          host: MANAGED.host,
          authority: MANAGED.authority,
        },
        entries: [{ ...MANAGED, credentialState: state }, YAML],
      },
    };
  }
  if (method === "POST" && url === "/api/upstream/health") {
    return {
      status: 200,
      body: {
        ...CONFIG,
        ok: true,
        summary: { probed: 1, healthy: 1, unhealthy: 0, skipped: 0 },
      },
    };
  }
  return { status: 200, body: CONFIG };
}

function httpErr(status: number, body: unknown): ApiError {
  return new ApiError(
    "http",
    `HTTP ${String(status)}`,
    status,
    JSON.stringify(body),
  );
}

// ── A1 ──────────────────────────────────────────────────────────────────────

describe("A1 read model decoder", () => {
  it("decodes the complete 2F-C/2F-D read model", () => {
    const c = decodeUpstreamConfig(CONFIG);
    expect(c.mode).toBe("chained");
    expect(c.effective.eligible).toBe(2);
    expect(c.coverage.summary).toBe("plain_http_only");
    expect(c.probe.interval).toBe("30s");
    expect(c.revision).toBe(5);
    expect(c.entries).toHaveLength(2);
    expect(c.entries[0]?.credentialState).toBe("configured");
    expect(c.entries[0]?.health.source).toBe("periodic");
    expect(c.entries[1]?.source).toBe("yaml");
    expect(c.entries[1]?.username).toBe("");
    expect(c.directFallback.active).toBe(false);
    expect(c.key.state).toBe("present");
    expect(c.migration.state).toBe("none");
    expect(c.degraded).toBeUndefined();
    expect(c.credentialsRequiringReplacement).toBe(0);
    expect(c.scope).toBe("node-local");
  });

  it("decodes the optional degraded / yamlDegraded / summary / entry fields", () => {
    const c = decodeUpstreamConfig({
      ...CONFIG,
      degraded: { reason: "duplicate_authority", count: 2 },
      yamlDegraded: { reason: "invalid_entry" },
      ok: true,
      summary: { probed: 2, healthy: 1, unhealthy: 1, skipped: 0 },
      entry: {
        id: MANAGED.id,
        scheme: "http",
        host: "parent-a.example",
        port: 3128,
        username: "svc",
        authority: MANAGED.authority,
        source: "managed",
        revision: 4,
        credentialState: "none",
      },
    });
    expect(c.degraded?.reason).toBe("duplicate_authority");
    expect(c.degraded?.count).toBe(2);
    expect(c.yamlDegraded?.reason).toBe("invalid_entry");
    expect(c.summary?.probed).toBe(2);
    expect(c.entry?.revision).toBe(4);
  });

  it("tolerates a null entries list (the wire shape of an empty pool)", () => {
    const c = decodeUpstreamConfig({
      ...CONFIG,
      mode: "no_pool",
      effective: {
        ...CONFIG.effective,
        mode: "no_pool",
        entries: 0,
        eligible: 0,
      },
      entries: null,
      proxies: null,
    });
    expect(c.entries).toEqual([]);
    expect(c.mode).toBe("no_pool");
  });

  it.each([
    ["mode", { ...CONFIG, mode: "protected" }],
    [
      "effective.mode",
      { ...CONFIG, effective: { ...CONFIG.effective, mode: "fully_chained" } },
    ],
    [
      "credentialState",
      { ...CONFIG, entries: [{ ...MANAGED, credentialState: "sealed" }] },
    ],
    [
      "health.status",
      {
        ...CONFIG,
        entries: [{ ...MANAGED, health: { status: "ok", reason: "none" } }],
      },
    ],
    [
      "health.reason",
      {
        ...CONFIG,
        entries: [
          {
            ...MANAGED,
            health: { status: "unhealthy", reason: "dial tcp: refused" },
          },
        ],
      },
    ],
    [
      "health.source",
      {
        ...CONFIG,
        entries: [
          { ...MANAGED, health: { ...MANAGED.health, source: "operator" } },
        ],
      },
    ],
    ["source", { ...CONFIG, entries: [{ ...MANAGED, source: "imported" }] }],
    ["scheme", { ...CONFIG, entries: [{ ...MANAGED, scheme: "socks5" }] }],
    ["circuit", { ...CONFIG, entries: [{ ...MANAGED, circuit: "tripped" }] }],
    [
      "coverage.summary",
      { ...CONFIG, coverage: { ...CONFIG.coverage, summary: "fully_chained" } },
    ],
    [
      "coverage.connect",
      { ...CONFIG, coverage: { ...CONFIG.coverage, connect: "chained" } },
    ],
    ["scope", { ...CONFIG, scope: "cluster" }],
    ["key.state", { ...CONFIG, key: { state: "rotated" } }],
    ["migration.state", { ...CONFIG, migration: { state: "pending" } }],
  ])("rejects an unknown %s value", (_label, body) => {
    expect(() => decodeUpstreamConfig(body)).toThrow(DecodeError);
  });

  it("the enum vocabularies are exactly the frozen 2F-C/2F-D sets", () => {
    expect([...UPSTREAM_MODES]).toEqual([
      "no_pool",
      "chained",
      "no_eligible_parent",
      "direct_fallback",
    ]);
    expect([...UPSTREAM_CREDENTIAL_STATES]).toEqual([
      "none",
      "configured",
      "unusable",
      "mismatch",
      "requiresReplacement",
    ]);
  });
});

// ── A2 ──────────────────────────────────────────────────────────────────────

describe("A2 fence", () => {
  it("428 precondition_required carries the server's current revision", () => {
    const f = asUpstreamFence(
      httpErr(428, {
        error:
          "precondition required: echo the current revision you loaded (5)",
        code: "precondition_required",
        current: { revision: 5 },
      }),
    );
    expect(f?.status).toBe(428);
    expect(f?.code).toBe("precondition_required");
    expect(f?.current["revision"]).toBe(5);
  });

  it("409 stale carries the server's current revision + id", () => {
    const f = asUpstreamFence(
      httpErr(409, {
        error: "stale revision 3 (current 4)",
        code: "stale",
        current: { revision: 4, id: MANAGED.id },
      }),
    );
    expect(f?.status).toBe(409);
    expect(f?.code).toBe("stale");
    expect(f?.current["revision"]).toBe(4);
    expect(f?.current["id"]).toBe(MANAGED.id);
  });

  it("a 409 with another code is NOT a fence", () => {
    expect(
      asUpstreamFence(
        httpErr(409, { error: "x", code: "credential_bound", current: {} }),
      ),
    ).toBeNull();
    expect(asUpstreamFence(new ApiError("network", "died"))).toBeNull();
  });
});

// ── A3 ──────────────────────────────────────────────────────────────────────

describe("A3 bounded refusals", () => {
  it.each([
    [
      409,
      "credential_bound",
      {
        id: "x",
        revision: 3,
        authority: "http://svc@a:1",
        credentialState: "configured",
      },
    ],
    [
      409,
      "credential_present",
      { id: "x", revision: 3, credentialState: "unusable" },
    ],
    [409, "yaml_owned", { id: "yaml-x", source: "yaml" }],
    [
      409,
      "document_rejected",
      { degraded: { reason: "duplicate_authority", count: 2 } },
    ],
    [404, "vanished", { id: "x" }],
    [409, "key_unusable", { id: "x", revision: 3 }],
    [409, "no_credential", { id: "x", revision: 3 }],
    [500, "persist_failed", {}],
    [500, "seal_failed", {}],
    [429, "probe_in_flight", { retryAfterSeconds: 3, scope: "node-local" }],
    [429, "probe_rate_limited", { retryAfterSeconds: 7, scope: "node-local" }],
    [400, "invalid_entry", { index: 0, id: "" }],
    [400, "credential_state_not_accepted", {}],
    [400, "invalid_password", {}],
    [400, "invalid_action", {}],
    [400, "invalid_json", {}],
    [409, "credentialed_entries_present", {}],
    [428, "precondition_required", { revision: 5 }],
    [409, "stale", { revision: 6 }],
  ])("%d %s is decoded with its current facts", (status, code, current) => {
    const r = asUpstreamRefusal(
      httpErr(status, { error: `server said ${code}`, code, current }),
    );
    expect(r?.status).toBe(status);
    expect(r?.code).toBe(code);
    expect(r?.current).toEqual(current);
    expect(r?.message).toBe(`server said ${code}`);
  });

  it("duplicate_authority carries the count and nothing else about the entry", () => {
    const r = asUpstreamRefusal(
      httpErr(409, {
        error: "the effective pool would carry duplicate canonical authorities",
        code: "duplicate_authority",
        current: { count: 1 },
        count: 1,
      }),
    );
    expect(r?.code).toBe("duplicate_authority");
    expect(r?.count).toBe(1);
  });

  it("confirm_required carries the server-named confirm field + value", () => {
    const r = asUpstreamRefusal(
      httpErr(409, {
        error: "retype the exact entry id",
        code: "confirm_required",
        current: {
          id: MANAGED.id,
          revision: 3,
          confirmField: "confirm",
          confirmValue: MANAGED.id,
        },
      }),
    );
    expect(r?.current["confirmValue"]).toBe(MANAGED.id);
  });

  it("an unknown code, a text/plain body, or a transport death is never classified", () => {
    expect(
      asUpstreamRefusal(
        httpErr(409, { error: "x", code: "made_up", current: {} }),
      ),
    ).toBeNull();
    expect(
      asUpstreamRefusal(new ApiError("http", "forbidden", 403, "forbidden\n")),
    ).toBeNull();
    expect(asUpstreamRefusal(new ApiError("timeout", "timed out"))).toBeNull();
  });
});

// ── A4 ──────────────────────────────────────────────────────────────────────

describe("A4 request shapes", () => {
  let calls: Array<{
    url: string;
    method: string;
    body: unknown;
    rawBody: unknown;
  }>;
  beforeEach(() => {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: unknown, init?: RequestInit) => {
        const raw = init?.body;
        calls.push({
          url: String(input),
          method: init?.method ?? "GET",
          body: typeof raw === "string" ? JSON.parse(raw) : undefined,
          rawBody: raw,
        });
        // Fixture completion (2F-F correction, harness not assertion): the
        // client now binds every 2xx to the requested action, so the stub
        // answers with that action's evidence (the shapes the appliance
        // sends) instead of a generic view.
        const { status, body: answer } = boundAnswer(
          String(input),
          init?.method ?? "GET",
          typeof raw === "string" ? JSON.parse(raw) : undefined,
        );
        return Promise.resolve(
          new Response(JSON.stringify(answer), {
            status,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
  });

  it("create carries the DOCUMENT revision and exactly the spec keys", async () => {
    await createUpstreamEntry(
      { scheme: "http", host: "parent-c.example", port: 0, username: "" },
      5,
    );
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/upstream/entries");
    expect(calls[0]?.body).toEqual({
      scheme: "http",
      host: "parent-c.example",
      port: 0,
      username: "",
      revision: 5,
    });
  });

  it("update carries the ENTRY revision on PUT /entries/{id}", async () => {
    await updateUpstreamEntry(
      MANAGED.id,
      {
        scheme: "https",
        host: "parent-a.example",
        port: 3129,
        username: "svc",
      },
      3,
    );
    expect(calls[0]?.method).toBe("PUT");
    expect(calls[0]?.url).toBe(`/api/upstream/entries/${MANAGED.id}`);
    expect(calls[0]?.body).toEqual({
      scheme: "https",
      host: "parent-a.example",
      port: 3129,
      username: "svc",
      revision: 3,
    });
  });

  it("delete carries the token in the QUERY only, with no body", async () => {
    await deleteUpstreamEntry(MANAGED.id, 3);
    expect(calls[0]?.method).toBe("DELETE");
    expect(calls[0]?.url).toBe(
      `/api/upstream/entries/${MANAGED.id}?revision=3`,
    );
    expect(calls[0]?.rawBody).toBeUndefined();
  });

  it("replace (T2) sends the password in the BODY only, never the URL", async () => {
    await replaceUpstreamCredential(MANAGED.id, "Canary-PW-2ff", 3);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe(
      `/api/upstream/entries/${MANAGED.id}/credential`,
    );
    expect(calls[0]?.url).not.toContain("Canary");
    expect(calls[0]?.body).toEqual({
      action: "replace",
      password: "Canary-PW-2ff",
      revision: 3,
    });
  });

  it("clear (T3) sends the typed confirm and NO password key", async () => {
    await clearUpstreamCredential(MANAGED.id, MANAGED.id, 3);
    expect(calls[0]?.body).toEqual({
      action: "clear",
      confirm: MANAGED.id,
      revision: 3,
    });
    const clearBody = calls[0]?.body;
    expect(isRecord(clearBody) ? Object.keys(clearBody) : []).not.toContain(
      "password",
    );
  });

  it("the manual probe is a bodiless POST /api/upstream/health", async () => {
    await runUpstreamProbe();
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("/api/upstream/health");
    expect(calls[0]?.rawBody).toBeUndefined();
  });

  it("no mutation ever asserts the derived credential state", async () => {
    await createUpstreamEntry(
      { scheme: "http", host: "h.example", port: 8080, username: "u" },
      5,
    );
    await updateUpstreamEntry(
      MANAGED.id,
      { scheme: "http", host: "h.example", port: 8080, username: "u" },
      3,
    );
    await replaceUpstreamCredential(MANAGED.id, "pw", 3);
    await clearUpstreamCredential(MANAGED.id, MANAGED.id, 3);
    for (const c of calls) {
      const keys = isRecord(c.body) ? Object.keys(c.body) : [];
      expect(keys).not.toContain("credentialState");
      expect(keys).not.toContain("credential_configured");
      expect(keys).not.toContain("credential");
    }
  });
});

// ── A5 ──────────────────────────────────────────────────────────────────────

describe("A5 fail-closed on credential material", () => {
  it.each([
    ["password", { ...MANAGED, password: "leaked" }],
    ["credential", { ...MANAGED, credential: { ciphertext: "AAAA" } }],
    ["ciphertext", { ...MANAGED, ciphertext: "AAAA" }],
    [
      "url userinfo password",
      { ...MANAGED, url: "http://svc:leaked@parent-a.example:3128" },
    ],
    [
      "authority userinfo password",
      { ...MANAGED, authority: "http://svc:leaked@parent-a.example:3128" },
    ],
  ])("an entry carrying %s is refused, never rendered", (_label, entry) => {
    expect(() => decodeUpstreamEntry(entry)).toThrow(DecodeError);
    expect(() =>
      decodeUpstreamConfig({ ...CONFIG, entries: [entry], proxies: [entry] }),
    ).toThrow(DecodeError);
  });

  it("a username-only authority is the legitimate shape and decodes", () => {
    expect(decodeUpstreamEntry(MANAGED).authority).toBe(
      "http://svc@parent-a.example:3128",
    );
  });
});

// ── A6 ──────────────────────────────────────────────────────────────────────

describe("A6 manual probe answer", () => {
  it("decodes the counts-only summary", () => {
    const c = decodeUpstreamConfig({
      ...CONFIG,
      ok: true,
      summary: { probed: 1, healthy: 0, unhealthy: 1, skipped: 1 },
    });
    expect(c.summary).toEqual({
      probed: 1,
      healthy: 0,
      unhealthy: 1,
      skipped: 1,
    });
  });
});

// ── A7 ──────────────────────────────────────────────────────────────────────

const FORBIDDEN = [/protected/i, /fully chained/i];

describe("A7 presentation facts are enum-derived", () => {
  it("only direct_fallback says traffic is bypassing; both degraded modes are critical (C11)", () => {
    const df = modeFacts("direct_fallback");
    expect(df.severity).toBe("critical");
    expect(df.bypassing).toBe(true);
    expect(df.banner ?? "").toMatch(/bypass/i);
    const ne = modeFacts("no_eligible_parent");
    expect(ne.severity).toBe("critical");
    expect(ne.bypassing).toBe(false);
    expect(ne.banner ?? "").not.toMatch(/bypass/i);
    expect(ne.banner).not.toBeNull();
    expect(modeFacts("chained").banner).toBeNull();
    expect(modeFacts("chained").bypassing).toBe(false);
    expect(modeFacts("no_pool").banner).toBeNull();
    expect(modeFacts("no_pool").severity).toBe("neutral");
  });

  it("coverage always reads plain-HTTP-only and never claims protection (C7)", () => {
    const line = coverageLine({
      plainHttp: "chained",
      connect: "direct",
      websocket: "direct",
      socks5: "direct",
      summary: "plain_http_only",
    });
    expect(line).toMatch(/plain HTTP/);
    expect(line).toMatch(/CONNECT/);
    expect(line).toMatch(/SOCKS5/);
    for (const m of UPSTREAM_MODES) {
      const f = modeFacts(m);
      for (const re of FORBIDDEN) {
        expect(f.label).not.toMatch(re);
        expect(f.banner ?? "").not.toMatch(re);
      }
    }
    for (const re of FORBIDDEN) expect(line).not.toMatch(re);
  });

  it("credential states: requiresReplacement is distinct and ineligible (C12)", () => {
    expect(credentialFacts("requiresReplacement").eligible).toBe(false);
    expect(credentialFacts("requiresReplacement").label).toMatch(
      /replacement/i,
    );
    expect(credentialFacts("unusable").eligible).toBe(false);
    expect(credentialFacts("mismatch").eligible).toBe(false);
    expect(credentialFacts("configured").eligible).toBe(true);
    expect(credentialFacts("none").eligible).toBe(true);
    const labels = new Set(
      UPSTREAM_CREDENTIAL_STATES.map((s) => credentialFacts(s).label),
    );
    expect(labels.size).toBe(UPSTREAM_CREDENTIAL_STATES.length);
  });

  it("health renders the bounded reason enum only", () => {
    expect(healthFacts({ status: "unprobed", reason: "none" }).label).toMatch(
      /unprobed/i,
    );
    expect(healthFacts({ status: "healthy", reason: "none" }).severity).toBe(
      "ok",
    );
    const h = healthFacts({ status: "unhealthy", reason: "proxy_auth_failed" });
    expect(h.severity).toBe("critical");
    expect(h.label).toContain("proxy_auth_failed");
  });
});
