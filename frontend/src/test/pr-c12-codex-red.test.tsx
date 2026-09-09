// PR-C12 RED matrix — the fourth Codex round on the Batch 2 PR head
// (7621f8fc), written against that tree BEFORE any correction. Every
// import exists there, so each case fails on its ASSERTION.
//
//   K7  the appliance lower-cases with Go's SIMPLE case mapping
//       (strings.ToLower: U+0130 `İ` → `i`, `Σ` → `σ` always) and strips
//       exactly ONE trailing dot before the IDNA mapping
//       (internal/upstream normalizeHost), so `İ.example` is stored and
//       returned as `i.example` and `example.com..` as `example.com.`;
//       the client used JavaScript's FULL case mapping (`İ` → `i̇`, which
//       the IDNA mapping turns into `xn--i-9bb`) and stripped every
//       trailing dot, so a genuine create/update success on such a host
//       latched the page as unproven. Companions pin the mappings that
//       already agree; the control keeps a differently-spelled answer
//       unproven.

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { createUpstreamEntry, updateUpstreamEntry } from "../api/upstream";

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

// [submitted host, the host the appliance returns]
const CASE_AND_DOTS: ReadonlyArray<[string, string]> = [
  ["İ.example", "i.example"],
  ["İ", "i"],
  ["example.com..", "example.com."],
  ["example.com...", "example.com.."],
];
const COMPANIONS: ReadonlyArray<[string, string]> = [
  ["ΑΣ.example", "xn--mxa0b.example"],
  ["K.example", "k.example"],
  ["example.com.", "example.com"],
  ["ẞ.example", "xn--zca.example"],
];

describe("K7 a success on a host the appliance lower-cases or dot-strips differently is bound as it keeps it", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each(CASE_AND_DOTS)(
    "create with host %s resolves",
    async (typed, returned) => {
      stubAnswer(
        configWith(managed(returned, `http://svc@${returned}:3128`), 201),
      );
      const cfg = await createUpstreamEntry(
        { scheme: "http", host: typed, port: 3128, username: "svc" },
        5,
      );
      expect(cfg.entry?.host).toBe(returned);
    },
  );
  it.each(CASE_AND_DOTS)(
    "update with host %s resolves",
    async (typed, returned) => {
      stubAnswer(
        configWith(managed(returned, `http://svc@${returned}:3128`), 200),
      );
      const cfg = await updateUpstreamEntry(
        ID,
        { scheme: "http", host: typed, port: 3128, username: "svc" },
        3,
      );
      expect(cfg.entry?.id).toBe(ID);
    },
  );
  it.each(COMPANIONS)(
    "companion: the mapping for %s still binds",
    async (typed, returned) => {
      stubAnswer(
        configWith(managed(returned, `http://svc@${returned}:3128`), 201),
      );
      const cfg = await createUpstreamEntry(
        { scheme: "http", host: typed, port: 3128, username: "svc" },
        5,
      );
      expect(cfg.entry?.host).toBe(returned);
    },
  );
  it("control: an answer keeping a trailing dot the appliance would have stripped stays unproven", async () => {
    stubAnswer(
      configWith(managed("example.com.", "http://svc@example.com.:3128"), 201),
    );
    await rejectsUnproven(
      createUpstreamEntry(
        { scheme: "http", host: "example.com.", port: 3128, username: "svc" },
        5,
      ),
    );
  });
});
