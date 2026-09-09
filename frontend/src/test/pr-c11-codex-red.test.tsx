// PR-C11 RED matrix — the third Codex round on the Batch 2 PR head
// (a3953619), written against that tree BEFORE any correction. Every
// import exists there, so each case fails on its ASSERTION.
//
//   K6  numeric host spellings: the appliance's normalizeHost recognises
//       only a full dotted-quad (net.ParseIP) as IPv4 and otherwise keeps
//       the host as an IDNA name — `127.1`, `2130706433` and `0x7f.1` are
//       stored and returned VERBATIM, and full-width digits are mapped by
//       UTS-46 to `127.1`. The client's canonical host went through the
//       WHATWG URL parser, which treats a last label that "ends in a
//       number" as an IPv4 literal and collapses all four to `127.0.0.1`,
//       so a genuine success on such a host latched the page as unproven.
//       The IDNA punycode mapping the URL parser was used for must survive
//       (`bücher.example` → `xn--bcher-kva.example`). Control: an answer
//       naming a different numeric host stays unproven.

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
const NUMERIC: ReadonlyArray<[string, string]> = [
  ["127.1", "127.1"],
  ["2130706433", "2130706433"],
  ["0x7f.1", "0x7f.1"],
  ["１２７.１", "127.1"],
];
const IDNA: ReadonlyArray<[string, string]> = [
  ["bücher.example", "xn--bcher-kva.example"],
  ["Ｅｘａｍｐｌｅ.com", "example.com"],
  ["127.0.0.1", "127.0.0.1"],
];

describe("K6 a success on a numeric host spelling is bound as the appliance keeps it", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each(NUMERIC)("create with host %s resolves", async (typed, returned) => {
    stubAnswer(
      configWith(managed(returned, `http://svc@${returned}:3128`), 201),
    );
    const cfg = await createUpstreamEntry(
      { scheme: "http", host: typed, port: 3128, username: "svc" },
      5,
    );
    expect(cfg.entry?.host).toBe(returned);
  });
  it.each(NUMERIC)("update with host %s resolves", async (typed, returned) => {
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
  it.each(IDNA)(
    "companion: the IDNA / dotted-quad mapping for %s still binds",
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
  it("control: an answer naming another numeric host stays unproven", async () => {
    stubAnswer(configWith(managed("127.2", "http://svc@127.2:3128"), 201));
    await rejectsUnproven(
      createUpstreamEntry(
        { scheme: "http", host: "127.1", port: 3128, username: "svc" },
        5,
      ),
    );
  });
});
