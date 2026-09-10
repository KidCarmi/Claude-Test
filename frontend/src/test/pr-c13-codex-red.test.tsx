// PR-C13 RED matrix — the fifth Codex round on the Batch 2 PR head
// (1bcc147f), written against that tree BEFORE any correction. Every
// import exists there, so each case fails on its ASSERTION.
//
//   K8  hosts the browser's URL parser REFUSES but the appliance's IDNA
//       mapping accepts: `ℵx.example` is mapped by UTS-46 to `אx.example`
//       (a label mixing right-to-left and left-to-right letters), which
//       the appliance returns as `xn--x-zhc.example` while the browser
//       throws on it; the client kept the raw spelling on a parser
//       failure and so refused a genuine create/update success as
//       unproven. The browser cannot be made to agree with the appliance's
//       tables, so the client must compare hosts at the UNICODE level
//       (punycode-decoded) with the NFKC mapping as the fallback for a
//       host the browser refuses. Companions pin symbol hosts the browser
//       already maps; the control keeps a different decoded host unproven.

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
const REFUSED_BY_BROWSER: ReadonlyArray<[string, string]> = [
  ["ℵx.example", "xn--x-zhc.example"],
  ["ℵＸ.example", "xn--x-zhc.example"],
];
const COMPANIONS: ReadonlyArray<[string, string]> = [
  ["ℶ.example", "xn--5db.example"],
  ["xℵ.example", "xn--x-0hc.example"],
  ["☃.example", "xn--n3h.example"],
  ["𝔞.example", "a.example"],
  ["ａ‐b.example", "xn--ab-v1t.example"],
];

describe("K8 a success on a host the browser refuses but the appliance maps is bound at the Unicode level", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each(REFUSED_BY_BROWSER)(
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
  it.each(REFUSED_BY_BROWSER)(
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
  it("control: an answer naming a host that decodes to different letters stays unproven", async () => {
    // xn--x-0hc decodes to `xא` — not the `אx` that was typed.
    stubAnswer(
      configWith(
        managed("xn--x-0hc.example", "http://svc@xn--x-0hc.example:3128"),
        201,
      ),
    );
    await rejectsUnproven(
      createUpstreamEntry(
        { scheme: "http", host: "ℵx.example", port: 3128, username: "svc" },
        5,
      ),
    );
  });
  it("control: a returned host with a malformed punycode label stays unproven", async () => {
    stubAnswer(
      configWith(managed("xn--.example", "http://svc@xn--.example:3128"), 201),
    );
    await rejectsUnproven(
      createUpstreamEntry(
        { scheme: "http", host: "ℵx.example", port: 3128, username: "svc" },
        5,
      ),
    );
  });
});
