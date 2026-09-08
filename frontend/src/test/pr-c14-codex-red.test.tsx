// PR-C14 RED matrix — the sixth Codex round on the Batch 2 PR head
// (db7eeae6), written against that tree BEFORE any correction. Every
// import exists there, so each case fails on its ASSERTION.
//
//   K9  Go's strings.TrimSpace and JavaScript's trim() use different
//       whitespace sets: the appliance strips U+0085 NEXT LINE (and
//       U+00A0, U+2028, U+3000 ...) from a username or host and KEEPS
//       U+FEFF, while the client's trim() keeps U+0085 and strips U+FEFF.
//       A username pasted with a leading or trailing NEXT LINE is
//       persisted and returned as `svc`, and the client's binding refused
//       the genuine create/update success as unproven; the editor's
//       draftToSpec sent the untrimmed value for the same reason.
//       Companions pin the whitespace both sides strip; the controls keep
//       a username the appliance would not have changed unproven.

import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { createUpstreamEntry, updateUpstreamEntry } from "../api/upstream";
import { draftToSpec } from "../features/network/upstream/upstreamEditors";

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
        username: entry.username,
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

// [submitted username, the username the appliance returns]
const GO_TRIMS: ReadonlyArray<[string, string]> = [
  ["\u0085svc", "svc"],
  ["svc\u0085", "svc"],
  ["\u0085svc\u0085", "svc"],
];
// [submitted username, the username the appliance KEEPS verbatim]
const GO_KEEPS: ReadonlyArray<[string, string]> = [["\ufeffsvc", "\ufeffsvc"]];
const COMPANIONS: ReadonlyArray<[string, string]> = [
  [" svc ", "svc"],
  ["\u00a0svc", "svc"],
  ["\u3000svc\u2028", "svc"],
  ["\u200bsvc", "\u200bsvc"],
];

function withUser(username: string) {
  const e = managed("parent-a.example", "http://svc@parent-a.example:3128");
  return { ...e, username };
}

describe("K9 a success on a username the appliance trims (or keeps) differently from trim() is bound as it returns it", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });
  it.each([...GO_TRIMS, ...GO_KEEPS])(
    "create with username %j resolves",
    async (typed, returned) => {
      const answer = configWith(withUser(returned), 201);
      stubAnswer(answer);
      const cfg = await createUpstreamEntry(
        {
          scheme: "http",
          host: "parent-a.example",
          port: 3128,
          username: typed,
        },
        5,
      );
      expect(cfg.entry?.username).toBe(returned);
    },
  );
  it.each([...GO_TRIMS, ...GO_KEEPS])(
    "update with username %j resolves",
    async (typed, returned) => {
      const answer = configWith(withUser(returned), 200);
      stubAnswer(answer);
      const cfg = await updateUpstreamEntry(
        ID,
        {
          scheme: "http",
          host: "parent-a.example",
          port: 3128,
          username: typed,
        },
        3,
      );
      expect(cfg.entry?.id).toBe(ID);
    },
  );
  it("create with a host carrying a leading NEXT LINE resolves", async () => {
    stubAnswer(
      configWith(
        managed("parent-a.example", "http://svc@parent-a.example:3128"),
        201,
      ),
    );
    const cfg = await createUpstreamEntry(
      {
        scheme: "http",
        host: "\u0085parent-a.example",
        port: 3128,
        username: "svc",
      },
      5,
    );
    expect(cfg.entry?.host).toBe("parent-a.example");
  });
  it.each(COMPANIONS)(
    "companion: username %j still binds",
    async (typed, returned) => {
      const answer = configWith(withUser(returned), 201);
      stubAnswer(answer);
      const cfg = await createUpstreamEntry(
        {
          scheme: "http",
          host: "parent-a.example",
          port: 3128,
          username: typed,
        },
        5,
      );
      expect(cfg.entry?.username).toBe(returned);
    },
  );
  it("control: an answer dropping a ZERO WIDTH SPACE the appliance keeps stays unproven", async () => {
    const answer = configWith(withUser("svc"), 201);
    stubAnswer(answer);
    await rejectsUnproven(
      createUpstreamEntry(
        {
          scheme: "http",
          host: "parent-a.example",
          port: 3128,
          username: "\u200bsvc",
        },
        5,
      ),
    );
  });
  it("the editor's draftToSpec trims exactly as the appliance does", () => {
    const spec = draftToSpec({
      scheme: "http",
      host: "\u0085parent-a.example\u3000",
      port: "3128",
      username: "\u0085svc\u00a0",
    });
    expect(typeof spec).not.toBe("string");
    if (typeof spec !== "string") {
      expect(spec.host).toBe("parent-a.example");
      expect(spec.username).toBe("svc");
    }
    const kept = draftToSpec({
      scheme: "http",
      host: "parent-a.example",
      port: "3128",
      username: "\ufeffsvc",
    });
    if (typeof kept !== "string") expect(kept.username).toBe("\ufeffsvc");
  });
});
