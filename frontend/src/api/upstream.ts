// 2F-F — the Upstream Proxies (parent-proxy chaining) admin API boundary:
// the credential-FREE v2 read model, per-entry create/update/delete, the
// write-only credential endpoint (T2 replace / T3 clear) and the manual
// probe. Every response crosses the boundary through a total decoder and
// every refusal the page acts on is decoded STRUCTURALLY from the server
// body (never from prose).
//
// Frozen backend semantics this client honours verbatim (2F-C/2F-D, C4,
// C6, C7, C9, C11, C12): a stable id (server ULID for `managed`,
// `yaml-<digest>` for read-only config.yaml entries — 409 yaml_owned on any
// mutation); a canonical authority `scheme://[username@]host:port`; a
// DERIVED `credentialState` (none | configured | unusable | mismatch |
// requiresReplacement) that a client may never assert (400
// credential_state_not_accepted); create fenced on the DOCUMENT revision,
// update/delete/credential on the ENTRY revision (428 precondition_required
// / 409 stale with `current.revision` / 404 vanished); an authority change
// while a credential exists is 409 credential_bound, a delete of an entry
// holding material is 409 credential_present; the manual probe is admin-only
// and window-limited (429 probe_in_flight / probe_rate_limited with
// `current.retryAfterSeconds`).
//
// SECRECY: the password travels ONCE, in the body of `replace`, and is
// never held afterwards — no caller keeps it, no read model returns it,
// and the decoder REFUSES an entry that carries credential material (a
// `password` / `credential` / `ciphertext` key, or a userinfo password in
// `url`/`authority`) so a misbehaving server can never put a secret into
// the DOM.
import { ApiError, apiRequest } from "./client";
import {
  DecodeError,
  field,
  isRecord,
  readArray,
  readBoolean,
  readEnum,
  readNumber,
  readOptional,
  readRecord,
  readString,
} from "./decode";
import type { Decoder } from "./decode";

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

// ── Vocabulary (the frozen 2F-C/2F-D enums; see internal/upstream) ─────────

export const UPSTREAM_MODES = [
  "no_pool",
  "chained",
  "no_eligible_parent",
  "direct_fallback",
] as const;
export type UpstreamMode = (typeof UPSTREAM_MODES)[number];

export const UPSTREAM_CREDENTIAL_STATES = [
  "none",
  "configured",
  "unusable",
  "mismatch",
  "requiresReplacement",
] as const;
export type UpstreamCredentialState =
  (typeof UPSTREAM_CREDENTIAL_STATES)[number];

export const UPSTREAM_HEALTH_STATUSES = [
  "unprobed",
  "healthy",
  "unhealthy",
] as const;
export type UpstreamHealthStatus = (typeof UPSTREAM_HEALTH_STATUSES)[number];

export const UPSTREAM_HEALTH_REASONS = [
  "none",
  "connect_failed",
  "timeout",
  "proxy_auth_failed",
  "probe_http_error",
  "credential_ineligible",
] as const;
export type UpstreamHealthReason = (typeof UPSTREAM_HEALTH_REASONS)[number];

export const UPSTREAM_PROBE_SOURCES = ["periodic", "manual"] as const;
export type UpstreamProbeSource = (typeof UPSTREAM_PROBE_SOURCES)[number];

export const UPSTREAM_SOURCES = ["managed", "yaml"] as const;
export type UpstreamSource = (typeof UPSTREAM_SOURCES)[number];

export const UPSTREAM_SCHEMES = ["http", "https"] as const;
export type UpstreamScheme = (typeof UPSTREAM_SCHEMES)[number];

export const UPSTREAM_CIRCUITS = ["closed", "open", "half-open"] as const;
export type UpstreamCircuit = (typeof UPSTREAM_CIRCUITS)[number];

export const UPSTREAM_KEY_STATES = [
  "present",
  "missing",
  "unreadable",
  "unused",
] as const;
export type UpstreamKeyState = (typeof UPSTREAM_KEY_STATES)[number];

export const UPSTREAM_MIGRATION_STATES = ["none", "ok", "degraded"] as const;
export type UpstreamMigrationState = (typeof UPSTREAM_MIGRATION_STATES)[number];

/** Every bounded refusal code the 2F-C/2F-D upstream endpoints answer. */
export const UPSTREAM_REFUSAL_CODES = [
  "precondition_required",
  "stale",
  "vanished",
  "yaml_owned",
  "credential_bound",
  "credential_present",
  "confirm_required",
  "credentialed_entries_present",
  "duplicate_authority",
  "no_credential",
  "invalid_entry",
  "userinfo_not_allowed",
  "credential_state_not_accepted",
  "invalid_password",
  "invalid_action",
  "invalid_json",
  "key_unusable",
  "document_rejected",
  "persist_failed",
  "seal_failed",
  "probe_in_flight",
  "probe_rate_limited",
] as const;
export type UpstreamRefusalCode = (typeof UPSTREAM_REFUSAL_CODES)[number];

// ── Model ───────────────────────────────────────────────────────────────────

export interface UpstreamHealth {
  status: UpstreamHealthStatus;
  reason: UpstreamHealthReason;
  lastProbeAt?: string;
  source?: UpstreamProbeSource;
}

export interface UpstreamEntry {
  id: string;
  /** legacy `scheme://host:port` — never userinfo */
  url: string;
  /** canonical `scheme://[username@]host:port` */
  authority: string;
  scheme: UpstreamScheme;
  host: string;
  port: number;
  username: string;
  source: UpstreamSource;
  revision: number;
  credentialState: UpstreamCredentialState;
  health: UpstreamHealth;
  healthy: boolean;
  eligible: boolean;
  circuit: UpstreamCircuit;
  failures: number;
  openedAtMs?: number;
  retryAfterMs?: number;
}

export interface UpstreamEffective {
  mode: UpstreamMode;
  entries: number;
  eligible: number;
  fallbackTotal: number;
  since: string;
}

export interface UpstreamCoverage {
  plainHttp: "chained";
  connect: "direct";
  websocket: "direct";
  socks5: "direct";
  summary: "plain_http_only";
}

export interface UpstreamProbeConfig {
  configured: boolean;
  interval: string;
}

export interface UpstreamDirectFallback {
  active: boolean;
  total: number;
}

export interface UpstreamMigration {
  state: UpstreamMigrationState;
  reason?: string;
  at?: string;
  migrated?: number;
  sealed?: number;
  yamlOwned?: number;
}

export interface UpstreamKey {
  state: UpstreamKeyState;
  keyId?: string;
}

export interface UpstreamDegraded {
  reason: string;
  count?: number;
}

export interface UpstreamProbeSummary {
  probed: number;
  healthy: number;
  unhealthy: number;
  skipped: number;
}

/** The entry a create/update/credential mutation just produced. */
export interface UpstreamEntryDTO {
  id: string;
  scheme: string;
  host: string;
  port: number;
  username: string;
  authority: string;
  source: string;
  revision: number;
  credentialState: UpstreamCredentialState;
}

export interface UpstreamConfig {
  enabled: boolean;
  mode: UpstreamMode;
  effective: UpstreamEffective;
  coverage: UpstreamCoverage;
  probe: UpstreamProbeConfig;
  /** the managed-document token a create must echo */
  revision: number;
  entries: readonly UpstreamEntry[];
  directFallback: UpstreamDirectFallback;
  migration: UpstreamMigration;
  key: UpstreamKey;
  degraded?: UpstreamDegraded;
  yamlDegraded?: UpstreamDegraded;
  credentialsIneligible: number;
  credentialsRequiringReplacement: number;
  scope: "node-local";
  ok?: boolean;
  summary?: UpstreamProbeSummary;
  entry?: UpstreamEntryDTO;
  /** the id a delete answer names (the delete's action evidence) */
  deleted?: string;
}

/** The client-authored entry spec — the password is NEVER part of it. */
export interface UpstreamEntrySpec {
  scheme: string;
  host: string;
  port: number;
  username: string;
}

// ── Decoders ────────────────────────────────────────────────────────────────

const MATERIAL_KEYS = ["password", "credential", "ciphertext", "sealed"];

/** `scheme://user:pw@host` — a password inside the userinfo. */
function carriesUserinfoPassword(s: string): boolean {
  const idx = s.indexOf("://");
  if (idx < 0) return false;
  const rest = s.slice(idx + 3);
  const at = rest.lastIndexOf("@");
  if (at < 0) return false;
  return rest.slice(0, at).includes(":");
}

/** Fail-closed guard: an entry object that carries credential material is
 * refused as a decode failure — it is never rendered. */
function refuseMaterial(o: Record<string, unknown>, path: string): void {
  for (const k of MATERIAL_KEYS) {
    if (k in o) {
      throw new DecodeError(
        `${path}.${k}`,
        "no credential material (never reaches the browser)",
        o[k],
      );
    }
  }
  for (const k of ["url", "authority"]) {
    const v = o[k];
    if (typeof v === "string" && carriesUserinfoPassword(v)) {
      throw new DecodeError(`${path}.${k}`, "no userinfo password", v);
    }
  }
}

export const decodeUpstreamHealth: Decoder<UpstreamHealth> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const lastProbeAt = opt(o, "lastProbeAt", readString, path);
  const source = opt(o, "source", readEnum(UPSTREAM_PROBE_SOURCES), path);
  return {
    status: field(o, "status", readEnum(UPSTREAM_HEALTH_STATUSES), path),
    reason: field(o, "reason", readEnum(UPSTREAM_HEALTH_REASONS), path),
    ...(lastProbeAt !== undefined ? { lastProbeAt } : {}),
    ...(source !== undefined ? { source } : {}),
  };
};

export const decodeUpstreamEntry: Decoder<UpstreamEntry> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseMaterial(o, path);
  const openedAtMs = opt(o, "openedAtMs", readNumber, path);
  const retryAfterMs = opt(o, "retryAfterMs", readNumber, path);
  return {
    id: field(o, "id", readString, path),
    url: field(o, "url", readString, path),
    authority: field(o, "authority", readString, path),
    scheme: field(o, "scheme", readEnum(UPSTREAM_SCHEMES), path),
    host: field(o, "host", readString, path),
    port: field(o, "port", readNumber, path),
    username: opt(o, "username", readString, path) ?? "",
    source: field(o, "source", readEnum(UPSTREAM_SOURCES), path),
    revision: field(o, "revision", readNumber, path),
    credentialState: field(
      o,
      "credentialState",
      readEnum(UPSTREAM_CREDENTIAL_STATES),
      path,
    ),
    health: field(o, "health", decodeUpstreamHealth, path),
    healthy: field(o, "healthy", readBoolean, path),
    eligible: field(o, "eligible", readBoolean, path),
    circuit: field(o, "circuit", readEnum(UPSTREAM_CIRCUITS), path),
    failures: field(o, "failures", readNumber, path),
    ...(openedAtMs !== undefined ? { openedAtMs } : {}),
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
  };
};

const decodeEffective: Decoder<UpstreamEffective> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    mode: field(o, "mode", readEnum(UPSTREAM_MODES), path),
    entries: field(o, "entries", readNumber, path),
    eligible: field(o, "eligible", readNumber, path),
    fallbackTotal: field(o, "fallbackTotal", readNumber, path),
    since: field(o, "since", readString, path),
  };
};

const decodeCoverage: Decoder<UpstreamCoverage> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    plainHttp: field(o, "plainHttp", readEnum(["chained"] as const), path),
    connect: field(o, "connect", readEnum(["direct"] as const), path),
    websocket: field(o, "websocket", readEnum(["direct"] as const), path),
    socks5: field(o, "socks5", readEnum(["direct"] as const), path),
    summary: field(o, "summary", readEnum(["plain_http_only"] as const), path),
  };
};

const decodeDegraded: Decoder<UpstreamDegraded> = (v, path = "$") => {
  const o = readRecord(v, path);
  const count = opt(o, "count", readNumber, path);
  return {
    reason: field(o, "reason", readString, path),
    ...(count !== undefined ? { count } : {}),
  };
};

const decodeMigration: Decoder<UpstreamMigration> = (v, path = "$") => {
  const o = readRecord(v, path);
  const reason = opt(o, "reason", readString, path);
  const at = opt(o, "at", readString, path);
  const migrated = opt(o, "migrated", readNumber, path);
  const sealed = opt(o, "sealed", readNumber, path);
  const yamlOwned = opt(o, "yamlOwned", readNumber, path);
  return {
    state: field(o, "state", readEnum(UPSTREAM_MIGRATION_STATES), path),
    ...(reason !== undefined ? { reason } : {}),
    ...(at !== undefined ? { at } : {}),
    ...(migrated !== undefined ? { migrated } : {}),
    ...(sealed !== undefined ? { sealed } : {}),
    ...(yamlOwned !== undefined ? { yamlOwned } : {}),
  };
};

const decodeKey: Decoder<UpstreamKey> = (v, path = "$") => {
  const o = readRecord(v, path);
  const keyId = opt(o, "keyId", readString, path);
  return {
    state: field(o, "state", readEnum(UPSTREAM_KEY_STATES), path),
    ...(keyId !== undefined ? { keyId } : {}),
  };
};

export const decodeUpstreamProbeSummary: Decoder<UpstreamProbeSummary> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  return {
    probed: field(o, "probed", readNumber, path),
    healthy: field(o, "healthy", readNumber, path),
    unhealthy: field(o, "unhealthy", readNumber, path),
    skipped: field(o, "skipped", readNumber, path),
  };
};

const decodeEntryDTO: Decoder<UpstreamEntryDTO> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseMaterial(o, path);
  return {
    id: field(o, "id", readString, path),
    scheme: field(o, "scheme", readString, path),
    host: field(o, "host", readString, path),
    port: field(o, "port", readNumber, path),
    username: opt(o, "username", readString, path) ?? "",
    authority: field(o, "authority", readString, path),
    source: field(o, "source", readString, path),
    revision: field(o, "revision", readNumber, path),
    credentialState: field(
      o,
      "credentialState",
      readEnum(UPSTREAM_CREDENTIAL_STATES),
      path,
    ),
  };
};

/** `entries` is nullable on the wire (an empty pool serialises as null). */
function readEntries(v: unknown, path: string): readonly UpstreamEntry[] {
  if (v === null || v === undefined) return [];
  return readArray(decodeUpstreamEntry)(v, path);
}

export const decodeUpstreamConfig: Decoder<UpstreamConfig> = (
  v,
  path = "$",
) => {
  const o = readRecord(v, path);
  const df = readRecord(o["direct_fallback"], `${path}.direct_fallback`);
  const degraded = opt(o, "degraded", decodeDegraded, path);
  const yamlDegraded = opt(o, "yamlDegraded", decodeDegraded, path);
  const ok = opt(o, "ok", readBoolean, path);
  const summary = opt(o, "summary", decodeUpstreamProbeSummary, path);
  const entry = opt(o, "entry", decodeEntryDTO, path);
  const deleted = opt(o, "deleted", readString, path);
  return {
    enabled: field(o, "enabled", readBoolean, path),
    mode: field(o, "mode", readEnum(UPSTREAM_MODES), path),
    effective: field(o, "effective", decodeEffective, path),
    coverage: field(o, "coverage", decodeCoverage, path),
    probe: (() => {
      const p = readRecord(o["probe"], `${path}.probe`);
      return {
        configured: field(p, "configured", readBoolean, `${path}.probe`),
        interval: field(p, "interval", readString, `${path}.probe`),
      };
    })(),
    revision: field(o, "revision", readNumber, path),
    entries: readEntries(o["entries"], `${path}.entries`),
    directFallback: {
      active: field(df, "active", readBoolean, `${path}.direct_fallback`),
      total: field(df, "total", readNumber, `${path}.direct_fallback`),
    },
    migration: field(o, "migration", decodeMigration, path),
    key: field(o, "key", decodeKey, path),
    ...(degraded !== undefined ? { degraded } : {}),
    ...(yamlDegraded !== undefined ? { yamlDegraded } : {}),
    credentialsIneligible: field(o, "credentialsIneligible", readNumber, path),
    credentialsRequiringReplacement: field(
      o,
      "credentialsRequiringReplacement",
      readNumber,
      path,
    ),
    scope: field(o, "scope", readEnum(["node-local"] as const), path),
    ...(ok !== undefined ? { ok } : {}),
    ...(summary !== undefined ? { summary } : {}),
    ...(entry !== undefined ? { entry } : {}),
    ...(deleted !== undefined ? { deleted } : {}),
  };
};

// ── Refusals (structured, bounded, status-bound, allowlisted facts) ─────────
//
// 2F-F correction: a refusal is a VERDICT ("nothing was changed") only when
// the appliance's answer is well-formed — the bounded code with its
// CONTRACTED HTTP status and its REQUIRED safe facts. Anything else (a
// mismatched status, a malformed `current`, an unknown code, a non-JSON
// body) is never a verdict: it is UNPROVEN and enters the authoritative
// read-back flow. The facts that may be rendered are TYPED and allowlisted
// here; the raw `current` record and the server's `error` line are kept
// for tests/logs but are never rendered, and an authority that carries a
// userinfo password is dropped from the facts.

function parsedBody(err: unknown): Record<string, unknown> | null {
  if (!(err instanceof ApiError) || err.kind !== "http") return null;
  if (err.bodyText === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(err.bodyText);
  } catch {
    return null;
  }
  return isRecord(parsed) ? parsed : null;
}

/** Allowlisted, typed facts a refusal may carry into the DOM. */
export interface UpstreamRefusalFacts {
  id?: string;
  revision?: number;
  /** canonical `scheme://[username@]host:port` — never a userinfo password */
  authority?: string;
  credentialState?: UpstreamCredentialState;
  count?: number;
  retryAfterSeconds?: number;
  /** equals `id` by contract (the T3 confirmation value) */
  confirmValue?: string;
  degradedReason?: string;
  index?: number;
}

export interface UpstreamRefusal {
  status: number;
  code: UpstreamRefusalCode;
  /** the raw server record — kept for tests/diagnostics, NEVER rendered */
  current: Readonly<Record<string, unknown>>;
  count?: number;
  /** the server's error line — NEVER rendered */
  message: string;
  facts: UpstreamRefusalFacts;
}

type RequiredFact =
  "id" | "revision" | "credentialState" | "retryAfterSeconds" | "confirmValue";

/** The contracted HTTP status + required facts per code (ui_upstream.go). */
const REFUSAL_CONTRACT: Readonly<
  Record<
    UpstreamRefusalCode,
    { status: number; required: readonly RequiredFact[] }
  >
> = {
  precondition_required: { status: 428, required: ["revision"] },
  stale: { status: 409, required: ["revision"] },
  vanished: { status: 404, required: ["id"] },
  yaml_owned: { status: 409, required: ["id"] },
  credential_bound: {
    status: 409,
    required: ["id", "revision", "credentialState"],
  },
  credential_present: {
    status: 409,
    required: ["id", "revision", "credentialState"],
  },
  confirm_required: {
    status: 409,
    required: ["id", "revision", "confirmValue"],
  },
  credentialed_entries_present: { status: 409, required: [] },
  duplicate_authority: { status: 409, required: [] },
  no_credential: { status: 409, required: ["id", "revision"] },
  invalid_entry: { status: 400, required: [] },
  userinfo_not_allowed: { status: 400, required: [] },
  credential_state_not_accepted: { status: 400, required: [] },
  invalid_password: { status: 400, required: [] },
  invalid_action: { status: 400, required: [] },
  invalid_json: { status: 400, required: [] },
  key_unusable: { status: 409, required: ["id", "revision"] },
  document_rejected: { status: 409, required: [] },
  persist_failed: { status: 500, required: [] },
  seal_failed: { status: 500, required: [] },
  probe_in_flight: { status: 429, required: ["retryAfterSeconds"] },
  probe_rate_limited: { status: 429, required: ["retryAfterSeconds"] },
};

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SAFE_TOKEN = /^[A-Za-z0-9_.-]{1,64}$/;
const SAFE_AUTHORITY =
  /^https?:\/\/(?:[A-Za-z0-9._~%+-]+@)?[A-Za-z0-9.\-[\]:]{1,253}:\d{1,5}$/;

function isRefusalCode(v: unknown): v is UpstreamRefusalCode {
  return typeof v === "string" && UPSTREAM_REFUSAL_CODES.some((c) => c === v);
}

function safeId(v: unknown): string | undefined {
  return typeof v === "string" && SAFE_ID.test(v) ? v : undefined;
}
function safeNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : undefined;
}
function safeAuthority(v: unknown): string | undefined {
  if (typeof v !== "string" || !SAFE_AUTHORITY.test(v)) return undefined;
  return carriesUserinfoPassword(v) ? undefined : v;
}
function safeCredentialState(v: unknown): UpstreamCredentialState | undefined {
  return UPSTREAM_CREDENTIAL_STATES.find((s) => s === v);
}

function refusalFacts(
  current: Readonly<Record<string, unknown>>,
  topCount: unknown,
): UpstreamRefusalFacts {
  const f: UpstreamRefusalFacts = {};
  const id = safeId(current["id"]);
  if (id !== undefined) f.id = id;
  const revision = safeNumber(current["revision"]);
  if (revision !== undefined) f.revision = revision;
  const authority = safeAuthority(current["authority"]);
  if (authority !== undefined) f.authority = authority;
  const state = safeCredentialState(current["credentialState"]);
  if (state !== undefined) f.credentialState = state;
  const count = safeNumber(topCount) ?? safeNumber(current["count"]);
  if (count !== undefined) f.count = count;
  const retry = safeNumber(current["retryAfterSeconds"]);
  if (retry !== undefined) f.retryAfterSeconds = retry;
  const confirm = safeId(current["confirmValue"]);
  if (confirm !== undefined && confirm === id) f.confirmValue = confirm;
  const degraded = current["degraded"];
  if (isRecord(degraded)) {
    const reason = degraded["reason"];
    if (typeof reason === "string" && SAFE_TOKEN.test(reason))
      f.degradedReason = reason;
  }
  const index = safeNumber(current["index"]);
  if (index !== undefined) f.index = index;
  return f;
}

/** A bounded 2F-C/2F-D refusal — decoded from {error, code, current} and
 * accepted ONLY with the code's contracted HTTP status and its required
 * safe facts. An unknown code, a mismatched status, a malformed `current`,
 * a text/plain body, or a transport death is NEVER a known refusal. */
export function asUpstreamRefusal(err: unknown): UpstreamRefusal | null {
  const o = parsedBody(err);
  if (o === null || !(err instanceof ApiError) || err.status === undefined)
    return null;
  const code = o["code"];
  if (!isRefusalCode(code)) return null;
  const contract = REFUSAL_CONTRACT[code];
  if (err.status !== contract.status) return null;
  const current = o["current"];
  if (!isRecord(current)) return null;
  const facts = refusalFacts(current, o["count"]);
  for (const need of contract.required) {
    if (facts[need] === undefined) return null;
  }
  return {
    status: err.status,
    code,
    current,
    ...(facts.count !== undefined ? { count: facts.count } : {}),
    message: typeof o["error"] === "string" ? o["error"] : "",
    facts,
  };
}

export interface UpstreamFence {
  status: 428 | 409;
  code: "precondition_required" | "stale";
  current: Readonly<Record<string, unknown>>;
  message: string;
  /** the server-owned current revision (always present on a fence) */
  revision: number;
}

/** The revision fence: 428 precondition_required / 409 stale with a
 * numeric server-owned `current.revision`. */
export function asUpstreamFence(err: unknown): UpstreamFence | null {
  const r = asUpstreamRefusal(err);
  if (r === null || r.facts.revision === undefined) return null;
  if (r.code === "precondition_required" && r.status === 428)
    return {
      status: 428,
      code: r.code,
      current: r.current,
      message: r.message,
      revision: r.facts.revision,
    };
  if (r.code === "stale" && r.status === 409)
    return {
      status: 409,
      code: r.code,
      current: r.current,
      message: r.message,
      revision: r.facts.revision,
    };
  return null;
}

/** A numeric fact under `current` (revision, retryAfterSeconds, count). */
export function refusalCurrentNumber(
  r: { current: Readonly<Record<string, unknown>> },
  key: string,
): number | undefined {
  const v = r.current[key];
  return typeof v === "number" ? v : undefined;
}

// ── Outcome classification ──────────────────────────────────────────────────

/** Is a mutation's outcome UNPROVEN — the request may have been durably
 * applied but the client holds no trustworthy verdict? True for a
 * transport death (network / timeout / abort), for a 2xx whose media type,
 * JSON or action-specific schema could not be verified, and for any
 * non-2xx answer that is not a recognised refusal (an unknown code, a
 * mismatched status, a malformed body). False ONLY for a recognised
 * refusal, a 401 (the auth boundary owns it) and a 403 (the server refused
 * before touching anything). */
export function unprovenOutcome(err: unknown): boolean {
  if (!(err instanceof ApiError)) return true;
  switch (err.kind) {
    case "network":
    case "timeout":
    case "aborted":
    case "contenttype":
    case "decode":
    case "toolarge":
      return true;
    case "target":
      return false;
    case "http":
      if (err.status === 401 || err.status === 403) return false;
      return asUpstreamRefusal(err) === null;
  }
}

// ── Requests ────────────────────────────────────────────────────────────────

function sig(
  signal: AbortSignal | undefined,
): { signal: AbortSignal } | Record<never, never> {
  return signal !== undefined ? { signal } : {};
}

export function getUpstream(signal?: AbortSignal): Promise<UpstreamConfig> {
  return apiRequest("/api/upstream", decodeUpstreamConfig, sig(signal));
}

/** The exact wire shape of a create/update body — nothing else is ever sent. */
function specWire(
  spec: UpstreamEntrySpec,
  revision: number,
): Record<string, unknown> {
  return {
    scheme: spec.scheme,
    host: spec.host,
    port: spec.port,
    username: spec.username,
    revision,
  };
}

/** The canonical FIELDS the appliance derives from a submitted spec
 * (`Normalize`: scheme + host lower-cased, trailing dot stripped, IDNA via
 * the URL parser, the scheme default port, the username trimmed). Used
 * ONLY to bind a success answer to the request — never to render or to
 * send. The answer is bound FIELD BY FIELD, never through a rebuilt
 * authority string: the appliance percent-escapes the username inside
 * `authority` (url.PathEscape — `?`, `#`, `%`, `;`, non-ASCII), and a
 * client-side re-implementation of that escaping would turn a genuine
 * success into an unproven outcome on exactly the usernames it got wrong
 * (PR-C9 K2). */
export interface CanonicalSpec {
  scheme: string;
  host: string;
  /** The host at the Unicode level (see hostUnicodeKey) — the appliance's
   *  IDNA tables cannot be reproduced exactly in the browser, so a returned
   *  host is ALSO accepted when it decodes to the same letters. */
  hostKey: string;
  port: number;
  username: string;
}

// ── Unicode-level host identity (PR-C13 K8) ─────────────────────────────
// RFC 3492 punycode decoding of one label (the part after `xn--`).
// Returns undefined for a malformed label — never a guess.
function punycodeDecode(input: string): string | undefined {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const out: number[] = [];
  let n = 128;
  let i = 0;
  let bias = 72;
  const delim = input.lastIndexOf("-");
  const basicEnd = delim > 0 ? delim : 0;
  for (let j = 0; j < basicEnd; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return undefined;
    out.push(c);
  }
  const digit = (c: number): number => {
    if (c >= 48 && c <= 57) return c - 22;
    if (c >= 65 && c <= 90) return c - 65;
    if (c >= 97 && c <= 122) return c - 97;
    return base;
  };
  const adapt = (d: number, numPoints: number, first: boolean): number => {
    let delta = first ? Math.floor(d / damp) : d >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  let idx = basicEnd > 0 ? basicEnd + 1 : 0;
  while (idx < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) return undefined;
      const d = digit(input.charCodeAt(idx++));
      if (d >= base) return undefined;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    const numPoints = out.length + 1;
    bias = adapt(i - oldi, numPoints, oldi === 0);
    n += Math.floor(i / numPoints);
    i %= numPoints;
    if (n > 0x10ffff) return undefined;
    out.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...out);
}

// The Unicode form of an ASCII (A-label) host: every `xn--` label decoded,
// NFC-normalised. A host with a malformed punycode label has NO key (an
// empty string can never equal a typed host).
export function hostUnicodeKey(host: string): string {
  if (host === "" || host.startsWith("[")) return host;
  const labels: string[] = [];
  for (const label of host.split(".")) {
    if (label.toLowerCase().startsWith("xn--")) {
      const u = punycodeDecode(label.slice(4));
      if (u === undefined || u === "") return "";
      labels.push(u);
    } else {
      labels.push(label);
    }
  }
  return labels.join(".").normalize("NFC");
}
// A trailing label appended ONLY while the browser maps a host through the
// URL parser (see canonicalSpec); it is stripped again and never reaches the
// appliance.
const HOST_MAP_SENTINEL = ".culvert-host-map-sentinel";

// Go's strings.TrimSpace strips Unicode White_Space — '\t' '\n' '\v' '\f'
// '\r' ' ' U+0085 U+00A0 and the Zs/Zl/Zp separators — while JavaScript's
// trim() strips its own WhiteSpace + LineTerminator set, which KEEPS U+0085
// and additionally strips U+FEFF. The appliance trims every spec field with
// Go's set, so the client trims with the same set (PR-C14 K9).
const GO_SPACE =
  /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g;
export function trimAsGo(s: string): string {
  return s.replace(GO_SPACE, "");
}

// Go's strings.ToLower applies the SIMPLE Unicode case mapping; JavaScript's
// toLowerCase applies the FULL mapping, which differs unconditionally for
// U+0130 (`İ` → `i̇`, two code points, vs `i`) and conditionally for a final
// sigma (`Σ` → `ς` at the end of a word vs `σ` always). Both are mapped to
// Go's result before the JavaScript lower-casing so the client agrees with
// the appliance on every host (PR-C12 K7).
function lowerAsGo(s: string): string {
  return s
    .replace(/\u0130/g, "i")
    .replace(/\u03a3/g, "\u03c3")
    .toLowerCase();
}

export function canonicalSpec(spec: UpstreamEntrySpec): CanonicalSpec {
  const scheme = trimAsGo(spec.scheme).toLowerCase();
  // The appliance strips exactly ONE trailing dot (`example.com..` is
  // accepted and kept as `example.com.`) — never all of them (PR-C12 K7).
  let host = lowerAsGo(trimAsGo(spec.host)).replace(/\.$/, "");
  let hostKey: string | undefined;
  if (host.includes(":")) {
    // An IPv6 literal: the appliance brackets a bare one and keeps the
    // literal AS TYPED (lower-cased, never compressed) — the URL parser
    // throws on a bare literal and compresses a bracketed one, so it must
    // not see it (PR-C10 K4).
    host = `[${host.replace(/^\[|\]$/g, "")}]`;
  } else {
    // Every other host is an IDNA name to the appliance: normalizeHost
    // recognises only a full dotted-quad as IPv4 and otherwise keeps the
    // UTS-46 mapping of what was typed (`127.1`, `2130706433`, `0x7f.1`
    // stay verbatim; full-width digits map to ASCII). The URL parser gives
    // the same UTS-46 mapping, but treats a LAST label that ends in a
    // number as an IPv4 literal and collapses those spellings to
    // `127.0.0.1` — so it is asked to map the host with a sentinel label
    // appended (never a last label, never numeric) and the sentinel is
    // stripped again (PR-C11 K6).
    try {
      const u = new URL(`http://${host}${HOST_MAP_SENTINEL}`);
      if (u.hostname.endsWith(HOST_MAP_SENTINEL)) {
        host = u.hostname.slice(0, -HOST_MAP_SENTINEL.length);
      }
    } catch {
      // The browser refuses a host the appliance's IDNA tables may still
      // accept (`ℵx.example` maps to `אx.example`, a label the browser's
      // bidi check rejects, which the appliance returns as
      // `xn--x-zhc.example`). The lowered host is kept, and the binding
      // falls back to the Unicode-level key: UTS-46 is NFKC plus case
      // folding for every mapped character seen so far, so the typed host
      // is NFKC-mapped and lower-cased again (PR-C13 K8).
      hostKey = lowerAsGo(host.normalize("NFKC"));
    }
  }
  const port = spec.port === 0 ? (scheme === "https" ? 443 : 80) : spec.port;
  return {
    scheme,
    host,
    hostKey: hostKey ?? hostUnicodeKey(host),
    port,
    username: trimAsGo(spec.username),
  };
}

function matchesSpec(
  e: { scheme: string; host: string; port: number; username: string },
  want: CanonicalSpec,
): boolean {
  if (
    e.scheme !== want.scheme ||
    e.port !== want.port ||
    e.username !== want.username
  ) {
    return false;
  }
  if (e.host === want.host) return true;
  // The appliance's ASCII form differs from the browser's: accept it only
  // when it decodes to exactly the letters that were typed (PR-C13 K8).
  const key = hostUnicodeKey(e.host);
  return key !== "" && key === want.hostKey;
}

/** Wrap the read-model decoder with an ACTION-SPECIFIC evidence check: a
 * schema-valid generic view is never proof of a mutation. A missing,
 * contradictory or wrong-identity answer is a decode failure, which the
 * page classifies as UNPROVEN (authoritative read-back). */
function bound(
  want: string,
  check: (cfg: UpstreamConfig) => boolean,
): Decoder<UpstreamConfig> {
  return (v, path = "$") => {
    const cfg = decodeUpstreamConfig(v, path);
    if (!check(cfg)) throw new DecodeError(`${path}.entry`, want, v);
    return cfg;
  };
}

/** POST /api/upstream/entries — fenced on the DOCUMENT revision; the
 * answer must name a MANAGED entry with the submitted canonical authority
 * that the republished list contains. */
export function createUpstreamEntry(
  spec: UpstreamEntrySpec,
  documentRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  const want = canonicalSpec(spec);
  return apiRequest(
    "/api/upstream/entries",
    bound(
      "the created managed entry with the submitted authority",
      (cfg) =>
        cfg.entry !== undefined &&
        cfg.entry.source === "managed" &&
        matchesSpec(cfg.entry, want) &&
        cfg.entries.some((e) => e.id === cfg.entry?.id),
    ),
    { method: "POST", body: specWire(spec, documentRevision), ...sig(signal) },
  );
}

/** PUT /api/upstream/entries/{id} — fenced on the ENTRY revision; the
 * answer must name the requested id with the submitted authority. */
export function updateUpstreamEntry(
  id: string,
  spec: UpstreamEntrySpec,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  const want = canonicalSpec(spec);
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}`,
    bound(
      "the updated entry (requested id, submitted authority)",
      (cfg) =>
        cfg.entry !== undefined &&
        cfg.entry.id === id &&
        matchesSpec(cfg.entry, want) &&
        cfg.entries.some((e) => e.id === id && matchesSpec(e, want)),
    ),
    { method: "PUT", body: specWire(spec, entryRevision), ...sig(signal) },
  );
}

/** DELETE /api/upstream/entries/{id}?revision= — the token travels in the
 * QUERY only; the answer must name the deleted id and no longer list it. */
export function deleteUpstreamEntry(
  id: string,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}?revision=${encodeURIComponent(String(entryRevision))}`,
    bound(
      "deleted == the requested id and the id absent from the list",
      (cfg) => cfg.deleted === id && !cfg.entries.some((e) => e.id === id),
    ),
    { method: "DELETE", ...sig(signal) },
  );
}

function credentialBound(
  id: string,
  state: UpstreamCredentialState,
): Decoder<UpstreamConfig> {
  return bound(
    `entry ${id} with credentialState ${state}`,
    (cfg) =>
      cfg.entry !== undefined &&
      cfg.entry.id === id &&
      cfg.entry.credentialState === state &&
      cfg.entries.some((e) => e.id === id && e.credentialState === state),
  );
}

/** T2 — seal a new password under the node-local key. The password is in
 * the body ONLY and is not retained by this client; the answer must name
 * the exact entry as `configured`. */
export function replaceUpstreamCredential(
  id: string,
  password: string,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}/credential`,
    credentialBound(id, "configured"),
    {
      method: "POST",
      body: { action: "replace", password, revision: entryRevision },
      ...sig(signal),
    },
  );
}

/** T3 — clear the credential; `confirm` must equal the exact entry id; the
 * answer must name the exact entry as `none`. */
export function clearUpstreamCredential(
  id: string,
  confirm: string,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}/credential`,
    credentialBound(id, "none"),
    {
      method: "POST",
      body: { action: "clear", confirm, revision: entryRevision },
      ...sig(signal),
    },
  );
}

/** The appliance bounds each probe at 5 s and runs the entries
 * SEQUENTIALLY (`internal/upstream` probeTimeout — pinned in lockstep by
 * the Go side), so a manual run legitimately takes up to
 * entries x 5 s. */
export const PROBE_PER_ENTRY_MS = 5_000;
/** Headroom above the appliance's worst case for the answer itself. */
export const PROBE_DEADLINE_MARGIN_MS = 10_000;
const PROBE_DEADLINE_FLOOR_MS = 30_000;

/** The client deadline for a manual probe run over `entryCount` entries:
 * never below the default request deadline, never below the appliance's
 * sequential worst case plus the margin. A run the appliance is still
 * executing must not be aborted into an unproven outcome (PR-C9 K3). */
export function probeDeadlineMs(entryCount: number): number {
  const n = Number.isFinite(entryCount) && entryCount > 0 ? entryCount : 0;
  return Math.max(
    PROBE_DEADLINE_FLOOR_MS,
    n * PROBE_PER_ENTRY_MS + PROBE_DEADLINE_MARGIN_MS,
  );
}

/** POST /api/upstream/health — the bounded, audited manual probe run; the
 * answer must carry the explicit result (`ok: true`) and its counts-only
 * `summary`. `entryCount` is the read model's entry count (an upper bound
 * of the eligible entries the appliance will probe) and sizes the request
 * deadline. */
export function runUpstreamProbe(
  signal?: AbortSignal,
  entryCount = 0,
): Promise<UpstreamConfig> {
  return apiRequest(
    "/api/upstream/health",
    bound(
      "the explicit probe result with its summary",
      (cfg) => cfg.ok === true && cfg.summary !== undefined,
    ),
    { method: "POST", timeoutMs: probeDeadlineMs(entryCount), ...sig(signal) },
  );
}
