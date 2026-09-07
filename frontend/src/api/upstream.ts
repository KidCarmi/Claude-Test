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
  };
};

// ── Refusals (structured, bounded) ──────────────────────────────────────────

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

export interface UpstreamRefusal {
  status: number;
  code: UpstreamRefusalCode;
  /** the server-owned facts (revision, id, authority, confirmValue, …) */
  current: Readonly<Record<string, unknown>>;
  count?: number;
  message: string;
}

function isRefusalCode(v: unknown): v is UpstreamRefusalCode {
  return typeof v === "string" && UPSTREAM_REFUSAL_CODES.some((c) => c === v);
}

/** Any bounded 2F-C/2F-D refusal — decoded from {error, code, current}.
 * An unknown code, a text/plain body, or a transport death is NEVER
 * classified as a known refusal. */
export function asUpstreamRefusal(err: unknown): UpstreamRefusal | null {
  const o = parsedBody(err);
  if (o === null || !(err instanceof ApiError) || err.status === undefined)
    return null;
  const code = o["code"];
  if (!isRefusalCode(code)) return null;
  const current = o["current"];
  const count = o["count"];
  return {
    status: err.status,
    code,
    current: isRecord(current) ? current : {},
    ...(typeof count === "number" ? { count } : {}),
    message: typeof o["error"] === "string" ? o["error"] : "",
  };
}

export interface UpstreamFence {
  status: 428 | 409;
  code: "precondition_required" | "stale";
  current: Readonly<Record<string, unknown>>;
  message: string;
}

/** The revision fence: 428 precondition_required / 409 stale with the
 * server-owned `current.revision`. */
export function asUpstreamFence(err: unknown): UpstreamFence | null {
  const r = asUpstreamRefusal(err);
  if (r === null) return null;
  if (r.code === "precondition_required" && r.status === 428)
    return {
      status: 428,
      code: r.code,
      current: r.current,
      message: r.message,
    };
  if (r.code === "stale" && r.status === 409)
    return {
      status: 409,
      code: r.code,
      current: r.current,
      message: r.message,
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

/** POST /api/upstream/entries — fenced on the DOCUMENT revision. */
export function createUpstreamEntry(
  spec: UpstreamEntrySpec,
  documentRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest("/api/upstream/entries", decodeUpstreamConfig, {
    method: "POST",
    body: specWire(spec, documentRevision),
    ...sig(signal),
  });
}

/** PUT /api/upstream/entries/{id} — fenced on the ENTRY revision. */
export function updateUpstreamEntry(
  id: string,
  spec: UpstreamEntrySpec,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}`,
    decodeUpstreamConfig,
    { method: "PUT", body: specWire(spec, entryRevision), ...sig(signal) },
  );
}

/** DELETE /api/upstream/entries/{id}?revision= — the token travels in the
 * QUERY only; there is no body. */
export function deleteUpstreamEntry(
  id: string,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}?revision=${encodeURIComponent(String(entryRevision))}`,
    decodeUpstreamConfig,
    { method: "DELETE", ...sig(signal) },
  );
}

/** T2 — seal a new password under the node-local key. The password is in
 * the body ONLY and is not retained by this client. */
export function replaceUpstreamCredential(
  id: string,
  password: string,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}/credential`,
    decodeUpstreamConfig,
    {
      method: "POST",
      body: { action: "replace", password, revision: entryRevision },
      ...sig(signal),
    },
  );
}

/** T3 — clear the credential; `confirm` must equal the exact entry id. */
export function clearUpstreamCredential(
  id: string,
  confirm: string,
  entryRevision: number,
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest(
    `/api/upstream/entries/${encodeURIComponent(id)}/credential`,
    decodeUpstreamConfig,
    {
      method: "POST",
      body: { action: "clear", confirm, revision: entryRevision },
      ...sig(signal),
    },
  );
}

/** POST /api/upstream/health — the bounded, audited manual probe run. */
export function runUpstreamProbe(
  signal?: AbortSignal,
): Promise<UpstreamConfig> {
  return apiRequest("/api/upstream/health", decodeUpstreamConfig, {
    method: "POST",
    ...sig(signal),
  });
}
