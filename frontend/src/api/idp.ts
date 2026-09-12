// FE-6A.1 — Identity Providers READ client: fail-closed runtime decoders
// over the frozen FE-6A.0 read models (ui_auth.go idpListReadModel /
// publicIdPProfile / idpClusterReadModel, idp_operations.go lookupReadModel
// / readModel, ui_auth_ldap.go apiIdPLegacyLDAP) and the where-used walk
// (policy_refs.go, type `idp`). READ ONLY: this module carries no create,
// update, delete, repair, test, import or credential call — the slice
// exposes none, and a read surface must not be able to reach one by accident.
//
// Secret boundary. The backend read models are secret-free BY CONSTRUCTION
// (publicIdPProfile rebuilds every sub-config from named non-secret fields;
// only the derived *Configured indicators survive). The browser enforces the
// same boundary independently: a response carrying a secret-bearing key at
// ANY depth (clientSecret, bindPassword, metadataXml, password, secret,
// ciphertext, sealed …) is a DECODE FAILURE — never rendered, never cached.
// The `oidc` / `saml` / `ldap` sub-configs stay open objects on the OpenAPI
// contract, so only the facts the surface renders are decoded from them; the
// rest is ignored after the secret sweep.
//
// Bounded vocabularies are decoded as enums and REFUSED when unknown — the
// surface never maps an unrecognised server state onto a rendered one.
import { apiRequest } from "./client";
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
import { decodeObjectReferences } from "./policy";
import type { ObjectReferences } from "./policy";

function opt<T>(
  o: Record<string, unknown>,
  key: string,
  read: Decoder<T>,
  path: string,
): T | undefined {
  return readOptional(read)(o[key], `${path}.${key}`);
}

/** A nullable Go slice: absent / null ⇒ []. */
function readStringsOrNull(v: unknown, path: string): readonly string[] {
  if (v === undefined || v === null) return [];
  return readArray(readString)(v, path);
}

// ── Vocabularies (server contract; ui_auth.go / idp_operations.go) ─────────

export const IDP_TYPES = ["oidc", "saml", "ldap"] as const;
export type IdPType = (typeof IDP_TYPES)[number];

export const IDP_DEGRADED_REASONS = [
  "corrupt_quarantined",
  "corrupt_not_quarantined",
] as const;
export type IdPDegradedReason = (typeof IDP_DEGRADED_REASONS)[number];

export const IDP_CLUSTER_STATES = ["published", "pending"] as const;
export type IdPClusterState = (typeof IDP_CLUSTER_STATES)[number];

export const IDP_AUDIT_SINKS = ["memory", "file"] as const;
export type IdPAuditSink = (typeof IDP_AUDIT_SINKS)[number];

export const IDP_OPERATION_STATES = [
  "pending",
  "committed",
  "aborted",
  "outcome_unknown",
] as const;
export type IdPOperationState = (typeof IDP_OPERATION_STATES)[number];

export const LEGACY_CUTOVER_DURABILITY = [
  "not_retired",
  "durable",
  "pending_reconciliation",
] as const;
export type LegacyCutoverDurability =
  (typeof LEGACY_CUTOVER_DURABILITY)[number];

export const LEGACY_CUTOVER_TRIGGERS = ["admin_api", "observed"] as const;
export type LegacyCutoverTrigger = (typeof LEGACY_CUTOVER_TRIGGERS)[number];

// ── Secret sweep ───────────────────────────────────────────────────────────

/** Keys that name write-only or at-rest secret material. Matched EXACTLY
 * (case-sensitive) at every depth — the derived indicator keys
 * (`clientSecretConfigured`, `bindCredentialConfigured`,
 * `inlineMetadataConfigured`) are distinct and never match. */
export const IDP_SECRET_KEYS: readonly string[] = [
  "clientSecret",
  "client_secret",
  "bindPassword",
  "bind_password",
  "metadataXml",
  "metadata_xml",
  "password",
  "pass_hash",
  "passHash",
  "secret",
  "ciphertext",
  "sealed",
  "totpSecret",
  "totp_secret",
];

/** Fail-closed guard: refuse a record (recursively) that carries any secret
 * key. The path names the offending key for the DecodeError only — the
 * VALUE is deliberately not echoed. */
export function refuseSecretKeys(
  v: unknown,
  path: string,
  keys: readonly string[] = IDP_SECRET_KEYS,
): void {
  if (Array.isArray(v)) {
    v.forEach((el, i) => {
      refuseSecretKeys(el, `${path}[${String(i)}]`, keys);
    });
    return;
  }
  if (!isRecord(v)) return;
  for (const k of Object.keys(v)) {
    if (keys.includes(k)) {
      throw new DecodeError(
        `${path}.${k}`,
        "no secret material (never reaches the browser)",
        "[redacted]",
      );
    }
    refuseSecretKeys(v[k], `${path}.${k}`, keys);
  }
}

// ── Models ─────────────────────────────────────────────────────────────────

export interface IdPOIDCFacts {
  issuer: string;
  clientId: string;
  /** derived write-only-secret indicator — never the value */
  clientSecretConfigured: boolean;
}

export interface IdPSAMLFacts {
  metadataUrl: string;
  /** derived write-only indicator for the inline metadata upload */
  inlineMetadataConfigured: boolean;
}

export interface IdPLDAPFacts {
  url: string;
  bindDn: string;
  /** derived write-only-secret indicator — never the value */
  bindCredentialConfigured: boolean;
}

export interface IdPProfile {
  id: string;
  name: string;
  type: IdPType;
  enabled: boolean;
  priority: number;
  /** server-minted ENTRY fencing token (≥1) */
  revision: number;
  /** provenance of the operation-identified create that produced the entry */
  operationId?: string;
  emailDomains: readonly string[];
  knownGroups: readonly string[];
  oidc?: IdPOIDCFacts;
  saml?: IdPSAMLFacts;
  ldap?: IdPLDAPFacts;
}

export interface IdPFleetRejection {
  /** bounded rejection class (publishRejectionClass), never the raw error */
  reason: string;
  at: string;
}

export interface IdPClusterFacts {
  state: IdPClusterState;
  publishedVersion: number;
  lastRejection?: IdPFleetRejection;
}

export interface IdPLedgerFacts {
  degraded: boolean;
  /** bounded class (unreadable | corrupt) when degraded */
  degradedReason?: string;
  retained: number;
  unresolved: number;
  capacity: number;
  auditSink: IdPAuditSink;
}

export interface IdPList {
  persisted: boolean;
  degraded: boolean;
  degradedReason?: IdPDegradedReason;
  /** base name of the quarantined file — PRESENCE is the rendered fact */
  quarantineEvidence?: string;
  /** content-derived registry DOCUMENT revision */
  revision: string;
  profiles: readonly IdPProfile[];
  scope: "cluster-synced";
  cluster: IdPClusterFacts;
  operations: IdPLedgerFacts;
}

export interface IdPOperation {
  operationId: string;
  state: IdPOperationState;
  action: string;
  actor: string;
  profileId: string;
  registryRevision: string;
  cutover: boolean;
  startedAt: string;
  audited: boolean;
  /** committed only: the durable success audit is still owed */
  auditState?: "pending";
  finishedAt?: string;
  /** aborted / outcome_unknown: the bounded refusal code (+ settlement suffix) */
  code?: string;
  committedRevision?: string;
}

export interface LegacyCutover {
  operationId: string;
  profileId?: string;
  profileName?: string;
  registryRevision?: string;
  actor: string;
  trigger: LegacyCutoverTrigger;
  at: string;
  durable: boolean;
}

export interface LegacyLDAP {
  present: boolean;
  /** present only: the legacy block is the live proxy-auth backend */
  active?: boolean;
  /** the DURABLE authority cutover has happened */
  retired: boolean;
  /** present only: retired OR an enabled registry LDAP profile exists */
  shadowed?: boolean;
  scope: "node-local";
  cutoverDurability: LegacyCutoverDurability;
  cutover?: LegacyCutover;
  url?: string;
  baseDn?: string;
  bindDn?: string;
  /** derived write-only-secret indicator — never the value */
  bindCredentialConfigured?: boolean;
}

// ── Decoders ───────────────────────────────────────────────────────────────

const decodeOIDCFacts: Decoder<IdPOIDCFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    issuer: opt(o, "issuer", readString, path) ?? "",
    clientId: opt(o, "clientId", readString, path) ?? "",
    clientSecretConfigured:
      opt(o, "clientSecretConfigured", readBoolean, path) ?? false,
  };
};

const decodeSAMLFacts: Decoder<IdPSAMLFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    metadataUrl: opt(o, "metadataUrl", readString, path) ?? "",
    inlineMetadataConfigured:
      opt(o, "inlineMetadataConfigured", readBoolean, path) ?? false,
  };
};

const decodeLDAPFacts: Decoder<IdPLDAPFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    url: opt(o, "url", readString, path) ?? "",
    bindDn: opt(o, "bindDn", readString, path) ?? "",
    bindCredentialConfigured:
      opt(o, "bindCredentialConfigured", readBoolean, path) ?? false,
  };
};

export const decodeIdPProfile: Decoder<IdPProfile> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const operationId = opt(o, "operationId", readString, path);
  const oidc = opt(o, "oidc", decodeOIDCFacts, path);
  const saml = opt(o, "saml", decodeSAMLFacts, path);
  const ldap = opt(o, "ldap", decodeLDAPFacts, path);
  return {
    id: field(o, "id", readString, path),
    name: field(o, "name", readString, path),
    type: field(o, "type", readEnum(IDP_TYPES), path),
    enabled: field(o, "enabled", readBoolean, path),
    priority: opt(o, "priority", readNumber, path) ?? 0,
    revision: field(o, "revision", readNumber, path),
    ...(operationId !== undefined ? { operationId } : {}),
    emailDomains: readStringsOrNull(o["emailDomains"], `${path}.emailDomains`),
    knownGroups: readStringsOrNull(o["knownGroups"], `${path}.knownGroups`),
    ...(oidc !== undefined ? { oidc } : {}),
    ...(saml !== undefined ? { saml } : {}),
    ...(ldap !== undefined ? { ldap } : {}),
  };
};

const decodeFleetRejection: Decoder<IdPFleetRejection> = (v, path = "$") => {
  const o = readRecord(v, path);
  return {
    reason: field(o, "reason", readString, path),
    at: field(o, "at", readString, path),
  };
};

const decodeClusterFacts: Decoder<IdPClusterFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  const lastRejection = opt(o, "lastRejection", decodeFleetRejection, path);
  return {
    state: field(o, "state", readEnum(IDP_CLUSTER_STATES), path),
    publishedVersion: field(o, "publishedVersion", readNumber, path),
    ...(lastRejection !== undefined ? { lastRejection } : {}),
  };
};

const decodeLedgerFacts: Decoder<IdPLedgerFacts> = (v, path = "$") => {
  const o = readRecord(v, path);
  const degradedReason = opt(o, "degradedReason", readString, path);
  return {
    degraded: field(o, "degraded", readBoolean, path),
    ...(degradedReason !== undefined ? { degradedReason } : {}),
    retained: field(o, "retained", readNumber, path),
    unresolved: field(o, "unresolved", readNumber, path),
    capacity: field(o, "capacity", readNumber, path),
    auditSink: field(o, "auditSink", readEnum(IDP_AUDIT_SINKS), path),
  };
};

/** The quarantine evidence is a BASE NAME by server contract
 * (filepath.Base). A value that could be a path is refused — no file path
 * ever reaches the browser. */
const readEvidenceBaseName: Decoder<string> = (v, path = "$") => {
  const s = readString(v, path);
  if (s === "" || s.includes("/") || s.includes("\\") || s.includes("..")) {
    throw new DecodeError(path, "quarantine evidence base name", "[redacted]");
  }
  return s;
};

export const decodeIdPList: Decoder<IdPList> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const degradedReason = opt(
    o,
    "degradedReason",
    readEnum(IDP_DEGRADED_REASONS),
    path,
  );
  const quarantineEvidence = opt(
    o,
    "quarantineEvidence",
    readEvidenceBaseName,
    path,
  );
  const rawProfiles = o["profiles"];
  return {
    persisted: field(o, "persisted", readBoolean, path),
    degraded: field(o, "degraded", readBoolean, path),
    ...(degradedReason !== undefined ? { degradedReason } : {}),
    ...(quarantineEvidence !== undefined ? { quarantineEvidence } : {}),
    revision: field(o, "revision", readString, path),
    profiles:
      rawProfiles === undefined || rawProfiles === null
        ? []
        : readArray(decodeIdPProfile)(rawProfiles, `${path}.profiles`),
    scope: field(o, "scope", readEnum(["cluster-synced"] as const), path),
    cluster: field(o, "cluster", decodeClusterFacts, path),
    operations: field(o, "operations", decodeLedgerFacts, path),
  };
};

export const decodeIdPOperation: Decoder<IdPOperation> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const auditState = opt(o, "auditState", readEnum(["pending"] as const), path);
  const finishedAt = opt(o, "finishedAt", readString, path);
  const code = opt(o, "code", readString, path);
  const committedRevision = opt(o, "committedRevision", readString, path);
  return {
    operationId: field(o, "operationId", readString, path),
    state: field(o, "state", readEnum(IDP_OPERATION_STATES), path),
    action: field(o, "action", readString, path),
    actor: field(o, "actor", readString, path),
    profileId: field(o, "profileId", readString, path),
    registryRevision: field(o, "registryRevision", readString, path),
    cutover: field(o, "cutover", readBoolean, path),
    startedAt: field(o, "startedAt", readString, path),
    audited: field(o, "audited", readBoolean, path),
    ...(auditState !== undefined ? { auditState } : {}),
    ...(finishedAt !== undefined ? { finishedAt } : {}),
    ...(code !== undefined ? { code } : {}),
    ...(committedRevision !== undefined ? { committedRevision } : {}),
  };
};

const decodeLegacyCutover: Decoder<LegacyCutover> = (v, path = "$") => {
  const o = readRecord(v, path);
  const profileId = opt(o, "profileId", readString, path);
  const profileName = opt(o, "profileName", readString, path);
  const registryRevision = opt(o, "registryRevision", readString, path);
  return {
    operationId: field(o, "operationId", readString, path),
    ...(profileId !== undefined ? { profileId } : {}),
    ...(profileName !== undefined ? { profileName } : {}),
    ...(registryRevision !== undefined ? { registryRevision } : {}),
    actor: field(o, "actor", readString, path),
    trigger: field(o, "trigger", readEnum(LEGACY_CUTOVER_TRIGGERS), path),
    at: field(o, "at", readString, path),
    durable: field(o, "durable", readBoolean, path),
  };
};

export const decodeLegacyLDAP: Decoder<LegacyLDAP> = (v, path = "$") => {
  const o = readRecord(v, path);
  refuseSecretKeys(o, path);
  const active = opt(o, "active", readBoolean, path);
  const shadowed = opt(o, "shadowed", readBoolean, path);
  const cutover = opt(o, "cutover", decodeLegacyCutover, path);
  const url = opt(o, "url", readString, path);
  const baseDn = opt(o, "baseDn", readString, path);
  const bindDn = opt(o, "bindDn", readString, path);
  const bindCredentialConfigured = opt(
    o,
    "bindCredentialConfigured",
    readBoolean,
    path,
  );
  return {
    present: field(o, "present", readBoolean, path),
    ...(active !== undefined ? { active } : {}),
    retired: field(o, "retired", readBoolean, path),
    ...(shadowed !== undefined ? { shadowed } : {}),
    scope: field(o, "scope", readEnum(["node-local"] as const), path),
    cutoverDurability: field(
      o,
      "cutoverDurability",
      readEnum(LEGACY_CUTOVER_DURABILITY),
      path,
    ),
    ...(cutover !== undefined ? { cutover } : {}),
    ...(url !== undefined ? { url } : {}),
    ...(baseDn !== undefined ? { baseDn } : {}),
    ...(bindDn !== undefined ? { bindDn } : {}),
    ...(bindCredentialConfigured !== undefined
      ? { bindCredentialConfigured }
      : {}),
  };
};

// ── Reads (GET only) ───────────────────────────────────────────────────────

export function getIdPList(signal?: AbortSignal): Promise<IdPList> {
  return apiRequest(
    "/api/idp",
    decodeIdPList,
    signal !== undefined ? { signal } : {},
  );
}

export function getLegacyLDAP(signal?: AbortSignal): Promise<LegacyLDAP> {
  return apiRequest(
    "/api/idp/legacy-ldap",
    decodeLegacyLDAP,
    signal !== undefined ? { signal } : {},
  );
}

/** Admin-only (uiRoutes GET /api/idp/operations/ = admin: the record names
 * the actor). Callers below admin must not issue it. */
export function getIdPOperation(
  operationId: string,
  signal?: AbortSignal,
): Promise<IdPOperation> {
  return apiRequest(
    `/api/idp/operations/${encodeURIComponent(operationId)}`,
    decodeIdPOperation,
    signal !== undefined ? { signal } : {},
  );
}

/** Where-used walk for one provider: the authentication rules whose
 * SSORequired providerRefs name it (running + active draft candidate) —
 * exactly the set a delete would be refused on (409 referenced). */
export function getIdPReferences(
  id: string,
  signal?: AbortSignal,
): Promise<ObjectReferences> {
  const qs = new URLSearchParams({ type: "idp", name: id });
  return apiRequest(
    `/api/objects/references?${qs.toString()}`,
    decodeObjectReferences,
    signal !== undefined ? { signal } : {},
  );
}
