// 2F-F — shared Upstream surface pieces: the revision-fence callout, the
// bounded-refusal callout and the UNPROVEN-outcome callout. Every refusal is
// rendered from TYPED, allowlisted facts the client validated (code with its
// contracted status, numeric revision, safe id/authority, enum credential
// state, counts) — never the server's `error` line, never the raw `current`
// record, never a stringified object (C7; 2F-F correction).
import type { JSX } from "react";
import { Callout, Mono } from "../../../design-system/primitives";
import type {
  UpstreamFence,
  UpstreamRefusal,
  UpstreamRefusalFacts,
} from "../../../api/upstream";

export const NODE_LOCAL_NOTE =
  "Node-local: entries, sealed credentials, probe verdicts and the effective mode live on this appliance only — never cluster-synced, never on config-version rollback. Exports and backups omit every credential by construction.";

export const COVERAGE_NOTE =
  "Chaining covers the plain-HTTP forward path only (PX-1): CONNECT, WebSocket and SOCKS5 client traffic always egresses direct.";

/** The revision fence rendered as fresh truth: nothing was changed. */
export function UpstreamFenceCallout({
  fence,
  tokenLabel,
}: {
  fence: UpstreamFence;
  tokenLabel: "document revision" | "entry revision";
}): JSX.Element {
  const shown = String(fence.revision);
  return (
    <Callout
      variant="warning"
      title={
        fence.code === "stale" ? "Stale write refused" : "Precondition required"
      }
      role="alert"
    >
      {fence.code === "stale"
        ? `The ${tokenLabel === "entry revision" ? "entry" : "pool document"} changed since you loaded it — the appliance refused (current revision ${shown}). Nothing was changed. Refresh, review again, then retry.`
        : `The appliance requires the ${tokenLabel} you loaded (current revision ${shown}). Nothing was changed.`}
    </Callout>
  );
}

/** What each bounded code MEANS, in the appliance's own terms. */
function refusalTitle(code: UpstreamRefusal["code"]): string {
  switch (code) {
    case "credential_bound":
      return "Refused — a credential is bound to this authority";
    case "credential_present":
      return "Refused — this entry still holds credential material";
    case "yaml_owned":
      return "Refused — owned by config.yaml";
    case "duplicate_authority":
      return "Refused — duplicate authority in the effective pool";
    case "document_rejected":
      return "Refused — the stored upstream document was rejected at load";
    case "vanished":
      return "The entry no longer exists";
    case "key_unusable":
      return "Refused — the node-local credential key is unusable";
    case "confirm_required":
      return "Refused — the typed confirmation did not match";
    case "no_credential":
      return "Nothing to clear";
    case "persist_failed":
      return "Not persisted — nothing was changed";
    case "seal_failed":
      return "Not sealed — nothing was changed";
    case "probe_in_flight":
      return "Manual probe already running";
    case "probe_rate_limited":
      return "Manual probe rate-limited";
    case "credentialed_entries_present":
      return "Refused — credentialed entries present";
    case "invalid_entry":
      return "Refused — the entry is invalid";
    case "userinfo_not_allowed":
      return "Refused — a proxy URL must not carry a username or password";
    case "credential_state_not_accepted":
      return "Refused — credential state is derived by the server";
    case "invalid_password":
      return "Refused — the password is required and at most 1024 bytes";
    case "invalid_action":
      return "Refused — invalid credential action";
    case "invalid_json":
      return "Refused — the request body was not accepted";
    case "precondition_required":
      return "Precondition required";
    case "stale":
      return "Stale write refused";
  }
}

/** The typed facts, rendered one by one — never a serialised object. */
function factLine(f: UpstreamRefusalFacts): string | null {
  const parts: string[] = [];
  if (f.authority !== undefined) parts.push(`authority ${f.authority}`);
  if (f.credentialState !== undefined)
    parts.push(`credential ${f.credentialState}`);
  if (f.revision !== undefined)
    parts.push(`current revision ${String(f.revision)}`);
  if (f.count !== undefined)
    parts.push(
      `${String(f.count)} duplicate authorit${f.count === 1 ? "y" : "ies"}`,
    );
  if (f.retryAfterSeconds !== undefined)
    parts.push(`retry after ${String(f.retryAfterSeconds)} s`);
  if (f.degradedReason !== undefined)
    parts.push(`degraded: ${f.degradedReason}`);
  if (f.index !== undefined) parts.push(`entry index ${String(f.index)}`);
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function UpstreamRefusalCallout({
  refusal,
}: {
  refusal: UpstreamRefusal;
}): JSX.Element {
  const facts = factLine(refusal.facts);
  const variant =
    refusal.code === "no_credential" || refusal.code === "vanished"
      ? "info"
      : refusal.status >= 500
        ? "critical"
        : "warning";
  return (
    <Callout variant={variant} title={refusalTitle(refusal.code)} role="alert">
      <div>
        <Mono>{refusal.code}</Mono> (HTTP {String(refusal.status)})
        {refusal.facts.id !== undefined ? (
          <>
            {" "}
            entry <Mono>{refusal.facts.id}</Mono>
          </>
        ) : null}
      </div>
      {facts !== null && <div>{facts}</div>}
      <div>
        Nothing was changed. Refresh to see the appliance&apos;s current state.
      </div>
    </Callout>
  );
}

export type UnprovenReason =
  | "transport"
  | "media_type"
  | "malformed_body"
  | "unbound_answer"
  | "unrecognised_refusal";

export interface UnprovenOutcome {
  action: string;
  reason: UnprovenReason;
  status: number | undefined;
}

function reasonText(r: UnprovenReason): string {
  switch (r) {
    case "transport":
      return "the request was sent but no answer was observed";
    case "media_type":
      return "the appliance answered with an unexpected media type";
    case "malformed_body":
      return "the appliance's answer was not valid JSON";
    case "unbound_answer":
      return "the appliance's answer did not carry evidence for this action";
    case "unrecognised_refusal":
      return "the appliance's refusal was not in the contracted form";
  }
}

/** An outcome the client could not verify: the mutation MAY be durably
 * applied. Never a success, never a failure — only the authoritative
 * read-back decides what the appliance now holds. */
export function UnprovenCallout({
  outcome,
  resolved,
}: {
  outcome: UnprovenOutcome;
  resolved: boolean;
}): JSX.Element {
  return (
    <Callout
      variant="unknown"
      title={`Outcome unproven — ${outcome.action}`}
      role="alert"
    >
      <div>
        The answer to this action could not be verified
        {outcome.status !== undefined
          ? ` (HTTP ${String(outcome.status)})`
          : ""}
        : {reasonText(outcome.reason)}. The change may already be applied on the
        appliance; nothing was retried.
      </div>
      <div>
        {resolved
          ? "The authoritative state has been re-read — review the entries below before acting again."
          : outcome.reason === "transport"
            ? "Refresh to re-read the authoritative state; every mutation stays blocked until a read succeeds."
            : "Re-reading the authoritative state; every mutation stays blocked until a read succeeds."}
      </div>
    </Callout>
  );
}
