// 2F-F — shared Upstream surface pieces: the revision-fence callout and the
// bounded-refusal callout. Every refusal is rendered from the STRUCTURED
// server body (code + the facts under `current`) — never re-worded into a
// claim the appliance did not make (C7).
import type { JSX } from "react";
import { Callout, Mono } from "../../../design-system/primitives";
import type { UpstreamFence, UpstreamRefusal } from "../../../api/upstream";
import { refusalCurrentNumber } from "../../../api/upstream";
import { isRecord } from "../../../api/decode";

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
  const n = refusalCurrentNumber(fence, "revision");
  const shown = n !== undefined ? String(n) : JSON.stringify(fence.current);
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

/** What each bounded code MEANS, in the appliance's own terms — the
 * server's `error` line is shown verbatim beside it. */
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
    case "userinfo_not_allowed":
    case "credential_state_not_accepted":
    case "invalid_password":
    case "invalid_action":
    case "invalid_json":
      return "Refused — invalid request";
    case "precondition_required":
      return "Precondition required";
    case "stale":
      return "Stale write refused";
  }
}

function factLine(r: UpstreamRefusal): string | null {
  const parts: string[] = [];
  const authority = r.current["authority"];
  if (typeof authority === "string") parts.push(`authority ${authority}`);
  const state = r.current["credentialState"];
  if (typeof state === "string") parts.push(`credential ${state}`);
  const count = r.count ?? refusalCurrentNumber(r, "count");
  if (count !== undefined)
    parts.push(
      `${String(count)} duplicate authorit${count === 1 ? "y" : "ies"}`,
    );
  const retry = refusalCurrentNumber(r, "retryAfterSeconds");
  if (retry !== undefined) parts.push(`retry after ${String(retry)} s`);
  const degraded = r.current["degraded"];
  if (isRecord(degraded) && typeof degraded["reason"] === "string") {
    parts.push(`degraded: ${degraded["reason"]}`);
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function UpstreamRefusalCallout({
  refusal,
}: {
  refusal: UpstreamRefusal;
}): JSX.Element {
  const facts = factLine(refusal);
  const variant =
    refusal.code === "no_credential" || refusal.code === "vanished"
      ? "info"
      : refusal.status >= 500
        ? "critical"
        : "warning";
  return (
    <Callout variant={variant} title={refusalTitle(refusal.code)} role="alert">
      <div>
        <Mono>{refusal.code}</Mono>
        {refusal.message !== "" ? ` — ${refusal.message}` : ""}
      </div>
      {facts !== null && <div>{facts}</div>}
      <div>
        Nothing was changed. Refresh to see the appliance&apos;s current state.
      </div>
    </Callout>
  );
}
