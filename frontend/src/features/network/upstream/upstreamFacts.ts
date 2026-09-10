// 2F-F — presentation facts derived from the server's enums ONLY. No copy
// here compensates for backend truth (C7): the effective mode, the
// credential state, the probe verdict and the coverage line are one-to-one
// renderings of what `GET /api/upstream` reports. Both `no_eligible_parent`
// and `direct_fallback` are critical; only `direct_fallback` says traffic
// is bypassing the chain (C11). Coverage is always "plain HTTP only" —
// nothing on this surface ever says "protected" or "fully chained".
import type {
  UpstreamCoverage,
  UpstreamCredentialState,
  UpstreamHealth,
  UpstreamMode,
} from "../../../api/upstream";

export type FactSeverity = "neutral" | "ok" | "warning" | "critical";

export interface ModeFacts {
  label: string;
  severity: FactSeverity;
  /** true ONLY for direct_fallback — a request has egressed direct */
  bypassing: boolean;
  /** the critical banner text, or null when no banner is due */
  banner: string | null;
}

export function modeFacts(mode: UpstreamMode): ModeFacts {
  switch (mode) {
    case "no_pool":
      return {
        label: "DIRECT (no pool)",
        severity: "neutral",
        bypassing: false,
        banner: null,
      };
    case "chained":
      return {
        label: "CHAINED",
        severity: "ok",
        bypassing: false,
        banner: null,
      };
    case "no_eligible_parent":
      return {
        label: "NO ELIGIBLE PARENT",
        severity: "critical",
        bypassing: false,
        banner:
          "No eligible parent proxy — every configured parent is unhealthy, circuit-open, or holds a credential that cannot be used. No plain-HTTP request has fallen back yet; the next one will egress direct (PX-2 fail-open).",
      };
    case "direct_fallback":
      return {
        label: "DIRECT FALLBACK",
        severity: "critical",
        bypassing: true,
        banner:
          "DIRECT FALLBACK ACTIVE — no parent proxy is eligible (down, circuit-open, or its credential is unusable). Plain-HTTP egress traffic is bypassing the parent-proxy chain.",
      };
  }
}

export interface CredentialFacts {
  label: string;
  severity: FactSeverity;
  /** the credential half of eligibility (C11) */
  eligible: boolean;
  detail: string;
}

export function credentialFacts(
  state: UpstreamCredentialState,
): CredentialFacts {
  switch (state) {
    case "none":
      return {
        label: "none",
        severity: "neutral",
        eligible: true,
        detail: "No credential material; the parent is used unauthenticated.",
      };
    case "configured":
      return {
        label: "configured",
        severity: "ok",
        eligible: true,
        detail:
          "A password is sealed under the node-local key and bound to this entry's id and authority.",
      };
    case "unusable":
      return {
        label: "unusable",
        severity: "critical",
        eligible: false,
        detail:
          "Sealed material exists but the node-local key (.upstream_cred_key) is missing or unreadable — never selected, never probed. Restore the original key file, or clear and re-enter the credential.",
      };
    case "mismatch":
      return {
        label: "mismatch",
        severity: "critical",
        eligible: false,
        detail:
          "The sealed material is bound to a different entry or authority — never selected, never probed. Clear it (Tier 3) and set a new credential.",
      };
    case "requiresReplacement":
      return {
        label: "requires replacement",
        severity: "critical",
        eligible: false,
        detail:
          "This entry is known to need a credential this node never held (restored from a backup or imported) — never selected, never probed, never sent unauthenticated. Replace it (Tier 2) or clear it (Tier 3).",
      };
  }
}

export interface HealthFacts {
  label: string;
  severity: FactSeverity;
}

export function healthFacts(
  h: Pick<UpstreamHealth, "status" | "reason">,
): HealthFacts {
  switch (h.status) {
    case "unprobed":
      return {
        label:
          h.reason === "credential_ineligible"
            ? "Unprobed (credential_ineligible)"
            : "Unprobed",
        severity: "neutral",
      };
    case "healthy":
      return { label: "Healthy", severity: "ok" };
    case "unhealthy":
      return { label: `Down (${h.reason})`, severity: "critical" };
  }
}

/** One line of backend-derived coverage truth per client path (PX-1). */
export function coverageLine(c: UpstreamCoverage): string {
  return `plain HTTP ${c.plainHttp} · CONNECT ${c.connect} · WebSocket ${c.websocket} · SOCKS5 ${c.socks5} — chaining covers the plain-HTTP forward path only`;
}
