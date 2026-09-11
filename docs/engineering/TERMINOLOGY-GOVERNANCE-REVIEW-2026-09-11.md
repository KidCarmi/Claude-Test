# Culvert Language & Terminology Governance Review — 2026-09-11

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `9775efd..574d265` — the window since the 2026-09-09 report's merge point,
> confirmed as the current `origin/main` HEAD by a fetch immediately before this report was written (per
> the DEBT-014 lesson the 2026-09-09 report recorded: sync against `main` right before opening a PR, not
> only at review-start, so a fix landed by a parallel branch is credited rather than re-claimed). The
> window covers 31 first-parent merges / 195 files / ~32.8k insertions, almost entirely the CHAOS-50
> through CHAOS-64 reliability/observability engineering sweep described in `CLAUDE.md` (new health
> subsystems: admin-UI listener recovery, credential-verification cost governance, cluster rate-limit
> freshness, DNS resolution health, GeoIP resolution health, LDAP directory stalls, request-history
> (logstore) recovery, threat-feed freshness, admin-login input bounds, plus the shared `storeguard`
> extraction) rather than admin-facing feature work.

---

## Executive Summary

**No new terminology drift found, and no new fixes made this pass.**

Two bounded audits were run against the diff since the last review:

1. **Cross-surface naming for every newly-added reliability subsystem** (`admin_ui_health.go`,
   `auth_cost_health.go`, `cluster_ratelimit_freshness.go`, `dns_health.go`, `geoip_resolve_health.go`,
   `internal/authcost`, `internal/feedsched`, `internal/logstore/resilient.go`,
   `internal/storeguard`, `login_input_bounds.go`, `logstore_health.go`, `maint_agent_status_api.go`,
   `threatfeed_health.go`, and their `docs/operator/*.md` counterparts). Every metric prefix, operator-
   contract row name, and doc title matches byte-for-byte across its `.go` source, its `metrics.go`
   HELP/TYPE registration, and its operator doc (`culvert_admin_ui_*`, `culvert_auth_verify_*`,
   `culvert_cluster_ratelimit_*`, `culvert_dns_resolve_*`, `culvert_geo_*`, `culvert_logstore_*`,
   `culvert_threat_feed_*`, `culvert_login_oversize_rejected_total`). `culvert_logstore_*` deliberately
   mirrors the pre-existing `culvert_catfeeddb_*` triple's shape for a different store — a documented,
   intentional pattern (`logstore_health.go`), not drift. Most of these subsystems have no independent
   GUI/API surface at all (internal reliability engines), which is not itself a finding.
2. **New `maint_agent_status_api.go` does not touch, worsen, or interact with the already-tracked T-12**
   (rename Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*`). It reads the agent's
   existing `/v1/status` endpoint only; `/v1/upgrades/*` is unchanged in this window
   (`cmd/culvert-maint/internal/server/handlers_upgrade.go:1,3,80`, spot-checked directly).
3. New `json:"..."` tags in the window (~26, mostly test-local) introduce no field-name collisions with
   existing concepts; new GUI/frontend strings in the window are small and consistent with their backing
   API (Maintenance Agent panel, threat-feed/credential-verification webhook-event labels).
4. `docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-29.md` — present in this diff window despite
   its earlier date, having landed via a separate branch (one more instance of the parallel-rediscovery
   pattern DEBT-014 already tracks) — was diffed against the 2026-09-09 report's carry-over list by
   T-number. No T-number present in 08-29's open-findings list is missing from 09-09's; T-49/T-50/T-51
   were explicitly fixed within 08-29's own pass (confirmed still live in `static/index.html`) and
   correctly excluded from carry-over.

**Spot-checked three carry-over items directly** to confirm they remain open and unchanged, rather than
trusting the diff-scope audit alone: T-13 (`docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md:1` still titled
"TLS Inspection Deployment"), T-29/T-30 (`rate_limit_rpm`/`conn_limit_max_per_ip` aliases still absent
from `config.go`), and T-12 (as above). All three are exactly as the prior reports left them.

**Terminology Health Score: 8.7 / 10** (unchanged from 2026-09-08/09-09). No new drift was introduced by
a 195-file, backend-heavy window, and no carry-over item moved — so the score neither rises nor falls.

---

## Carried-Over Findings (unchanged)

All twelve previously-open finding IDs remain open, unchanged, and re-confirmed against the current tree:
T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34,
T-39. Full descriptions and the priority-ordered refactoring plan are unchanged from
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-09.md` and are not restated here to avoid drift between two
descriptions of the same open items — see that report (or its predecessors, cited therein) for the
canonical text of each.

The "Content & Scanning" vs. "Content Security" soft finding (design-document reconciliation between two
deliberate naming decisions, not a mechanical rename) also remains unresolved and is not queued to the
numbered backlog, per 2026-09-09's reasoning.

---

## Stop-Condition Assessment

No production-worthy NEW terminology improvement was identified this pass: the 31-merge window audited
was backend reliability/observability engineering with disciplined internal naming (confirmed
cross-surface for every new subsystem) and no admin-facing vocabulary change. The twelve-item carry-over
backlog is unchanged and was independently re-confirmed (not merely assumed unchanged) for three of its
higher-visibility items. No cosmetic or preference-driven renames are proposed. This report itself — the
audit record and backlog reconciliation — is the deliverable of this pass; per the DEBT-014 process
lesson, it was written only after a fresh sync against `origin/main` immediately before opening its PR.
