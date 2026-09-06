# Culvert Language & Terminology Governance Review — 2026-09-06

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..290e376` (315 commits — confirmed via both `git log --oneline | wc -l` and
> `git rev-list --count`, run twice against the unambiguous full commit hashes to rule out any abbreviation
> collision — 21 on the first-parent path, 240 files changed). Both figures are the largest this program has
> processed in one window: the commit count exceeds every prior review's, and the 240-file diff is itself
> larger than 08-25's previous high-water mark (the 154-file MCP Shadow-execution drop). The window is
> dominated by the continuation of that same MCP
> program: Shadow soak/exit-gap closure, the MCP tool-trust approval slice (ADR-0034), the MCP kill
> boundary, and the first Canary-tier work (activation gate, architecture, admission fairness rollback,
> physical-effect-truth evidence preservation) plus three "Live"-tier PRs (execution trust, tier
> composition, production deps). Method: (1) full-repo grep for every `# ADR-NNNN` / `ADR-NNNN:` header
> across `docs/adr/` and `docs/support/rfc/` — the check this program's own 08-24/08-25 recommendation asks
> future reviews to run every time, given the defect class has now recurred three times; (2) diffed
> `metrics.go` for new Prometheus families and checked the new `culvert_mcp_shadow_*` pair
> (`mcp_shadow_metrics.go`) against every existing `culvert_mcp_*` family for a same-word collision; (3)
> checked every one of the fourteen still-open carry-over finding IDs' dependent files against this
> window's changed-file list (240 files) — none intersect (including root `policy.go`, `metrics.go`'s own
> pre-existing clam/scan lines, `admin_settings.go`, `config.go`, `internal/sealbox`, and the connlimit/
> catfeed/urlcatfeed files T-30/T-31/T-34 depend on — `metrics.go` itself *was* touched this window, but
> only by one new fan-out line for the Shadow metrics, nowhere near the clam/remote-scan series T-31
> concerns); (4) spot-checked the new `docs/adr/0035-mcp-canary-execution-architecture.md` and
> `docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md` for fresh Canary/Shadow/Live vocabulary collisions
> against the existing three-tier pipeline language — none found, the tier names stay disjoint and
> consistently ordered (Disabled → Observe → Shadow → Canary → Production) everywhere sampled.
> **Companion change:** one fix ships with this review — a fourth ADR-numbering collision, found on `0034`.

---

## Executive Summary

**One finding, fully fixed: a fourth recurrence of the ADR-numbering-collision defect class (T-16 →
T-46 → T-47 → this pass), and the fastest one yet.** The 08-25 review renamed
`docs/support/rfc/0032-ai-receives-normalized-evidence.md` to `0034` after confirming that number was
clean against every `# ADR-NNNN` header in the repository — true at that moment, 2026-08-25. Within
about three days, an independent PR stream (`claude/mcp-tool-trust-approval`) added
`docs/adr/0034-mcp-tool-trust-approval.md`, an ACCEPTED architecture decision dated 2026-08-28, reclaiming
the same number a third time running. This is the fastest recurrence of the three fixed so far (T-46 and
T-47 each surfaced roughly a review-cycle apart; this one landed inside the very next handful of merges),
and the collision is also the most expensive one this program has found to date on the *keeper* side: the
new `docs/adr/0034-mcp-tool-trust-approval.md` is cited by name across more than 45 call sites — nine root
`package main` files, five `internal/mcp/*` packages, three `docs/design/mcp/` documents, one operator
runbook, and the technical-debt register — because it landed mid-stream in the same MCP program that has
been growing for two months. Renumbering *that* document would have been a large, error-prone edit; the
much smaller, one-paragraph, still-unadopted RFC is once again the cheaper side to move.

**Fix, same precedent a fourth time:** the established, ACCEPTED `docs/adr/` decision keeps `0034`; the
not-yet-adopted RFC-track document (`docs/support/rfc/`, still carrying its original "PROPOSED — NOT
ADOPTED" status from 2026-07-13, and now on its *third* number in three consecutive reviews — `0018` →
`0032` → `0034` → `0036`) is renumbered to `0036`, confirmed clean against every `ADR-NNNN` header in the
repository including both new files this window added (`0034`, `0035`).
`docs/support/rfc/0034-ai-receives-normalized-evidence.md` → `0036-ai-receives-normalized-evidence.md`,
header updated, and the four downstream citations that genuinely mean the RFC's topic (AI receives
normalized findings, not raw bundles by default) updated to match: `docs/adr/0016-raw-evidence-vs-
normalized-findings.md` (1 "Relates to" line), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3 call sites: the
raw-plane-summary line, the pipeline-step-8 line, and the §6 section heading), and
`docs/support/SUPPORTABILITY-THREAT-MODEL.md` (the `T-PROMPT` row). All 45+ citations of "ADR-0034" that
mean the MCP tool-trust decision (`ui_mcp_tooltrust.go`, `mcp_tooltrust.go`, `main.go`, `ui_routes_meta.go`,
`ui_mcp.go`, `mcp_shadow_preflight.go`, `internal/mcp/catalog/*`, `internal/mcp/tooltrust/*`,
`internal/mcp/mcperr/mcperr.go`, `internal/mcp/execution/discovery.go`,
`internal/mcp/policy/antiweakening_tooltrust_test.go`, `docs/adr/0035-...md`,
`docs/design/mcp/SHADOW-ACTIVATION.md`, `docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md`,
`docs/operator/mcp-tool-trust-approvals.md`, `docs/engineering/TECHNICAL-DEBT-REGISTER.md`) were read and
verified to genuinely mean the tool-trust document, and were left untouched. The prior review's own dated
report (`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`) is left unedited as a point-in-time historical
record, per this program's existing convention of never rewriting past dated reports.

**The new `culvert_mcp_shadow_evaluations_total` / `culvert_mcp_shadow_evaluation_errors_total` pair
(`mcp_shadow_metrics.go`) was checked against every existing `culvert_mcp_*` family for a same-word
collision** — the same check the 08-25 review ran on `culvert_mcp_telemetry_composed`. No collision: the
`_shadow_` infix is unique among current `culvert_mcp_*` series, the two metrics are additive (wired via
one new `writeMCPShadowMetrics(&ruleMetBuf)` fan-out line in `metrics.go`, unrelated to any prior series),
and the naming pattern (`<subsystem>_<tier>_<noun>_total`) matches the established convention. Recorded as
a clean same-window check, not a finding.

**Terminology Health Score: 8.5 / 10** (down slightly from 8.6). The fix itself is, again, complete,
same-day, and zero-risk — a docs-only rename of an unadopted one-page RFC with four downstream citations.
The score moves down, not up, because the defect class's recurrence rate is now *accelerating*: this is the
fourth instance in six weeks, the third involving the exact same "just-freed number" trap the 08-25 review
already flagged, and this time the gap between the fix that freed a number and the next PR stream claiming
it was roughly three days — not a review cycle. The keeper side of this collision was also markedly more
expensive to audit (45+ citations vs. single digits in the three prior instances), which is a preview of
what a *wrong-side* renumbering mistake would cost were a future reviewer to miss one. The process
recommendation below is therefore escalated from "record for the ADR-process owner to consider" to "the
cost-benefit case for a mechanical reservation check has now tipped."

---

## Escalated Recommendation: an ADR-number reservation convention (fourth occurrence)

This is the fourth occurrence of the identical defect class (T-16 → `0008`–`0011` vs. main sequence; T-46 →
first `0018` collision; T-47 → first `0032` collision, ~1 day after its own freeing fix; this pass → second
`0032`-lineage collision, on `0034`, ~3 days after its freeing fix). The interval between a number being
freed and a new stream claiming it has now shrunk twice in a row (review-cycle → 1 day → 3 days), which is
the opposite of what "an occasional coincidence" should look like and consistent instead with a numbering
scheme under real, sustained pressure from a wide, fast-moving MCP program that adds new ADRs roughly every
one-to-two weeks. This program still cannot mechanically fix the root cause by itself — it is a docs-only
terminology pass, not an owner of `docs/adr/0001-record-architecture-decisions.md` or of CI configuration —
but after a fourth recurrence in six weeks, each one cheaper to have prevented than to keep fixing, this
review upgrades the standing recommendation from "worth considering" to "worth doing before the fifth
one": either (a) a CI check that fails a PR introducing a `# ADR-NNNN`/`ADR-NNNN:` header duplicating an
existing one anywhere under `docs/adr/` or `docs/support/rfc/`, or (b) a documented convention of claiming
a number via a near-empty placeholder file at proposal time (so "the next number" is computed once, at
first commit, and never recomputed by a second stream mid-flight). Not added to the priority-ordered
backlog below because it remains a process recommendation, not a terminology-drift finding with a
mechanical rename fix — but it should not need a fifth occurrence to get picked up.

---

## Findings

### T-48 — Third recurrence of the ADR-numbering collision, this time on `0034` (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (Accepted, dated 2026-08-28, the MCP tool-trust
  source-of-truth/approval-purpose-binding decision — part of the same MCP Agent Security Gateway program
  as ADR-0024/0032/0033/0035) and `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (Proposed —
  Not Adopted, dated 2026-07-13, on its third number after two prior renumberings in T-46 and T-47).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, and — new for this instance — the most heavily cross-referenced document either side of any of
  the four collisions this program has fixed, with 45+ citations across code comments, admin-API route
  metadata, five `internal/mcp/*` packages, and three design documents); the RFC becomes ADR-0036.
- **Why the current naming was problematic:** identical root cause to T-16, T-46, and T-47 — a bare
  "ADR-0034" citation in `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous
  between two unrelated decisions (the MCP tool-trust approval primitive vs. the AI-input-normalization
  boundary), with no way to disambiguate from the number alone, and every reader or AI agent citing "ADR-
  0034" without also naming the file would land on whichever document they happened to open first.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0036` is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including
  both new files this window added (`0034`, `0035`).
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/adr/0016-raw-evidence-vs-normalized-
  findings.md` (1 "Relates to" citation), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3 citations),
  `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 4 files touched plus the rename, no code/API/GUI/config
  surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches T-16's, T-46's, and T-47's own priority — a documentation-identifier
  collision with no runtime/functional impact, but a real, recurring, and now visibly *accelerating* risk
  of a reader or an AI agent citing or acting on the wrong decision record).

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence)

All fourteen remaining previously-open finding IDs were re-checked against this window's 240-file changed
list; none of their dependent files appear in it, so each is re-confirmed open and unchanged with no
further diffing needed: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired), T-25
(residual), T-29, T-30, T-31, T-33, T-34, T-39. Full descriptions remain in the reports where each was
first raised and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid duplicating
unchanged text. Two of these merit an explicit note this pass rather than silent carry-forward: root
`metrics.go` *was* touched this window (the one-line `writeMCPShadowMetrics` fan-out addition quoted
above), but nowhere near the clam/remote-scan series T-31 concerns — verified by reading the diff in full,
not by name-matching; and root `policy.go` was not touched — the window's `policy.go` diffs are all under
`internal/mcp/runtime/` and `internal/mcp/rollout/`, a different, MCP-tool-call-scoped policy engine
unrelated to the root package's `PolicyAction`/access-rule evaluator T-11 and T-33 are about.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-48 is resolved in this pass and does not appear
on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also queued (process-level, not a mechanical rename, escalated this pass): the ADR-number reservation
convention described above.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass caught and fixed a new same-window collision (T-48) —
the fourth instance of a recurring defect class, closed at zero migration risk and zero compatibility
impact for the fourth time, but on its most heavily-cited "keeper" document yet and its fastest-recurring
interval yet (roughly three days between the number being freed and being reclaimed). It also verified, by
reading the actual diff rather than by name-matching, that the window's one new `culvert_mcp_*` metric
family is not a collision, and that neither of the two carry-over findings whose filenames appear to
"almost" intersect this window's diff (`metrics.go`, and the unrelated MCP-scoped `policy.go` files) are
actually affected. All fourteen still-open carry-over findings were re-confirmed unchanged. No cosmetic or
preference-driven renames were proposed. Given the accelerating recurrence of the ADR-numbering defect
class — four times in six weeks, with the gap between fix and re-collision shrinking each time — this
review escalates last cycle's process recommendation from "worth recording" to "worth acting on before a
fifth, possibly more expensive, occurrence."
