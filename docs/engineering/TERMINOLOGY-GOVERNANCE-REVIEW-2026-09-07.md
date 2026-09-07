# Culvert Language & Terminology Governance Review — 2026-09-07

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..1b3d0e6` (362 commits, 22 on the first-parent path, 253 files changed,
> ~55,600 insertions — the largest window this program has processed since 08-25, spanning 2026-08-26
> through 2026-09-07 and dominated by the MCP Agent Security Gateway's Canary execution tier: tool-trust
> approval, admission fairness, the kill-boundary/kill-switch/Canary-abort taxonomy, canary activation
> gating, authoritative rollback, and live-production-dependency composition). Method: (1) full-repo grep
> for every `# ADR-NNNN` header across `docs/adr/` and `docs/support/rfc/` — the check this program's own
> 08-25 review recommended running every pass after three prior collisions on this exact defect class;
> (2) re-confirmed all sixteen still-open carry-over finding IDs against this window's 253-file changed
> list, distinguishing genuine dependent-file touches from unrelated changes to the same file (as the
> 08-25 review's T-33 note first established as a distinct check); (3) read the new
> `internal/mcp/canary/abort.go` and its "kill switch" / "kill boundary" / "Canary abort" taxonomy
> doc-comment in full against operator runbooks (`CANARY-FIRST-RUNBOOK.md`,
> `mcp-shadow-soak-report.md`) for a same-word, different-concept collision, given the window introduces
> three new "stop executing" vocabulary items in the same subsystem; (4) diffed `static/index.html`,
> `metrics.go`, and every new `internal/mcp/**/metrics*.go`/audit-event call site added in this window for
> new GUI labels, Prometheus series, and audit-event strings that might duplicate an existing concept
> under a different name.
> **Companion change:** one fix ships with this review — the fourth occurrence of the recurring
> ADR-numbering-collision defect, plus (new this pass) a permanent regression guard so a fifth occurrence
> fails `go test` instead of waiting for the next audit.

---

## Executive Summary

**One finding, fully fixed: the fourth recurrence of the ADR-numbering-collision defect class — and, per
the process recommendation the 08-25 review recorded for exactly this outcome, the underlying gap is now
closed with a mechanical guard instead of a fifth manual fix.** This window's MCP tool-trust-approval work
landed `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED, cited from seven other files across
`docs/operator/`, `docs/design/mcp/`, `docs/adr/0035`, and `docs/engineering/TECHNICAL-DEBT-REGISTER.md`),
reclaiming the exact number the 08-25 review had, the previous cycle, moved
`docs/support/rfc/0018-ai-receives-normalized-evidence.md` onto after the *third* collision. The two PR
streams — one renumbering an RFC out of the way of a freshly-vacated slot, the other independently
claiming the same slot for a new accepted decision a day or two later — never cross-referenced each other,
identical in shape to all three prior occurrences (T-16, T-46, T-47). **Fix, same precedent a fourth
time:** the established, ACCEPTED `docs/adr/0034-mcp-tool-trust-approval.md` keeps `0034`; the
proposed-not-adopted RFC is renumbered to `0036` (`0035` was independently claimed in the same window by
`docs/adr/0035-mcp-canary-execution-architecture.md`, confirmed clean via the same repo-wide grep before
use), with its header and the five genuine downstream citations that mean its topic (AI receives
normalized findings, not raw bundles) updated to match:
`docs/support/rfc/0034-ai-receives-normalized-evidence.md` → `0036-ai-receives-normalized-evidence.md`,
`docs/support/TAC-CLOUD-ARCHITECTURE.md` (three call sites: §3 prose, the §8 pipeline step, the §6 section
heading), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (the `T-PROMPT` row), and
`docs/adr/0016-raw-evidence-vs-normalized-findings.md`'s own "Relates to" line. Every other citation
pattern-matching "ADR-0034" in this window's diff (`docs/operator/mcp-tool-trust-approvals.md`,
`docs/design/mcp/SHADOW-ACTIVATION.md`, `docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md`,
`docs/adr/0035`, `TECHNICAL-DEBT-REGISTER.md`) was individually verified to genuinely mean the new,
accepted tool-trust decision and left untouched.

**This is the fourth occurrence of the identical root cause within eleven review cycles, two of the four
within about a day of the collision-clearing fix that immediately preceded them.** The 08-25 review
recorded the threshold explicitly: *"a fourth recurrence would be the point at which 'keep fixing it each
time it happens' stops being the cheaper option than 'stop it from happening.'"* That threshold is now
met, and this pass adds the mechanical guard it anticipated: `docs_adr_numbering_test.go`
(`TestADRNumberingIsUnique`) walks `docs/adr/` and `docs/support/rfc/` at `go test` time and fails on any
`# ADR-NNNN` header claimed by more than one file. This is a docs-scoped test in `package main` (matching
the repo's existing governance-test convention — `config_surfaces_test.go`, `ui_routes_meta_test.go` —
rather than a new CI job), verified failing against the pre-fix tree (reintroducing the duplicate `0034`
header trips it) and passing against the fixed tree. It does not require the CI-check-or-placeholder-file
convention the 08-25 review floated as one option; it is the cheaper mechanical alternative the same
review named as the other option, landed once the recurrence count justified the investment.

**A second, smaller signal was checked and left as an evidence update rather than a fix: T-33 has
compounded.** `internal/mcp/runtime/policy.go` gained a fourth non-conforming literal assignment to the
MCP runtime's internal `PolicyAction`/`PolicyReason` observation fields —
`rb.rec.PolicyAction = "BLOCKED_BY_EMERGENCY_KILL"` (line 111, confirmed absent at the 08-25 review's
audited commit, added by this window's kill-boundary work) — extending the exact pattern T-33 first
documented on 2026-08-02 (`"BLOCKED_BY_INSPECTION"`, `"REDACTION_FAILED"`, `"BLOCKED_BY_DURABILITY"`, and
a fourth pre-existing outlier, `"BLOCKED_BY_DECISION_STALE"`). Verified: still zero consumers repo-wide of
either field for any of these five values, so the compatibility-risk assessment this program has carried
since 08-02 ("None today; rises once a consumer exists") is unchanged in substance, only in the count of
non-conforming literals now sharing the field. Not promoted to fixed this pass, consistent with this
program's standing treatment of T-29 through T-33 — a behavioral source change to a security-relevant,
actively-developing subsystem is left to a dedicated PR rather than folded into a governance pass — but
the finding's evidence is updated below so the next reviewer (or the eventual dedicated PR) starts from
the current count, not the 08-02 one.

**Three same-window near-misses were checked by full reading and found NOT to be drift.** (1) The new
`internal/mcp/canary/abort.go` explicitly and deliberately distinguishes three "stop executing tool calls"
concepts that a careless reading could conflate: the **kill switch** (the emergency, capability-wide
admission-stop mechanism), the **kill boundary** (the last-check checkpoint immediately before an
irreversible tool call actually fires), and **Canary abort** / `AbortScope` (the request-vs-whole-Canary
blast-radius taxonomy deciding how much of a rollout a detected problem invalidates) — the file's own doc
comment states "Conflating the two is the mistake this taxonomy prevents," and operator docs
(`docs/design/mcp/CANARY-FIRST-RUNBOOK.md`, `docs/operator/mcp-shadow-soak-report.md`) use all three terms
consistently with these distinct meanings throughout. This is the same disciplined-naming pattern the
08-25 review found in `mcp_health_plane.go`, not a new instance of the thing this program exists to catch.
(2) The window's one new metric family, `culvert_mcp_shadow_evaluations_total` /
`culvert_mcp_shadow_evaluation_errors_total` (`mcp_shadow_metrics.go`), is cleanly namespaced against every
pre-existing `culvert_mcp_*` series with no label or name overlap. (3) The new audit-event family
(`mcp.tooltrust.{approve,reject,request,revoke}`, `shadow_exit_review_passed`, `mcp.rollback.request`) sits
alongside the pre-existing `mcp.rollout.rehearse-rollback`/`-authoritative` pair without colliding — a
rollback *request* and a rollback *rehearsal* are genuinely different actions, not two names for one.

**Terminology Health Score: 8.6 / 10** (unchanged from 08-25 in the headline number, but the composition
changed: the fourth ADR-numbering recurrence would ordinarily have been scored as a fresh same-window
collision like the third one was, but this pass also closes the standing process gap that made a fourth
occurrence possible, which the score model treats as a wash — one more instance of a known, now-mechanically-
guarded defect class, offset by that defect class becoming structurally unable to recur silently again.
The score does not rise because the sixteen-item carry-over backlog is unchanged in count, and one of
those sixteen, T-33, is trending the wrong direction — its non-conforming-literal count grew from three to
four in this window, the second consecutive window in which it grew rather than shrank.)

---

## Findings

### T-48 — Fourth recurrence of the ADR-numbering collision, this time on `0034` (new — fixed this pass, with a permanent guard)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED, part of this window's MCP tool-trust-approval
  slice, cited from `docs/operator/mcp-tool-trust-approvals.md`, `docs/design/mcp/SHADOW-ACTIVATION.md`
  (twice), `docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md`, `docs/adr/0035`, and
  `docs/engineering/TECHNICAL-DEBT-REGISTER.md` (twice)) and `docs/support/rfc/0034-ai-receives-normalized-
  evidence.md` (PROPOSED — NOT ADOPTED, the RFC the 08-25 review had just renumbered onto `0034` after the
  *third* collision, on `0032`).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, by far the more heavily cited of the two — seven citing files vs. the RFC's three); the RFC
  becomes ADR-0036 (`0035` independently claimed in the same window by
  `docs/adr/0035-mcp-canary-execution-architecture.md`).
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034"
  citation was ambiguous between two unrelated decisions (MCP tool-trust source-of-truth binding vs. the
  AI-input-normalization boundary) with no way to disambiguate from the number alone.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0036` is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass, including
  every file from this window.
- **Affected code:** none (the fix); `docs_adr_numbering_test.go` (new — the process fix, see below).
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only rename/citation update, 5 files) plus one small, additive
  Go test with no production code path (`docs_adr_numbering_test.go`, `package main`, reads only
  `docs/adr/` and `docs/support/rfc/` at test time).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium for the rename (matching T-16/T-46/T-47's own priority); the accompanying process
  fix is priced as part of the same small PR rather than a separate item, since it was the standing
  recommendation this exact finding class had already queued.

**Process fix, landed this pass:** `TestADRNumberingIsUnique` (`docs_adr_numbering_test.go`) scans every
`.md` file directly under `docs/adr/` and `docs/support/rfc/` for a `^#\s*ADR-(\d+)` header line and fails
if any number is claimed by more than one file, naming every offending path in the failure message. This
was verified failing against the pre-fix state (both `0034` files present) and passing against the fixed
tree. It closes the 08-25 review's "New Recommendation: an ADR-number reservation convention" — that
recommendation offered two options (a CI check, or a documented placeholder-claim practice); this is the
CI-adjacent option, implemented as a repo-native `go test` rather than a new workflow file, so it runs on
every PR through the existing Fast PR Gate's test run with no new CI wiring. It cannot prevent two branches
from independently choosing the same number before either merges (that would need the placeholder-claim
convention, still worth adopting if a fifth near-miss — caught before merge by a contributor running tests
locally — turns up), but it guarantees the collision can never again reach `main` undetected, which is the
failure mode all four prior occurrences shared.

---

## Carried-Over Findings

Fifteen of the sixteen previously-open finding IDs were re-checked against this window's 253-file changed
list and re-confirmed open and unchanged, several with files nominally associated with the finding
appearing in the changed list for unrelated reasons (verified by diff, not by absence, per the 08-25
review's established stronger-check pattern where a dependent file *is* touched): T-9, T-11, T-12
(`static/index.html` touched, but its one-line diff is an unrelated `review_required_tools` label swap —
see T-38's closure in the 08-25 review), T-13 residual, T-17, T-18, T-21 + T-32 paired
(`controlplane_server.go` touched for CHAOS-56 graceful-shutdown work, `static/index.html` for the same
unrelated label swap), T-25 residual, T-29 (`main.go` touched for CHAOS-56 shutdown escalation,
`metrics.go` for an unrelated `writeMCPShadowMetrics` fan-out line), T-30, T-31 (same unrelated `metrics.go`
touch as T-29), T-34, T-39 (`mcp_telemetry.go` touched, but for schema-v2 Shadow-evidence support unrelated
to the qualification-naming dispute). Full descriptions remain in the reports where each was first raised
and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid duplicating unchanged
text.

### T-33 — evidence updated (not fixed this pass; trend now two consecutive windows of growth)

- **Business concept:** unchanged from the 2026-08-02 finding — the MCP runtime's internal
  `PolicyAction`/`PolicyReason` observation-record fields (`internal/mcp/runtime`), documented to carry
  only the nine-action policy taxonomy and the dotted `MCP.POLICY.*`/`MCP.MANAGEMENT.*` reason-code
  taxonomy, but repeatedly overwritten with ad hoc literal strings for pre-policy and post-policy gate
  outcomes that never went through the policy engine.
- **New evidence this pass:** `internal/mcp/runtime/policy.go:111` now also assigns
  `rb.rec.PolicyAction = "BLOCKED_BY_EMERGENCY_KILL"` (paired with
  `rb.rec.PolicyReason = mcperr.ReasonRolloutEmergencyActive.Code()`), fired when this window's
  capability-wide emergency-kill switch is engaged after a record-only disposition was resolved but before
  it commits. Confirmed absent at the 08-25 review's audited commit (`e698a12`) via `git show`. This is the
  **fourth** non-conforming literal sharing the field, alongside `"BLOCKED_BY_INSPECTION"`,
  `"REDACTION_FAILED"`, `"BLOCKED_BY_DURABILITY"` (all from 08-02) and `"BLOCKED_BY_DECISION_STALE"` (added
  in a window between 08-02 and 08-25, not previously called out by number in a carry-over update).
- **Compatibility risk, re-verified:** still zero consumers repo-wide (code or test) of `PolicyAction` or
  `PolicyReason` reading any of these five values as a discriminator — the "None today; rises once a
  consumer exists" assessment from 08-02 holds, but the population of values a future consumer would have
  to handle correctly (or a dashboard grouped by the field would silently mis-bucket) has grown from three
  to five.
- **Why not fixed this pass:** unchanged reasoning — a behavioral source change to a security-relevant,
  actively-developing subsystem (this window alone landed the Canary kill-boundary, tool-trust-approval,
  and admission-fairness slices) is left to a dedicated PR rather than folded into a governance pass.
- **Recommended canonical name / fix:** unchanged from 08-02 — stop overwriting `PolicyAction`/
  `PolicyReason` for gate outcomes that never reached the policy engine; introduce a dedicated field (e.g.
  `GateAction`/`GateReason`) for the now five non-conforming cases, or leave the taxonomy fields unset when
  policy genuinely never ran.
- **Priority:** raised from Low-Medium to **Medium** — not because the risk profile changed (still zero
  consumers), but because the pattern has now grown in two consecutive review windows rather than holding
  steady, and each new kill/gate mechanism the Canary work adds is a plausible next site for a fifth
  literal absent a fix.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items except T-33's priority bump; T-48 is resolved in
this pass and does not appear on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-33 (carried over, priority raised) | Stop overwriting `PolicyAction`/`PolicyReason` for the now five pre-/post-policy gate cases; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists, and the non-conforming set has grown two windows running | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

No new process-level recommendation is queued this pass — the standing one (ADR-number reservation) is now
partially discharged by `TestADRNumberingIsUnique` (detection); the remaining half (pre-merge reservation,
to stop a collision from being *authored* rather than only catching it before it reaches `main`) is left
open for whoever owns `docs/adr/0001-record-architecture-decisions.md` to weigh against its cost, per the
08-25 review's framing.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass fixed the fourth recurrence of a known defect class at
the same trivial migration cost as the prior three, and — because a fourth recurrence was the explicit
threshold the previous review set for graduating from "fix it again" to "stop it from recurring" — also
landed a permanent, zero-cost regression guard (`TestADRNumberingIsUnique`) so a fifth occurrence fails
`go test` on the offending PR instead of surfacing at the next scheduled audit. It also verified, by full
reading rather than by name-matching, that three same-window near-misses in the new MCP Canary vocabulary
(the kill-switch/kill-boundary/Canary-abort taxonomy, the new Shadow-evaluation metric family, and the new
tool-trust/rollback audit-event names) are deliberately distinct concepts, not drift. All fifteen unaffected
carry-over findings were re-confirmed unchanged by diff, and the sixteenth, T-33, was found to have grown
by one more non-conforming literal in this window — its evidence is updated and its priority raised, though
it is not fixed this pass, consistent with this program's standing treatment of behavioral changes to an
actively-developing security-relevant subsystem. No cosmetic or preference-driven renames were proposed.
