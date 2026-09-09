# Culvert Language & Terminology Governance Review — 2026-09-09

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..43f95b2` (426 commits, 27 on the first-parent path — the largest window
> this program has processed, roughly a 2-week gap since the 2026-08-25 review; no review ran in the
> interim). Method: (1) full-repo scan for every `# ADR-NNNN` header (the program's now four-times-recurring
> defect class) — found and fixed a new collision; (2) re-confirmed all fourteen still-open carry-over
> findings (T-9, T-11, T-12, T-13 residual, T-17, T-18, T-21+T-32, T-25 residual, T-29, T-30, T-31, T-33,
> T-34, T-39) by direct grep against each finding's named identifiers/files, not by file-list absence alone;
> (3) inspected the highest-signal new files in the window (the MCP Canary/Live-tier/Tool-Trust program,
> ~22k new lines, ADR-0034/0035) for the classic same-word/two-concepts collision shape; (4) read the new
> frontend's Decryption surface end-to-end (`DecryptionPage.tsx`, `AutoExclusionsTab.tsx`,
> `DecryptionProfilesPage.tsx`) after an independent same-day sweep flagged a candidate there; (5) checked
> `docs/design/PRODUCT-TERMINOLOGY.md`, `docs/design/INFORMATION-ARCHITECTURE.md`, and
> `docs/design/FRONTEND-MIGRATION-PLAN.md` against two other same-day candidates before touching anything —
> one candidate (a legacy-GUI nav-label change) was reverted after that check showed the existing name was a
> **documented, deliberate** choice, not drift (see the "False start" note below).
> **Companion changes:** three fixes ship with this review.

---

## Executive Summary

**Three fixes this pass, one of them the program's signature catch for the fourth time.**

1. A **new ADR-0034 collision** — `docs/adr/0034-mcp-tool-trust-approval.md` (Accepted, wired into ~50 code
   sites) landed in this window and reclaimed the number `docs/support/rfc/0034-ai-receives-normalized-
   evidence.md` had only just been renumbered to by the 2026-08-25 review after an *identical* collision on
   0032. Same precedent as T-16, T-46, and T-47: the accepted, deeply-wired `docs/adr/` decision keeps its
   number; the not-yet-adopted RFC is renumbered again, this time to `0036` (confirmed clean against every
   ADR header in the repo). Fixed: the RFC's own header plus five downstream citations
   (`docs/support/TAC-CLOUD-ARCHITECTURE.md` ×3, `docs/support/SUPPORTABILITY-THREAT-MODEL.md`,
   `docs/adr/0016-raw-evidence-vs-normalized-findings.md`). **This is the fourth recurrence of the identical
   defect class, and the second time the fix itself was re-collided within days of being applied** (0032→0034
   on 08-25, then 0034 reclaimed within the same review's own audited window). The process-level
   recommendation the 08-25 review logged — a CI check or number-reservation convention for `docs/adr/` — is
   restated below with more urgency; "keep fixing it each time" has now failed to hold for even one full
   review cycle twice in a row.

2. **A new same-window finding, found and fixed: the new React admin frontend contradicts itself about one
   tab's name.** `frontend/src/features/security/DecryptionPage.tsx` names the auto-learned decryption-
   exclusion-cache tab **"Auto-Exclusions,"** and `AutoExclusionsTab.tsx`'s own header comment uses the same
   name — but `frontend/src/features/objects/DecryptionProfilesPage.tsx:496`, in the *same* frontend, cross-
   references the identical feature as "the Decryption Exclusions surface." This is not the familiar
   old-GUI-vs-new-GUI migration drift this program has recorded before (T-13-class) — it is the new frontend
   disagreeing with itself, one component citing another's tab under a name that tab does not use. Fixed:
   reworded the callout in `DecryptionProfilesPage.tsx` to say "the Auto-Exclusions tab (Decryption page)."
   `frontend/dist` was rebuilt with the pinned Node 24.19.0/npm 11.17.0 toolchain (checksum-verified) and
   passed the full `npm run verify` contract (787 unit tests, lint, format, strict typecheck) plus the
   determinism gate (2 isolated clean builds, byte-identical root hash) before committing.

3. **T-31 (carried over since 2026-08-01, fixed this pass).** `culvert_clam_scan_errors_total` is the one
   metric in the ClamAV family still using the "clam" short form while every sibling
   (`culvert_clamav_blocked_total`, the GUI, the operator runbook prose) says "clamav." Dual-emitted a new
   `culvert_clamav_scan_errors_total` counter carrying the identical value (`metrics.go`); the original name
   is kept permanently for wire compatibility with any existing dashboard or alert rule (same "kept
   permanently, no consumer asked to migrate" pattern the 08-25 review used for T-38's `drifted_tools`). No
   test or operator doc previously locked the old name exclusively, so no migration is forced.

**A false start, caught before it shipped.** An independent same-day terminology sweep (not backlog-aware)
flagged the legacy GUI's "Administrators" nav label as inconsistent with the API/audit noun "users." Before
acting, this review checked `docs/design/PRODUCT-TERMINOLOGY.md`, which documents exactly this term:
*"Administrator | A console account (admin/operator/viewer role) | 'Users & Roles' → 'Administrators'
(avoids collision with proxy users/identities)."* The existing name is a **deliberate, already-adopted**
disambiguation against a real ambiguity this program cares about (console accounts vs. proxied end-user
identities) — renaming it back toward "Users" would have reintroduced the collision it was created to avoid.
Reverted before commit. Recorded here because it is exactly the failure mode this program exists to prevent
in the other direction: fixing on pattern-matching alone, without checking whether the current name is
already a considered decision.

**A second same-day candidate was checked against design docs and found to be a genuine but non-mechanical
gap, matching the class this program declines to force (T-13 precedent).** The legacy GUI says "Content &
Scanning" (`static/index.html`, `docs/design/INFORMATION-ARCHITECTURE.md:68` records this as a *deliberate*
rename away from "Security"); the new frontend's `ContentSecurityPage.tsx` says "Content Security"
(`docs/design/FRONTEND-MIGRATION-PLAN.md` records this as the deliberate 2E-A slice decision, "nav: Security
→ Content Security"). Both are documented, deliberate choices made by different design passes that never
cited each other, and `FRONTEND-FEATURE-PARITY.md` still anchors the surface to the old name with no updated
row. This is a naming-policy reconciliation between two design documents, not a mechanical rename — recorded
as a new soft finding below, not queued to the numbered backlog (consistent with how T-13's "TLS Inspection"
branding question has been carried as a residual rather than forced).

Also checked and found NOT to be drift: the ~22k-line MCP Canary/Live-tier/Tool-Trust addition in this
window uses "live tier," "tool trust," and canary-path routes in ways that are consistently
cross-referenced and self-disambiguating at every call site inspected — the same authors-caught-it-themselves
pattern the 08-25 review recorded for `culvert_mcp_telemetry_composed`.

**Terminology Health Score: 8.7 / 10** (up from 8.6). Three concrete fixes landed this pass — one long-queued
Low-risk backlog item (T-31) closed at zero migration risk, one genuine new same-window collision (the 4th
occurrence of the ADR-numbering class) caught and fixed, and one new same-window frontend self-contradiction
caught and fixed — plus a false-start reversal that demonstrates the review checking documented intent before
acting, not just pattern-matching. The score does not move further because: the fourteen-item carry-over
backlog is entirely unchanged (re-confirmed by direct grep, not just absence from the diff), and the
ADR-numbering defect class's second same-review-cycle recollision is a *worsening* signal on the underlying
process gap, not a neutral one.

---

## Recommendation, restated with more urgency: an ADR-number reservation convention

This is now the **fourth** occurrence of the identical defect (T-16 → 0008–0011 vs. main sequence; T-46 →
first `0018` collision; 2026-08-25 → `0032` collision; today → `0034` collision, discovered within the same
audited window as the process that created the available slot). Every occurrence shares the same root cause:
two independent PR streams each compute "the next free number" by grepping the tree at the moment they need
one, with no mechanism to claim a number before a document merges. The 08-25 review recorded this as a
recommendation for whoever owns `docs/adr/0001-record-architecture-decisions.md` to consider. It is repeated
here, more urgently, because the fix has now been re-collided with **twice in a row** — once within about a
day (08-25), once within the very next audited window (today). A docs-only terminology pass cannot add CI
enforcement itself; the two mechanical options remain (a) a CI check that fails a PR introducing a duplicate
`# ADR-NNNN` header, or (b) a documented practice of reserving a number via a near-empty placeholder file at
proposal time. **A fifth recurrence would mean the "fix it each time" strategy has failed on its own terms
three times running** — this review recommends the next occurrence (or this one) be the trigger to actually
land (a), since it is the cheaper of the two to implement and enforces the invariant this program keeps having
to restore by hand.

---

## Findings

### T-48 — Fourth recurrence of the ADR-numbering collision, this time on `0034` (new — fixed this pass)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (Accepted 2026-08-28, part of the MCP Canary/Tool-Trust program,
  cited from `docs/design/mcp/SHADOW-ACTIVATION.md`, `docs/design/mcp/CANARY-ACTIVATION-GATE-REPORT.md`,
  `docs/adr/0035-mcp-canary-execution-architecture.md`, `docs/operator/mcp-tool-trust-approvals.md`, and
  `docs/engineering/TECHNICAL-DEBT-REGISTER.md`) and `docs/support/rfc/0034-ai-receives-normalized-
  evidence.md` (Proposed — NOT ADOPTED, dated 2026-07-13, renumbered to 0034 only three days earlier by the
  2026-08-25 review's own T-47 fix).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (Accepted,
  extensively cross-referenced, expensive to move); the RFC becomes ADR-0036.
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034" citation
  was ambiguous between two unrelated decisions (MCP tool-trust approval vs. the AI-input-normalization
  boundary) with no way to disambiguate from the number alone.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision; `0036`
  is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass.
- **Affected code:** none.
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (docs-only, 5 files, no code/API/GUI/config surface).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (matches the prior three occurrences' priority — a documentation-identifier collision
  with no runtime/functional impact, but now a demonstrated four-times-recurring risk of a reader or an AI
  agent citing or acting on the wrong decision record).

### T-49 — New admin frontend's Decryption surface disagrees with itself about the exclusion-cache tab's name (new — fixed this pass)

- **Business concept:** the volatile, runtime-learned decryption-exclusion cache (fail-open auto-learn,
  `internal/autoexclude`).
- **Current names before this fix:** `frontend/src/features/security/DecryptionPage.tsx:25,66` and
  `AutoExclusionsTab.tsx:1` (comment header) name the tab **"Auto-Exclusions."**
  `frontend/src/features/objects/DecryptionProfilesPage.tsx:496`, in the same frontend, cross-references the
  identical feature as "the Decryption Exclusions surface."
- **Recommended canonical name:** "Auto-Exclusions" (the tab's own name) — the cross-reference was the
  outlier, not the tab.
- **Why the current naming was problematic:** unlike the well-documented old-GUI-vs-new-GUI migration drift
  this program tracks separately (see the "Content & Scanning" vs. "Content Security" finding below), this
  is the *same* frontend codebase, in the same feature area, citing its own sibling component under a name
  that component does not use — an admin following the callout's link text would be looking for a tab
  labeled "Decryption Exclusions" and would not immediately recognize "Auto-Exclusions" as the same thing.
- **Why the new name is better:** removes the internal contradiction with zero net renaming — one string
  changed to match an existing, unambiguous label one file away.
- **Affected code:** `frontend/src/features/objects/DecryptionProfilesPage.tsx` (1 line).
- **Affected API:** none.
- **Affected GUI:** the Decryption Profiles page's fail-open callout text; rebuilt `frontend/dist` (Node
  24.19.0/npm 11.17.0, checksum-verified; `npm run verify` — 787 tests, lint, format, typecheck — and the
  2-build determinism gate all passed before commit).
- **Affected Documentation:** none.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (one string, no compat surface — the experimental new frontend is
  disabled by default via `CULVERT_EXPERIMENTAL_UI`).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (confusing but confined to a disabled-by-default preview surface with no external
  consumers yet).

### T-31 — ClamAV scan-error metric was the one series in its family still using the "clam" short form (carried over since 2026-08-01 — fixed this pass)

- **Business concept:** a mid-request ClamAV scan failure (content forwarded unscanned, fail-open).
- **Current names before this fix:** `culvert_clamav_blocked_total` (metrics.go:719-721) and the GUI/operator
  runbook prose all say "clamav"; the scan-error counter alone said `culvert_clam_scan_errors_total`
  (metrics.go:727-729).
- **Fix:** dual-emitted `culvert_clamav_scan_errors_total`, carrying the identical value
  (`scanCounters.ClamScanError`) as the pre-existing `culvert_clam_scan_errors_total`, which is kept
  permanently for wire compatibility with any existing dashboard/alert (`docs/operator/scan-capacity-and-
  timeouts.md`'s PromQL examples continue to work unmodified). No consumer is asked to migrate.
- **Verification:** `go build ./...` clean, `go vet .` clean (confirms the `Fprintf` format/arg count still
  matches after the insertion), `gofmt -l metrics.go` clean, and the full in-repo metrics test set
  (`TestMetrics_*`, `TestURLCatMetrics_*`, `TestChaos54_MetricsAppearOnlyWhenConfigured`,
  `TestChaos50_MetricsExposeLoadPosture`, etc.) passes unchanged.
- **Affected code:** `metrics.go` (2 new lines + 1 new Fprintf argument).
- **Affected API:** `GET /metrics` (additive series; `culvert_clam_scan_errors_total` unchanged).
- **Affected GUI:** none directly (the GUI reads via the JSON stats API, not `/metrics`, for this counter).
- **Affected Documentation:** none required (old name still valid); a future pass may choose to also mention
  the canonical name in `docs/operator/scan-capacity-and-timeouts.md`, left as-is here per the additive,
  minimal-diff precedent this fix follows.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (additive metric, zero breaking change).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low-Medium (matches the finding's own carried priority — a real but low-stakes naming
  inconsistency, open for five review cycles at zero fix cost once picked up).

### Soft finding (not queued) — "Content & Scanning" (legacy GUI) vs. "Content Security" (new frontend) are two separately-documented, separately-deliberate names for the same page

- **Business concept:** the admin page covering scan engines, IP filter, rate limiting, and log export
  (`data-view="security"`).
- **Current names:** legacy `static/index.html:826,6024` — "Content & Scanning," a deliberate rename away
  from bare "Security" per `docs/design/INFORMATION-ARCHITECTURE.md:68,123`. New frontend
  `frontend/src/features/security/ContentSecurityPage.tsx:1,43,49` — "Content Security," a deliberate 2E-A
  slice decision per `docs/design/FRONTEND-MIGRATION-PLAN.md:2659-2660,2688-2689`.
- **Why this is not a mechanical fix:** both names are documented, intentional product decisions made by
  different design passes; neither design document cites the other's rationale for the same surface.
  Overriding either one requires a product-naming judgment call between two considered alternatives, not a
  drift correction — the same class this program has previously declined to force for T-13's "TLS
  Inspection" vs. "SSL" branding question.
- **What would need to happen to resolve it:** the frontend migration owner decides whether "Content
  Security" or "Content & Scanning" is the terminology `docs/design/PRODUCT-TERMINOLOGY.md` should adopt
  as canonical (that document currently has no row for this concept at all), and
  `docs/design/FRONTEND-FEATURE-PARITY.md:59`'s stale anchor to the old name gets an updated row either way.
- **Not added to the numbered backlog** — recorded here as a flagged reconciliation gap between two design
  documents, consistent with how T-13's residual has been carried without a mechanical action item.

---

## Carried-Over Findings (unchanged — re-confirmed by direct grep, not file-list absence)

All fourteen remaining previously-open finding IDs were re-checked against this window's actual identifiers
and files (not merely absence from the 426-commit diff): **T-39** (`qualification_inventory_file`/
`qualification_telemetry`/`qualification_policy_file` unchanged in `mcp_observe_startup*.go`, `mcp_policy.go`,
`mcp_inventory.go`), **T-18** (`internal/sealbox.Seal`/`Open` unchanged), **T-21+T-32** (`cp_version`/
`snapshot_sha256` unchanged in `saas_feed_activation.go`, `cluster_convergence.go`, `static/index.html`),
**T-17** (`decryption_redact_hosts`/`/api/decryption/redaction` unchanged), **T-29** (`config.go` `yaml:
"rate_limit"`, `main.go` `-rate-limit` unchanged), **T-30** (`max_conns_per_ip`/`MaxConnsPerIP` unchanged),
**T-33** (root `Entry.PolicyAction`/`PolicyReason` unchanged; the MCP `internal/mcp/runtime/*.go`
`.PolicyAction` hits in this window's diff are confirmed the distinct MCP-tool-call-scoped field, not this
one), **T-25 residual** (`support_recipients.go`/`support_tac_trust.go` still separate), **T-9**
(`exportedAt` still present), **T-11** (`type PolicyAction string` unchanged), **T-12** (`/v1/upgrades/*`
unchanged), **T-34** (`apiURLCatFeedStatus` field names unchanged), **T-13 residual** ("TLS Inspection"
still in `README.md`). Full descriptions remain in the reports where each was first raised and in
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-31, T-48, and T-49 are resolved in this pass and
do not appear on the plan.

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
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also queued (process-level, not a mechanical rename, restated with more urgency this pass): the ADR-number
reservation convention.

Also flagged (design-document reconciliation, not a numbered backlog item): "Content & Scanning" vs.
"Content Security" — see the soft finding above.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass fixed a long-queued Low-Medium-priority backlog item
(T-31, open five review cycles) at zero migration risk, caught and fixed a new same-window collision (T-48)
— the fourth instance of a recurring defect class and the second time the *fix itself* recollided within
one review cycle — and caught and fixed a new same-window internal contradiction in the React admin frontend
(T-49). It also correctly declined to act on two other same-day candidates after checking documented design
intent: one ("Administrators") was already a deliberate, adopted disambiguation and the proposed change
would have reintroduced the exact collision it was created to avoid; the other ("Content & Scanning" vs.
"Content Security") is a genuine but non-mechanical reconciliation gap between two design documents, recorded
as a soft finding rather than forced. All fourteen still-open carry-over findings were re-confirmed unchanged
by direct grep against their named identifiers. No cosmetic or preference-driven renames were proposed. The
recurrence of the ADR-numbering defect class, now four times and twice within a single review cycle, is
restated as a process-level recommendation with increased urgency rather than re-litigated as a fifth ad-hoc
fix waiting to happen.
