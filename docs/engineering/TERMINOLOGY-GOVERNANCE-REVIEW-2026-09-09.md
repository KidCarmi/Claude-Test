# Culvert Language & Terminology Governance Review — 2026-09-09

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method, and a correction made mid-review:** This review started by auditing `e698a12..43f95b2`
> (426 commits, 27 first-parent — the window since 2026-08-25, the last review visible on `main` at
> the time this review's branch was created) and found four fixes, including independently
> rediscovering the fourth ADR-numbering collision (`0034`) and the `culvert_clam_scan_errors_total`
> naming gap (T-31). Before this review's PR could be opened, `main` had already advanced past that
> window; a branch-sync merge (`git merge origin/main`) pulled in **five more governance reports this
> program had already produced on other branches** (`2026-08-28`, `2026-08-30`, `2026-09-05`,
> `2026-09-08`, plus their landed fixes) that were not visible when this review began. Both the ADR
> collision and T-31 were **already fixed and merged to `main`** by the time of that sync — this
> review's own copies of those two fixes were dropped by the merge as redundant, with zero net
> duplication reaching `main`. This report is being revised, post-merge, to credit the fixes that
> actually landed rather than re-claim them, and to keep only the findings that are genuinely new. See
> the "Reconciliation note" below for what this means and doesn't mean.
> **What's new in this report, still original to this review:** T-53 (the new React admin frontend
> contradicting itself about the "Auto-Exclusions" tab's name — not found by any prior review) and two
> legacy-GUI panel-title alignments (`static/index.html`'s Access Rules / Authentication Rules panels
> titling themselves "Active Policy Rules" / "Auth Policy Rules").

---

## Reconciliation note: this program independently rediscovers the same defect across parallel runs, and that is a known, tracked risk (DEBT-014)

`docs/engineering/TECHNICAL-DEBT-REGISTER.md`'s **DEBT-014** (opened by the 2026-09-05 review) already
names this exact pattern: this scheduled routine runs repeatedly and each run only sees `main` as it
stood when its branch was created, so two runs that start close together can independently find and
fix the identical defect, and if both open PRs, only one fix is needed but two (or, in T-48/ADR-0034's
case, five) get written. This review's branch is one more data point for that pattern — it independently
rediscovered the ADR-0034 collision and the T-31 metric-naming gap, both already diagnosed and fixed by
the 2026-08-28 and 2026-09-08 reports on other branches. The difference here: because this review's PR
had not yet been opened when the sync happened, `git merge origin/main` absorbed the already-merged
fixes and this review's redundant copies of them simply disappeared from the diff — no duplicate PR, no
wasted reviewer attention, no addition to DEBT-014's count. The lesson this review draws for future runs
of this program (recorded here, not as a new backlog item, since DEBT-014 already owns it): **sync
against `main` immediately before opening a PR, not only at review-start**, so a fix that landed
mid-review is credited instead of re-claimed. The two findings below are unaffected by this — they were
never touched by any other branch.

---

## Executive Summary

**Two genuinely new fixes this pass**, both confined to admin-facing GUI copy with zero API/compat
surface, both verified against the actual merged `main` (not a stale pre-sync snapshot):

1. **The new React admin frontend contradicts itself about one tab's name (T-53, new).**
   `frontend/src/features/security/DecryptionPage.tsx` names the auto-learned decryption-exclusion-cache
   tab **"Auto-Exclusions"** (`AutoExclusionsTab.tsx`'s own header comment uses the same name) — but
   `frontend/src/features/objects/DecryptionProfilesPage.tsx:496`, in the *same* frontend, cross-
   referenced the identical feature as "the Decryption Exclusions surface." This is not the familiar
   old-GUI-vs-new-GUI migration drift this program tracks separately (see the "soft finding" below) — it
   is the new frontend disagreeing with itself, one component citing another's tab under a name that tab
   does not use. Fixed: reworded the callout to say "the Auto-Exclusions tab (Decryption page)."
   `frontend/dist` was rebuilt with the pinned Node 24.19.0/npm 11.17.0 toolchain (checksum-verified
   against nodejs.org) and passed the full `npm run verify` contract (787 unit tests, lint, format,
   strict typecheck) plus the determinism gate (2 isolated clean builds, byte-identical root hash)
   before committing. Confirmed via `git merge`'s empty `frontend/` diff-stat that no other branch
   touched this file in the interim, so the fix and the rebuilt `dist` are both still current post-sync.

2. **Legacy GUI panel titles didn't match their own nav labels.** The Access Rules and Authentication
   Rules panels in `static/index.html` titled themselves "Active Policy Rules" / "Auth Policy Rules"
   while their own sidebar nav items — and the new React frontend's equivalent pages — call them "Access
   Rules" / "Authentication Rules," matching `docs/design/PRODUCT-TERMINOLOGY.md`'s documented "Rule"
   vocabulary (which explicitly replaces "policy rule" phrasing). Fixed: both panel titles now read
   "Access Rules" and "Authentication Rules."

**A false start, caught before it shipped.** An independent same-day terminology sweep (not
backlog-aware) flagged the legacy GUI's "Administrators" nav label as inconsistent with the API/audit
noun "users." Before acting, this review checked `docs/design/PRODUCT-TERMINOLOGY.md`, which documents
exactly this term: *"Administrator | A console account (admin/operator/viewer role) | 'Users & Roles' →
'Administrators' (avoids collision with proxy users/identities)."* The existing name is a **deliberate,
already-adopted** disambiguation against a real ambiguity this program cares about (console accounts vs.
proxied end-user identities) — renaming it back toward "Users" would have reintroduced the collision it
was created to avoid. Reverted before commit, and confirmed still reverted (i.e. "Administrators" is
still the live label) after the `main` sync.

**A soft, non-mechanical finding, checked but not force-fixed.** The legacy GUI says "Content & Scanning"
(`static/index.html`, a deliberate rename away from "Security" per
`docs/design/INFORMATION-ARCHITECTURE.md:68`); the new frontend's `ContentSecurityPage.tsx` says "Content
Security" (a deliberate 2E-A slice decision per `docs/design/FRONTEND-MIGRATION-PLAN.md`). Both are
documented, deliberate choices from two design passes that never cited each other, and
`FRONTEND-FEATURE-PARITY.md` still anchors the surface to the old name. This is a naming-policy
reconciliation between two design documents, not a mechanical rename — the same class this program has
previously declined to force for T-13's "TLS Inspection" vs. "SSL" branding question. Not queued to the
numbered backlog; flagged for the frontend migration owner to resolve.

**Terminology Health Score: 8.7 / 10** (unchanged from the 2026-09-08 report, which already credited the
CI-enforced ADR-numbering fix this review's branch independently rediscovered). This review's own net-new
contribution — two small, real GUI-copy fixes with no prior coverage — is real but modest relative to the
fourteen-item carry-over backlog, which remains entirely unchanged. The score is not lowered for the
duplicate-discovery episode above, since it produced zero waste that reached `main`; it is also not
raised beyond 8.7 for the same reason 09-08 gave for holding its own score there — the underlying
carry-over backlog hasn't moved.

---

## Findings

### T-53 — New admin frontend's Decryption surface disagrees with itself about the exclusion-cache tab's name (new — fixed this pass)

- **Business concept:** the volatile, runtime-learned decryption-exclusion cache (fail-open auto-learn,
  `internal/autoexclude`).
- **Current names before this fix:** `frontend/src/features/security/DecryptionPage.tsx:25,66` and
  `AutoExclusionsTab.tsx:1` (comment header) name the tab **"Auto-Exclusions."**
  `frontend/src/features/objects/DecryptionProfilesPage.tsx:496`, in the same frontend, cross-referenced
  the identical feature as "the Decryption Exclusions surface."
- **Recommended canonical name:** "Auto-Exclusions" (the tab's own name) — the cross-reference was the
  outlier, not the tab.
- **Why the current naming was problematic:** unlike the well-documented old-GUI-vs-new-GUI migration
  drift this program tracks separately (the "Content & Scanning" vs. "Content Security" soft finding
  above), this is the *same* frontend codebase, in the same feature area, citing its own sibling
  component under a name that component does not use — an admin following the callout's link text would
  be looking for a tab labeled "Decryption Exclusions" and would not immediately recognize
  "Auto-Exclusions" as the same thing.
- **Why the new name is better:** removes the internal contradiction with zero net renaming — one string
  changed to match an existing, unambiguous label one file away.
- **Affected code:** `frontend/src/features/objects/DecryptionProfilesPage.tsx` (1 line).
- **Affected API:** none.
- **Affected GUI:** the Decryption Profiles page's fail-open callout text; rebuilt `frontend/dist` (Node
  24.19.0/npm 11.17.0, checksum-verified; `npm run verify` — 787 tests, lint, format, typecheck — and the
  2-build determinism gate all passed before commit; re-confirmed current after the `main` sync since no
  other branch touched `frontend/` in the interim).
- **Affected Documentation:** none.
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (one string, no compat surface — the experimental new frontend is
  disabled by default via `CULVERT_EXPERIMENTAL_UI`).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium (confusing but confined to a disabled-by-default preview surface with no external
  consumers yet).

### Unnumbered — Legacy GUI panel titles didn't match their own nav labels (new — fixed this pass)

- **Business concept:** the Stage-2 access-control rulebase and the Stage-1 authentication-policy
  rulebase, each already named "Access Rules" / "Authentication Rules" in `docs/design/
  PRODUCT-TERMINOLOGY.md`'s "Rule" row and in both GUIs' own nav.
- **Current names before this fix:** `static/index.html`'s in-page panel titles read "Active Policy
  Rules" and "Auth Policy Rules" — one scroll away from their own nav items reading "Access Rules" and
  "Authentication Rules."
- **Fix:** panel titles now read "Access Rules" and "Authentication Rules," matching the nav, the new
  frontend, and the documented canonical vocabulary.
- **Affected code:** `static/index.html` (2 lines).
- **Migration Complexity:** Trivial. **Compatibility Risk:** None. **Estimated PR Size:** Small.
- **Priority:** Low (cosmetic within one already-consistent page, no cross-surface ambiguity — kept
  unnumbered rather than assigned a new T-ID since it doesn't reach the severity bar of most tracked
  findings, but recorded for completeness).

---

## Carried-Over Findings (unchanged — as confirmed by the 2026-09-08 report and re-verified against the post-sync tree)

All fourteen previously-open finding IDs remain open and unchanged: T-9, T-11, T-12, T-13 (residual),
T-17, T-18, T-21+T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39. (T-31 and T-48 are removed
from this list — both are now fixed and merged to `main`, T-31 via the fix originally written in PR
#1239 and T-48 via the 2026-09-08 report's fix, which additionally shipped `docs_adr_numbering_test.go`
— a merge-blocking Go test that makes a fifth ADR-numbering collision fail CI automatically instead of
waiting for the next manual review pass. This review's own independently-written copies of both fixes
were superseded by the sync and never reached `main` separately.) Full descriptions remain in the reports
where each was first raised; see `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-08.md` for the most recent
confirmation of this exact set.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 2026-09-08 for the still-open carry-over items; T-53 and the panel-title fix are resolved
in this pass and do not appear on the plan. T-31 and T-48 are removed (fixed, merged).

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

Also flagged (design-document reconciliation, not a numbered backlog item): "Content & Scanning" vs.
"Content Security" — see the soft finding above.

Process-level (owned by DEBT-014, not restated here as a fresh recommendation): sync against `main`
immediately before opening a PR, not only at review-start, to catch a mid-review landing before writing
a redundant fix.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass fixed two genuinely new, small, zero-risk GUI-copy
issues (T-53 and the panel-title alignment) that no prior review had found. It also correctly declined to
act on two other same-day candidates after checking documented design intent: one ("Administrators") was
already a deliberate, adopted disambiguation and the proposed change would have reintroduced the exact
collision it was created to avoid; the other ("Content & Scanning" vs. "Content Security") is a genuine
but non-mechanical reconciliation gap between two design documents, recorded as a soft finding rather than
forced. This review's branch also independently rediscovered and fixed the ADR-0034 collision (T-48) and
the ClamAV metric naming gap (T-31) — both already fixed and merged to `main` via other branches by the
time of this review's pre-PR sync, so those fixes were dropped as redundant rather than shipped a second
time, producing zero net duplication (a concrete instance of the pattern DEBT-014 already tracks, handled
without adding to its count). All twelve remaining carry-over findings (T-9, T-11, T-12, T-13, T-17, T-18,
T-21+T-32, T-25, T-29, T-30, T-33, T-34) are unchanged per the 2026-09-08 report. No cosmetic or
preference-driven renames were proposed.
