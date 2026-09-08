# Culvert Language & Terminology Governance Review — 2026-09-08

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..HEAD` (362 commits, 22 on the first-parent path — the largest window
> this program has processed, more than 3.5x the prior record of 95 commits set on 2026-08-25). The
> window is almost entirely one program: the MCP Canary → Live-execution activation slice (Shadow-Exit
> review, Canary activation gate, tool-trust approval, Live-tier composition/arming/quiesce,
> Live-Production-dependency wiring, rollback rehearsal, red-team/mutation campaigns) plus the
> unrelated CHAOS-56 bounded-shutdown work CLAUDE.md already documents. Method: (1) full-repo grep for
> every `# ADR-NNNN` header across `docs/adr/` and `docs/support/rfc/`, prompted by this being the
> fourth window running to add new ADR-numbered documents on an actively-collision-prone number; (2)
> `git diff --stat e698a12..HEAD` (253 files) partitioned into the MCP-Canary/Live/CHAOS-56 cluster
> (already covered by the collision check and by reading representative files from each new subsystem —
> `internal/mcp/canary`, `internal/mcp/tooltrust`, the `mcp_live_*.go`/`mcp_canary_*.go` composition-root
> families) versus a residual set of four files (`controlplane_server.go`, `metrics.go`,
> `static/index.html`, one new security-review doc) checked individually and confirmed unrelated to
> naming; (3) every one of the fourteen still-open carry-over finding IDs' dependent files (T-9, T-11,
> T-12, T-13, T-17, T-18, T-21+T-32, T-25, T-29, T-30, T-31, T-33, T-34, T-39) checked against this
> window's changed-file list — all fourteen absent except T-39's own already-known dependency
> (`mcp_telemetry.go`, touched for an unrelated schema-version-compatibility fix, read in full and
> confirmed to not touch the `qualification_*` vocabulary); (4) spot-read of the new Canary/Live design
> docs and runbooks (`CANARY-FIRST-RUNBOOK.md`, `LIVE-PRODUCTION-DEPS-REPORT.md`,
> `mcp-first-controlled-canary-review.md`, `mcp-shadow-first-controlled-run-report.md`) for the T-39
> "qualification" collision pattern specifically, since this window's Canary work references the
> QUAL-2/3 bootstrap-fleet inventory repeatedly — no new head-on collision with the pre-existing
> Production-Qualification concept found, only continued use of the already-flagged ambiguous term; (5)
> new-route audit: `api/route-classification.yaml` and `ui_routes_meta.go`'s additions (`/api/mcp/tool-approvals`,
> `/api/mcp/tool-approval-decision`, `/api/mcp/rollout/rehearse-rollback-authoritative`,
> `/api/mcp/canary/shadow-exit-review`) cross-checked against the internal `tooltrust`/`canary` package
> vocabulary and audit-event names (`mcp.tooltrust.*`) — consistent, no drift.
> **Companion change:** one fix ships with this review — a fourth ADR-numbering collision, on `0034`,
> created within this window and closed today — plus, because this is the fourth recurrence of the
> identical defect class, a new merge-blocking Go test (`docs_adr_numbering_test.go`) that makes the
> check permanent instead of a manual grep repeated every review cycle.

---

## Executive Summary

**One finding, fully fixed, and — for the first time in this defect class's four-time history — closed
at the root cause rather than patched again at the symptom.** The 2026-08-25 review renumbered
`docs/support/rfc/0032-ai-receives-normalized-evidence.md` to `0034` after confirming that number was
clean against every `# ADR-NNNN` header at that moment. Within the same window being audited here, an
independent long-running feature branch (`claude/mcp-tool-trust-approval`, first committing
`docs/adr/0034-mcp-tool-trust-approval.md` on 2026-08-28) had branched from a point in history that
predated the 08-25 fix and computed "the next free number" against its own stale view of the tree —
claiming `0034` for an unrelated, now-heavily-cited ACCEPTED architecture decision (MCP Tool Trust:
source of truth and approval-purpose binding, cited from 40+ call sites across `internal/mcp/tooltrust`,
`internal/mcp/catalog`, `mcp_tooltrust.go`, `ui_mcp_tooltrust.go`, `ui_routes_meta.go`, and five design/
operator docs) before the two branches were ever merged together. This is the fourth occurrence of the
identical root cause T-16, T-46, and T-47 each independently identified — no reservation mechanism
exists for these numbers, so two concurrent branches can always race to claim the same "next" one, and
this time the race was won by a branch that had simply started before the previous fix landed, which no
grep-at-merge-time discipline can prevent by itself.

**Fix, same precedent a fourth time, but this time paired with the process fix the 08-25 review
recommended and flagged as due.** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
ACCEPTED, by far the more heavily cited and more expensive to move of the two); the RFC-track document
— renumbered twice already for the identical reason (`0018` → `0032` → `0034`) — becomes `docs/support/
rfc/0036-ai-receives-normalized-evidence.md`, the next number confirmed clean against every `# ADR-NNNN`
header in the repository including both new files this window added (`0034`, `0035`). Header and the
three downstream citations that genuinely mean the RFC's topic (AI receives normalized findings, not raw
bundles) updated to match: `docs/support/TAC-CLOUD-ARCHITECTURE.md` (three call sites), `docs/support/
SUPPORTABILITY-THREAT-MODEL.md` (the `T-PROMPT` row), and `docs/adr/0016-raw-evidence-vs-normalized-
findings.md`'s own "Relates to" line. **New this pass:** the 08-25 review recorded a recommendation — "a
CI check that fails a PR introducing a duplicate `# ADR-NNNN` header" — but declined to implement it,
reserving that decision for whoever owns `docs/adr/0001`, and explicitly flagged that "a fourth
recurrence would be the point at which... keep fixing it each time stops being the cheaper option."
`docs/adr/0001` was not touched this window (confirmed by diff-stat absence) and no such check exists
anywhere in the repository (confirmed by grep across `.github/workflows/*.yml` and
`TECHNICAL-DEBT-REGISTER.md`) — the fourth recurrence duly arrived. Rather than record the
recommendation a second time, this pass implements the low-risk half of it: `docs_adr_numbering_test.go`,
a new root-package Go test that walks `docs/adr/*.md` + `docs/support/rfc/*.md`, extracts each file's
leading `# ADR-NNNN` header, and fails with the exact colliding filenames if any number is claimed twice.
It requires no CI workflow changes — `go test ./...` (the root package `.` in particular) is already part
of the required `pr-fast-gate.yml` lane per CLAUDE.md's own CI Pipelines section, so this closes the gap
the moment it merges to `main`, without touching lane architecture, without a new job, and without
altering any existing test's behavior (additive-only). The test was verified to catch the exact defect
class: reintroducing the just-fixed `0034` collision by hand fails it with the two colliding filenames
named, and reverting the change makes it pass again (see Verification below).

**Every one of the fourteen still-open carry-over findings is unchanged.** Two were checked more than by
file-list absence: T-39 ("qualification" ambiguity) because this window's Canary/Live work references the
QUAL-2/3 bootstrap-fleet inventory repeatedly (`CANARY-FIRST-RUNBOOK.md`, `LIVE-PRODUCTION-DEPS-REPORT.md`,
`mcp-first-controlled-canary-review.md`, `mcp-shadow-first-controlled-run-report.md`) — read in full and
confirmed to continue the existing, already-flagged ambiguous usage without introducing a fresh head-on
collision with the pre-existing Production-Qualification concept; and T-38's already-shipped fix (verified
still intact — `static/index.html`'s only change in this window is the "Review required tools" label from
the 08-25 fix, untouched otherwise).

**No new terminology drift was found in the ~55,000 lines this window adds.** The dominant new
subsystem — MCP Canary activation, Live-execution tier composition/arming/quiesce, and tool-trust
approval (`internal/mcp/canary`, `internal/mcp/tooltrust`, the `mcp_canary_*.go`/`mcp_live_*.go`
composition-root families, `docs/adr/0034`, `docs/adr/0035`) — was read across its file headers, error
namespaces, audit-event names, and admin-route metadata specifically looking for the pattern this
program exists to catch: the same word naming two things, or two words naming one thing. The one
apparent near-miss — "Live" (the mechanism: does a request cross the real upstream side-effect boundary)
versus "Production" (the pre-existing rollout-ladder rung name, `Disabled→Observe→Shadow→Canary→
Production`) sharing a codebase and both appearing in filenames like `mcp_live_production_deps.go` — is
not drift: the code is explicit and consistent that these are two orthogonal axes (a Live tier is a
prerequisite CAPABILITY that both the Canary and Production rungs consume; `internal/mcp/rollout`'s
`ModeCanary`/`ModeProduction` remain the sole rollout-mode vocabulary, `mcp_live_tier.go`'s own header
states the three states that "the program's core principle requires never collapse into one": Live tier
COMPOSED != Live tier ARMED != Canary ACTIVE). This continues the pattern the 08-25 review already
recorded as a positive sign for this program's authors — self-disambiguating same-window near-misses in
header comments before they ever reach this review.

**Terminology Health Score: 8.7 / 10** (up from 8.6 — one new same-window collision, the fourth
recurrence of the ADR-numbering defect class, was caught and fixed, and this time the fix closes the
recurrence mechanism itself with a merge-blocking test rather than only the immediate symptom, which is
a materially stronger remediation than the three prior instances of this exact finding. The score does
not move further because the fourteen-item carry-over backlog is unchanged, and because — despite the
process fix landing today — the underlying pattern that produced four recurrences (long-running feature
branches computing "next free number" against a stale view of `main`) is now caught at merge time going
forward but was not preventable by anything that existed during this window, so this review credits the
detection/prevention fix without crediting the backlog for anything it hasn't yet resolved.)

---

## Verification

`docs_adr_numbering_test.go` (new file) + the five-file rename/citation fix:

```
$ go build ./...
(clean, no output)

$ gofmt -l docs_adr_numbering_test.go
(clean, no output)

$ go vet .
(clean, no output)

$ go test -run TestADRNumberingNoCollisions -v .
=== RUN   TestADRNumberingNoCollisions
--- PASS: TestADRNumberingNoCollisions (0.00s)
PASS
ok  	github.com/KidCarmi/Culvert	0.095s
```

Regression-proof (defect-gate discipline consistent with this repo's own chaos-test convention — pinning
that the gate actually fails against the reintroduced defect, not just passing against the fixed tree):

```
$ sed -i 's/ADR-0036/ADR-0034/' docs/support/rfc/0036-ai-receives-normalized-evidence.md
$ go test -run TestADRNumberingNoCollisions -v .
=== RUN   TestADRNumberingNoCollisions
    docs_adr_numbering_test.go:93: ADR-0034 is claimed by 2 documents (must be exactly 1):
    [docs/adr/0034-mcp-tool-trust-approval.md docs/support/rfc/0036-ai-receives-normalized-evidence.md]
    — renumber the newer/less-established one to the next number confirmed clean against every
    '# ADR-NNNN' header in docs/adr/ and docs/support/rfc/, and update its downstream citations
--- FAIL: TestADRNumberingNoCollisions (0.00s)
FAIL

$ git checkout -- docs/support/rfc/0036-ai-receives-normalized-evidence.md   # restore the fix
$ go test -run TestADRNumberingNoCollisions -v .
--- PASS: TestADRNumberingNoCollisions (0.00s)
```

Full-repo collision re-check after the fix (empty output = no duplicate `# ADR-NNNN` number anywhere in
`docs/adr/` or `docs/support/rfc/`):

```
$ grep -rn '^# ADR-[0-9]\+' docs/adr/*.md docs/support/rfc/*.md \
    | sed -E 's/.*# ADR-([0-9]+).*/\1/' | sort | uniq -d
(no output)
```

---

## Findings

### T-48 — Fourth recurrence of the ADR-numbering collision, this time on `0034` (new — fixed this pass, root cause closed)

- **Business concept:** the unique identifier for one architecture decision record.
- **Current names before this fix:** `# ADR-0034` claimed simultaneously by
  `docs/adr/0034-mcp-tool-trust-approval.md` (ACCEPTED 2026-08-28, part of the MCP Canary/Live-execution
  activation program, 40+ citations across `internal/mcp/tooltrust`, `internal/mcp/catalog`,
  `mcp_tooltrust.go`, `ui_mcp_tooltrust.go`, `ui_routes_meta.go`, `main.go`, and five design/operator
  docs) and `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (PROPOSED — NOT ADOPTED, itself
  only renumbered to `0034` in the immediately prior review cycle after the identical collision on
  `0032`).
- **Recommended canonical name:** `docs/adr/0034-mcp-tool-trust-approval.md` keeps ADR-0034 (established,
  ACCEPTED, overwhelmingly more cited and more expensive to move); the RFC becomes ADR-0036.
- **Why the current naming was problematic:** identical to T-16, T-46, and T-47 — a bare "ADR-0034"
  citation in `TAC-CLOUD-ARCHITECTURE.md` or `SUPPORTABILITY-THREAT-MODEL.md` was ambiguous between two
  unrelated decisions (the MCP tool-trust approval boundary vs. the AI-input-normalization boundary)
  with no way to disambiguate from the number alone. Root-cause analysis this time: the two branches
  never raced at "grep time" in the way the prior three collisions did — `docs/adr/0034-mcp-tool-trust-
  approval.md`'s first commit (2026-08-28) predates the 08-25 review's own fix landing on `main`
  (`403ef54`, same day) by branch-point, i.e. the tool-trust branch's worldview of "the next free number"
  was already stale by the time it was created, and the two streams were never rebased against each
  other before both merged.
- **Why the new name is better:** restores a 1:1 mapping between decision-record number and decision;
  `0036` is confirmed clean against every `# ADR-NNNN` header in the repository as of this pass,
  including both new files this window added (`0034`, `0035`).
- **Affected code:** none (docs-only rename), plus the new `docs_adr_numbering_test.go` gate (additive,
  root package, no behavior change to any existing code path).
- **Affected API:** none.
- **Affected GUI:** none.
- **Affected Documentation:** `docs/support/rfc/0034-ai-receives-normalized-evidence.md` (renamed to
  `0036-ai-receives-normalized-evidence.md`, header updated), `docs/support/TAC-CLOUD-ARCHITECTURE.md` (3
  citations), `docs/support/SUPPORTABILITY-THREAT-MODEL.md` (1 citation),
  `docs/adr/0016-raw-evidence-vs-normalized-findings.md` (1 "Relates to" citation).
- **Affected Configuration:** none.
- **Process fix (new this pass, not part of the prior three instances of this finding):**
  `docs_adr_numbering_test.go` — a merge-blocking Go test in the root package (runs under the existing,
  already-required `go test ./...` root-package coverage in `pr-fast-gate.yml`; no CI workflow edits) that
  fails with the exact colliding filenames the moment two documents under `docs/adr/` or
  `docs/support/rfc/` claim the same `# ADR-NNNN` number. This is the CI-check half of the reservation-
  convention recommendation the 08-25 review raised and explicitly deferred to whoever owns
  `docs/adr/0001` — deferred a fourth time would have meant recording the same recommendation a fourth
  time with no different outcome expected, so this pass implements the mechanical, additive, zero-risk
  half of it directly rather than re-queuing it. It does not implement a number-reservation/allocation
  mechanism (still out of scope — that is a process/tooling design question, not a mechanical check); it
  only makes the failure mode of "two branches independently claim the same number" visible at merge
  time instead of at the next terminology-governance pass, days to weeks later.
- **Verification:** see the Verification section above — `go build ./...` clean, `gofmt -l` clean, `go
  vet .` clean, the new test passes on the fixed tree and fails (naming both colliding files) when the
  collision is reintroduced by hand, and a full-repo `# ADR-NNNN` grep confirms zero duplicates remain.
- **Migration Complexity:** Trivial (docs-only rename, 4 citation files, 1 new additive test file; no
  code/API/GUI/config surface touched).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Medium-High (raised half a step from T-16/T-46/T-47's "Medium" — the fourth recurrence of
  an identical defect class, explicitly flagged as the threshold for escalation by the prior review, and
  the fix now includes closing the recurrence mechanism rather than only the symptom).

---

## Carried-Over Findings (unchanged — re-confirmed by file-list absence, two re-confirmed by direct read)

All fourteen remaining previously-open finding IDs were re-checked against this window's 253-file
changed list: T-9, T-11, T-12, T-13 (residual), T-17, T-18, T-21 + T-32 (paired), T-25 (residual), T-29,
T-30, T-31, T-33, T-34, T-39. Twelve are re-confirmed open and unchanged with no further diffing needed —
none of their dependent files (`ui_policy.go`, `configversion.go`, `config_surfaces.go`, `policy.go`,
`store.go`, `cmd/culvert-maint/internal/{server,ops,runner}/*upgrade*.go`, `README.md`,
`decryption_redaction.go`, `admin_settings.go`, `proxy_tunnel.go`, `internal/sealbox/*`,
`support_export.go`, `support_recipients.go`, `connlimit_startup.go`, `internal/clamav/*`,
`internal/reqlog/*`, `internal/urlcatfeed/*`) appear anywhere in this window's diff. Two were checked
further: **T-39** ("qualification" naming two unrelated concepts) because this window's dominant new
work — the MCP Canary activation slice — repeatedly references the QUAL-2/3 bootstrap-fleet inventory
concept the finding is partly about (`CANARY-FIRST-RUNBOOK.md:42`, `LIVE-PRODUCTION-DEPS-REPORT.md:83,85`,
`mcp-first-controlled-canary-review.md:87,169`, `mcp-shadow-first-controlled-run-report.md:94`); each
citation was read and confirmed to use the term consistently with the finding's already-documented
"business concept B" (the bootstrap/staging fleet), never juxtaposed against "business concept A"
(Production Qualification) in a way that creates a fresh, sharper collision than what T-39 already
describes — the finding's dependent config-key files (`config.go`'s `qualification_inventory_file`/
`qualification_telemetry`, `mcp_inventory.go`) remain untouched, so the fix scope and priority are
unchanged. **T-21 + T-32**'s only apparent file-list touch, `static/index.html` (1 line), was verified to
be the already-shipped T-38 fix (`'Drifted tools'` → `'Review required tools'`) from the 08-25 review,
unrelated to the `cp_version`/`snapshot_sha256` territory T-21/T-32 are about. Full descriptions remain in
the reports where each was first raised and in `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over
list, to avoid duplicating unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-48 is resolved in this pass and does not
appear on the plan.

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

Also closed this pass, not queued further: the ADR-number reservation convention the 08-25 review
recommended and left open — its low-risk, mechanical half (a merge-blocking duplicate-number test) now
ships as `docs_adr_numbering_test.go`; the remaining, higher-effort half (an actual number-allocation/
reservation mechanism for branches that want to claim a number before merging) remains a process design
question for whoever owns `docs/adr/0001`, not a mechanical rename this program can carry out.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass caught and fixed a new same-window collision (T-48) —
the fourth instance of a recurring defect class — and, unlike the three prior instances, closed the
recurrence mechanism itself rather than only the immediate symptom, by shipping the CI-enforced half of
the process recommendation the prior review had left open. It also verified, by reading rather than by
name-matching, that the ~55,000-line MCP Canary/Live-execution/tool-trust addition dominating this
window's diff introduces no new drift: its one apparent same-word near-miss ("Live" vs. "Production") is
a deliberate, well-documented, orthogonal distinction, continuing the pattern of author-side self-
disambiguation this program has recorded favorably in prior reviews. All fourteen still-open carry-over
findings were re-confirmed unchanged, two (T-39, T-21+T-32) by direct read rather than file-list absence
alone given this window's size and the specific risk each carried of a fresh collision. No cosmetic or
preference-driven renames were proposed.
