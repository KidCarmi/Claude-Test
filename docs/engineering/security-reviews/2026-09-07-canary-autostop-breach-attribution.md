# Security regression review — Canary auto-stop breach attribution — 2026-09-07

**Scope:** the change surface merged into `main` since the last review window. In practice that is
one pull request — **#1314, "whole-Canary automatic stop" (blocker #7)**, merged `1b3d0e6` over
`290e376`. Every other Go source change on `main` in the window belongs to the same MCP program;
nothing outside `internal/mcp/**` and the root `mcp_*.go` wiring changed, so the SWG data path,
auth, TLS, policy, cluster, release-trust and admin-API surfaces were reviewed only for
*reachability from* this change, and were not themselves modified.

**Branch:** `claude/epic-bardeen-tks1g6` · baseline `1b3d0e6`
**Method:** REVIEW → PROVE → FIX → TEST → RE-REVIEW. The finding was reproduced against the
pre-fix tree before the patch was written, and both guards are mutation-verified: the fix was
reverted and each test required to fail.

> **Verdict:** one finding, **P2 (latent)**. No authentication, authorization, policy, TLS,
> transport or persistence control was found weakened by the reviewed change. Guarded MCP execution
> remains disabled by default and this review does not authorise enabling it.

---

## 1. Finding ledger

Severity: **P0** reachable today and security-relevant · **P1** reachable, correctness or
availability · **P2** latent / pre-activation · **P3** accuracy and maintainability.

| ID | Severity | Finding | State |
|---|---|---|---|
| CAN-01 | P2 | The **admission gate** is a third generation-bound breach reporter and reached `tripCanaryAbortForGeneration` directly, so the generation it snapshots was forwarded raw. A zero — "no activation was admitting when I looked" — is a **wildcard** downstream ("whatever is current"), so an unattributable observation could stop an activation it says nothing about. Round 18 closed this inversion at the other two reporters and did not reach this one. | Fixed + walled, this PR |

### Refuted (investigated, no defect)

- **`mcpLiveTrustRevalidate`'s new `(bool, string)` signature.** Every prior `return false` still
  returns `false`; the added code is advisory to the abort path only. No request that was denied
  before is admitted now, and no request that was admitted before is denied. Authorization is
  unchanged.
- **The `BudgetDeniedWindow` case added to `reserveCanaryExecution`.** It latches `window_expired`
  instead of `budget_exhausted` and is *not* named in the persist-failure fail-closed condition
  below it — but `BudgetOutcome.WholeCanaryExhaustion()` already includes `BudgetDeniedWindow`, so
  the durable record is still removed on a failed persist. Only the recorded first *cause* changed.
- **Slot release moved from `callUpstream`'s own defer to the outer defer.** Reviewed for a leak:
  `callUpstream` is invoked exactly once (`Broker.Materialize` calls its callback from a single site
  outside any loop; the no-credential branch calls it directly), so `releaseSlot` cannot be
  overwritten, and the outer defer runs on every return path. The residual is that a panic in the
  three statements ahead of it would skip the release — availability only, in the fail-closed
  direction, and a per-request panic already fails the request closed.
- **Nil dereference on the new status surface.** `canaryAbortStatusFor` calls `cr.health.Stats()`
  and `abortCodeNow` calls `cr.aborter.AbortCode()` without nil checks. Both `*HealthMonitor` and
  `*AbortController` implement every method nil-safely (`NewHealthMonitor(0)` / `NewAbortController(0)`
  return nil by design), so this is correct, not lucky.
- **Log injection on the new log lines.** The two new `logger.Printf` call sites interpolate a
  bounded capability enum and a `sanitizeLog`-wrapped error under `%q`. Every abort `code` that can
  reach the status JSON is a package constant; none is caller-controlled.
- **Health-detector evasion.** `reportAttemptSettled` excludes caller cancellations and
  self-classifying breaches from the population. Neither exclusion is reachable from an untrusted
  upstream: `ReasonUpstreamCancelled`/`context.Canceled` are produced by Culvert's own client when
  *this* caller goes away, and a `DeadlineExceeded` overrun is deliberately still charged.

---

## 2. CAN-01 — an unattributable admission breach could stop a healthy activation

### What the control is for

A whole-Canary breach revokes the experiment's authority to change reality. Because that is a
destructive verdict, every report of one carries the **activation generation** it was observed
under, and `tripCanaryAbortForGeneration` verifies it under the same lock that latches — so an
observation belonging to an activation that is gone is discarded rather than charged to whatever
replaced it.

`wantGen == 0` is deliberately **not** a null in that function. It is a documented **wildcard**
meaning "whatever is current", reserved for the one unbound entry point (`tripCanaryAbort`), whose
callers have no originating activation to name.

### The defect

PR #1314's admission gate takes one generation reading before the live-trust check and carries it
to the trip:

```go
var admittingGen uint64
if g.currentGeneration != nil { admittingGen = g.currentGeneration() }
trustedNow, driftCode := g.trustOK(...)
if driftCode != "" { g.tripBreach(admittingGen, driftCode) }
```

and the production `tripBreach` reached the trip **directly**:

```go
tripBreach: func(gen uint64, code string) {
    globalCanaryRuntime.tripCanaryAbortForGeneration(capb, gen, code, canaryNow())
},
```

That is a generation-**bound** reporter forwarding its snapshot raw. When the reading is `0` —
no activation was admitting at that instant — the value arrives downstream meaning *stop whichever
activation is running now*. The sentinel for "attribute to none" acts as "attribute to all".

This is precisely the inversion Codex round 18 closed, in the same PR, at the two reporters it knew
about: `Deps.reportCanaryBreach` (`internal/mcp/runtime/deps.go`) and `canarySafetyFunnel.Breach`
(`mcp_canary_autostop.go`) both drop a zero, and the mutation campaign records why the guard is
written twice — "the guard is deliberately duplicated ... independently breakable". The admission
gate is a **third** reporter of the same kind, added at the same time, and it opted out of both
copies by not going through either.

### Attack scenario, preconditions, exploitability

This is a **safety-control integrity** defect, not an access-control one. It cannot admit a request
that policy would deny, cannot reach an upstream, and cannot widen scope — the request that triggers
it fails closed in every case.

- **Preconditions.** Guarded MCP execution composed and armed (Canary), *and* the gate's single
  generation reading landing in a window where no activation is armed — between a demotion and the
  re-activation that follows it, or before the first activation of the process — *and* an
  authoritative drift (`tool_fingerprint_drift` / `server_identity_drift`) observed on that same
  pass, *and* an activation current by the time the trip runs.
- **Exploitability.** Not attacker-reachable. The drift signal comes from Culvert's own catalog and
  tool-trust records, not from request data; the window is an operator-timed transition. There is no
  input an MCP client can send that selects it.
- **Impact.** A healthy, correctly-behaving Canary is stopped with an immutable first cause it did
  not earn. Because the latch is monotonic and persisted, the operator's record of *why* the
  experiment stopped is wrong, and recovery requires a demote/re-activate cycle. §16 of the review
  is explicit that this direction is the one a safety control must not err in: stopping a healthy
  experiment for something outside its own blast radius is, to an operator, indistinguishable from
  the control being broken.
- **Likelihood today.** Low. With the live tier disarmed on restart and a failed activation rolling
  the rollout state back, `currentGeneration()` returning 0 at an armed gate is not reachable on the
  shipped path — which is why this is rated **P2 latent** rather than P1. It is a guard that is
  absent, not a hole that is open, and the reason to close it is that the two reporters beside it
  treat the same value as unsafe.

**CWE-863** (Incorrect Authorization — wrong subject) is the closest fit for the attribution error;
the operator-visible consequence is **CWE-754** (improper check for an exceptional condition).
**OWASP A04:2021 — Insecure Design** (a sentinel value overloaded with two opposite meanings across
a trust seam).

### The fix

The gate now reports through the **same funnel** every other reporter uses, rather than carrying a
third copy of the guard:

```go
tripBreach: newCanarySafetyFunnel(capb).breachForCapability(),
```

`canarySafetyFunnel.Breach` already checks the capability and refuses a zero, and forwards a
non-zero generation to `tripCanaryAbortForGeneration` with `canaryNow()` — which is exactly what
the replaced closure did. **For every non-zero generation the behaviour is byte-identical.** Only
the zero case changes, from "abort whatever is current" to "dropped".

The wildcard itself is **not** removed. It stays on `tripCanaryAbort`, where it is intended.

### Files

- `mcp_live_gate.go` — the gate reports through the funnel.
- `mcp_canary_autostop.go` — `breachForCapability()`, the capability-scoped adapter.
- `mcp_canary_autostop_test.go` — the behavioural gate and the structural wall.
- `scripts/mcp-canary-mutation-campaign.sh` — M116.

### Required tests, and what each proves

| Test | Class | Proves |
|---|---|---|
| `TestAutoStop_AdmissionGateZeroGenerationBreachCannotStopALiveActivation` | negative / regression | An unattributable admission breach leaves a live activation's authority `granted`. Reproduced failing against the pre-fix tree. |
| …its in-test **control** | positive | The *same* drift on the *same* gate with the reading the production closure actually takes still stops the whole Canary, with `tool_fingerprint_drift` as the first cause — so the gate cannot be satisfied by severing the gate's breach routing, which is the failure mode a zero-guard invites. |
| `TestAutoStopWall_GenerationBoundReportersGoThroughTheFunnel` | structural / boundary | Only the two files that own the trip may name it. A **fourth** reporter added anywhere else fails here and is pointed at the funnel. Also fails if the trip is renamed out from under it, so the wall cannot silently retire. |
| `TestAutoStop_ZeroGenerationBreachCannotStopALiveActivation` (pre-existing) | regression | The round-18 guard at the funnel and runtime seams is untouched. |
| `TestAutoStop_ToolFingerprintDriftAbortsTheWholeCanary`, `TestAutoStop_ServerIdentityDriftAbortsTheWholeCanary` (pre-existing) | positive | Attributable drift still aborts. |
| `TestAutoStop_MerelyUnauthorizedRequestDoesNotStopTheCanary` (pre-existing) | negative | An ordinary unauthorized request still fails closed *without* stopping the experiment. |
| Mutation **M116** | mutation | Restoring the direct trip is caught. Verified: the mutated tree compiles and both new tests fail. |

Concurrency is covered by the existing generation-strict locking gates — the fix adds no state and
no lock; it removes a call site.

---

## 3. Residual risk

- **The wildcard still exists** on `tripCanaryAbort`, by design. It is now reachable from exactly
  one entry point, and the wall makes a new bound reporter that bypasses the funnel a build failure
  rather than a review question.
- **The gate's reading is still a snapshot**, taken before the trust check rather than under one
  lock with it. A demote-and-reactivate landing in that window makes the observation stale and the
  trip discards it — the fail-closed direction, and the same posture
  `resolveUnderStableGeneration` takes on the pipeline path. The drift is persistent, so the next
  request under the new activation observes it and latches correctly.
- **`generation` is never reset on demotion** (deliberately — it is monotonic), so
  `currentGeneration()` returns 0 only for a capability never activated in this process. That is
  what keeps CAN-01 latent rather than reachable, and it is a property of the *activation*
  lifecycle, not of this seam: a future change that reset the counter would make CAN-01 live. The
  wall and the gate hold regardless.
- Everything recorded as open in
  `docs/operator/mcp-first-controlled-canary-review.md` is unchanged by this review.
