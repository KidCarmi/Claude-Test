#!/usr/bin/env bash
# mcp-canary-atomic-binding-mutations.sh — §10 campaign for the ATOMIC activation-bound
# admission transaction (follow-up to PR #1314, whose pre-admission drift path merged with two
# open P1 findings).
#
# Each mutation reintroduces ONE specific defect the physical-effect accounting
# work exists to prevent, then runs the NAMED gate that must catch it. A mutation
# that no test rejects is not a passing mutation: it is a hole in the gates.
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall
# whose stated purpose is compile-time prevention. Mutations here are written to
# compile and change behavior, so the failure comes from an assertion.
#
# Usage:  scripts/mcp-canary-mutation-campaign.sh [-k]   (-k: keep going after a
#         surviving mutation; default stops at the first survivor)
set -uo pipefail
cd "$(dirname "$0")/.."

KEEP=0
[ "${1:-}" = "-k" ] && KEEP=1

# The campaign mutates tracked files IN PLACE and reverts them with `git checkout`.
# Running it against a dirty tree therefore DESTROYS uncommitted work — it did
# exactly that once, silently reverting an unrelated edit mid-run. Refuse to start
# unless every tracked file is committed.
if ! git diff --quiet || ! git diff --cached --quiet; then
  printf 'refusing to run: the working tree has uncommitted changes to tracked files.\n'
  printf 'this campaign mutates tracked files and reverts them with `git checkout --`,\n'
  printf 'which would discard that work. commit or stash first.\n'
  git status --short
  exit 2
fi

PASS=0; SURVIVED=0; SKIPPED=0
declare -a SURVIVORS=()

# revert restores the working tree to HEAD for the files a mutation touched.
revert() { git checkout -- "$@" 2>/dev/null || true; }

# has_re / has_fixed search captured output WITHOUT a producer pipe.
#
# `printf '%s' "$out" | grep -q PATTERN` is WRONG under `set -o pipefail`, which this
# script sets: grep exits as soon as it matches, printf then dies of SIGPIPE (141),
# and pipefail reports the PIPELINE as failed even though the pattern matched. Every
# use of that idiom here was mis-scoring, each in a different direction — a matched
# build failure not setting build_broke, a matched "no tests to run" not raising
# BROKEN GATE, a matched race report read as "no race reported", and a matched
# attribution symbol read as missing (Codex round 19). A herestring has no producer
# to kill, so the exit status is grep's alone.
has_re()    { grep -qE -- "$1" <<<"$2"; }
has_fixed() { grep -qF -- "$1" <<<"$2"; }

# gate_ran reports whether a `go test` invocation actually REACHED an assertion.
#
# There are exactly two ways it does not, and both exit in a way that a bare status
# check misreads: the -run pattern matched no tests (exit 0 — indistinguishable from a
# pass), or the package did not build (nonzero — indistinguishable from a caught
# mutation). Every result decision in this script must go through this function.
#
# It exists because THREE CONSECUTIVE REVIEW ROUNDS found a hole in a hand-rolled
# copy of this logic (Codex 18/19/20): the build check was missing from run_mutation,
# then from M02 and M17, then the no-tests check was still missing from M17 — where
# `sink_rc == 0` is the CAUGHT condition, so a drifted sink pattern made the required
# control vacuous. Three holes in three rounds is a structural signal, not three
# coincidences: duplicated classification is what kept producing them.
gate_ran() {
  local id="$1" label="$2" out="$3"
  if has_fixed 'no tests to run' "$out"; then
    printf '      BROKEN GATE — %s matched no tests; this proves NOTHING\n' "$label"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: BROKEN GATE ($label matched no tests)")
    return 1
  fi
  if build_or_vet_failed "$out"; then
    printf '      NOT PROVEN — %s did not BUILD, so no gate ran; this proves NOTHING\n' "$label"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN ($label build/vet failure, not an assertion)")
    return 1
  fi
  return 0
}

# build_or_vet_failed reports that `go test` never reached an assertion. It is shared
# by run_mutation and by the two mutations that must drive `go test` themselves, so
# the header's "a compile failure is not proof" rule cannot hold in one place and not
# the other.
build_or_vet_failed() {
  has_re '\[build failed\]|\[setup failed\]|^vet: |^# github\.com/KidCarmi' "$1"
}

# mutate <id> <description> <gate-regex> <package> <file> <sed-script...>
# Applies the sed script(s) to <file>, runs <gate-regex> in <package>, and requires
# the run to FAIL. Anything else is a surviving mutation.
run_mutation() {
  local id="$1" desc="$2" gate="$3" pkg="$4" file="$5"; shift 5
  # A gate whose defect is a DATA RACE is invisible without the detector: the mutated
  # build passes and scores as a survivor. Such a mutation passes --race here, and the
  # flag is consumed before the perl scripts.
  local raceflag=() race_attr="" compile_wall=0
  while :; do
    case "${1:-}" in
      --race|--race=*)
        raceflag=(-race); race_attr="${1#--race}"; race_attr="${race_attr#=}"; shift ;;
      # The header rule says a compile failure is not proof UNLESS the mutation
      # targets a structural wall whose purpose is compile-time prevention. Such a
      # mutation declares itself here, and for it the build failure IS the proof.
      --compile-wall)
        compile_wall=1; shift ;;
      *) break ;;
    esac
  done
  printf '\n[%s] %s\n' "$id" "$desc"
  printf '      gate: %s  (%s)%s\n' "$gate" "$pkg" "${raceflag[0]:+ [race]}"

  local before; before="$(git rev-parse HEAD:"$file" 2>/dev/null || echo none)"
  for script in "$@"; do
    perl -0pi -e "$script" "$file"
  done
  local after; after="$(git hash-object "$file")"
  if [ "$before" = "$after" ]; then
    printf '      SKIPPED — the mutation did not change %s (pattern drifted)\n' "$file"
    SKIPPED=$((SKIPPED+1)); revert "$file"; return
  fi

  local out; out="$(go test "${raceflag[@]}" -count=1 -run "$gate" "$pkg" 2>&1)"
  local rc=$?
  revert "$file"

  # A compile-time wall is the ONE case where a build failure IS the proof, so it is
  # decided before gate_ran (which treats that same failure as "no gate ran").
  if [ $compile_wall -eq 1 ]; then
    if build_or_vet_failed "$out"; then
      printf '      CAUGHT (structural wall: the mutation does not compile, as required)\n'
      PASS=$((PASS+1))
    else
      printf '      *** SURVIVED *** a compile-time wall must REJECT this at build time\n'
      SURVIVED=$((SURVIVED+1)); SURVIVORS+=("$id: $desc")
      [ $KEEP -eq 0 ] && { printf '\nstopping at first survivor (pass -k to continue)\n'; exit 1; }
    fi
    return
  fi

  if ! gate_ran "$id" "the gate in $pkg" "$out"; then
    printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
    [ $KEEP -eq 0 ] && exit 1
    return
  fi

  if [ $rc -ne 0 ]; then
    # A --race mutation must be caught BY THE DETECTOR, and a bare nonzero exit does not
    # establish that. `go test` compiles and vets before running, so a build break, a
    # vet failure, a panic, a timeout or an UNRELATED race all land here too — and each
    # would score the mutation as caught while proving nothing about the lock that was
    # removed (Codex round 17). The scoring is therefore evidence-based for these, not
    # exit-code-based: the output must carry a race report, and that report must name
    # the mutated access.
    if [ ${#raceflag[@]} -ne 0 ]; then
      if ! has_fixed 'WARNING: DATA RACE' "$out"; then
        printf '      NOT PROVEN — the gate failed but NO race was reported; this proves NOTHING\n'
        printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
        SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN (gate failed without a race report)")
        [ $KEEP -eq 0 ] && exit 1
        return
      fi
      # race_attr is a comma-separated list of symbols that must ALL appear in the
      # report. Requiring both sides of the intended pair — the mutated writer and the
      # guarded reader — is what makes this attribution rather than "a race happened
      # somewhere in this package while the mutation was applied".
      local _attr_missing=""
      if [ -n "$race_attr" ]; then
        local _oldifs="$IFS"; IFS=','
        for pat in $race_attr; do
          has_fixed "$pat" "$out" || _attr_missing="$pat"
        done
        IFS="$_oldifs"
      fi
      if [ -n "$_attr_missing" ]; then
        printf '      NOT PROVEN — a race was reported but it does not name %s; this proves NOTHING\n' "$_attr_missing"
        printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
        SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN (race not attributable to $_attr_missing)")
        [ $KEEP -eq 0 ] && exit 1
        return
      fi
      printf '      CAUGHT (race detector reported a race naming %s, as required)\n' "${race_attr:-the mutated access}"
      PASS=$((PASS+1))
      return
    fi
    printf '      CAUGHT (gate failed as required)\n'
    PASS=$((PASS+1))
  else
    printf '      *** SURVIVED *** the gate passed with the defect reintroduced\n'
    printf '%s\n' "$out" | tail -5 | sed 's/^/        /'
    SURVIVED=$((SURVIVED+1)); SURVIVORS+=("$id: $desc")
    [ $KEEP -eq 0 ] && { printf '\nstopping at first survivor (pass -k to continue)\n'; exit 1; }
  fi
}

printf 'MCP Canary ATOMIC activation-binding mutation campaign\n'
printf '=====================================================\n'


ADM=mcp_canary_admission.go
GATE=mcp_live_gate.go
RUN=internal/mcp/runtime/execute.go

# ── (1) THE ATOMICITY ITSELF ────────────────────────────────────────────────
# The property every other mutation depends on: the trust observation is covered by the
# activation lock. Each of these breaks that in a different way and must be caught by the
# structural gate, which asks the mutex directly rather than racing it.

run_mutation M01 \
  'the activation lock is released around the trust observation' \
  'TestAtomicBinding_TrustProbeRunsUnderTheActivationLock' \
  . "$ADM" \
  's/\ttrusted, driftCode := false, ""\n\tif trust != nil \{\n\t\ttrusted, driftCode = trust\(\)\n\t\}\n/\ttrusted, driftCode := false, ""\n\tif trust != nil \{\n\t\tcr\.mu\.Unlock\(\)\n\t\ttrusted, driftCode = trust\(\)\n\t\tcr\.mu\.Lock\(\)\n\t\}\n/'

run_mutation M02 \
  'counter equality either side of an unlocked observation is substituted for locking' \
  'TestAtomicBinding_TrustProbeRunsUnderTheActivationLock' \
  . "$ADM" \
  's/\ttrusted, driftCode := false, ""\n\tif trust != nil \{\n\t\ttrusted, driftCode = trust\(\)\n\t\}\n/\ttrusted, driftCode := false, ""\n\tif trust != nil \{\n\t\tcr\.mu\.Unlock\(\)\n\t\ttrusted, driftCode = trust\(\)\n\t\tcr\.mu\.Lock\(\)\n\t\tif cr\.generation != gen \{\n\t\t\treturn canaryAdmission\{Denial: canaryAdmitNoActivation\}\n\t\t\}\n\t\}\n/'

run_mutation M08 \
  'the lock is released after the observation and the latch stops re-verifying the generation' \
  'TestAtomicBinding_C_ObservationCanNeverLatchTheReplacementActivation' \
  . "$ADM" \
  's/\ttrusted, driftCode := false, ""\n\tif trust != nil \{\n\t\ttrusted, driftCode = trust\(\)\n\t\}\n/\ttrusted, driftCode := false, ""\n\tif trust != nil \{\n\t\ttrusted, driftCode = trust\(\)\n\t\tcr\.mu\.Unlock\(\)\n\t\ttime\.Sleep\(100 \* time\.Millisecond\)\n\t\tcr\.mu\.Lock\(\)\n\t\}\n/' \
  's/\tif !cr\.active \|\| cr\.aborter == nil \|\| cr\.generation != gen \{\n\t\treturn canary\.TripCanaryLatched\n\t\}\n//'


# ── (2) THE ACTIVATION GUARDS ───────────────────────────────────────────────

run_mutation M03 \
  'an inactive runtime is treated as an activation that can be attributed to' \
  'TestAtomicBinding_InactiveRuntimeIsNotAnActivation' \
  . "$ADM" \
  's/\tif !cr\.active \|\| cr\.enforcer == nil \|\| cr\.aborter == nil \|\| cr\.generation == 0 \{/\tif cr\.enforcer == nil \|\| cr\.aborter == nil \{/'

run_mutation M04 \
  'a zero generation is accepted as an activation (the abort wildcard)' \
  'TestAtomicBinding_ActiveWithZeroGenerationIsNotAnActivation' \
  . "$ADM" \
  's/\tif !cr\.active \|\| cr\.enforcer == nil \|\| cr\.aborter == nil \|\| cr\.generation == 0 \{/\tif !cr\.active \|\| cr\.enforcer == nil \|\| cr\.aborter == nil \{/'

# ── (3) THE LATCH ───────────────────────────────────────────────────────────

run_mutation M06 \
  'an authoritative drift denies the request but never latches the active generation' \
  'TestAtomicBinding_A_DriftLatchesTheActiveGeneration' \
  . "$ADM" \
  's/\t\tres := rt\.tripLockedForGeneration\(cr, capb, driftCode, gen, now\)/\t\tres := canary\.TripRequestScoped\n\t\t_ = res/'

run_mutation M07 \
  'the drift is latched against whatever generation is current at trip time' \
  'TestAtomicBinding_C_ObservationCanNeverLatchTheReplacementActivation' \
  . "$ADM" \
  's/\t\tres := rt\.tripLockedForGeneration\(cr, capb, driftCode, gen, now\)/\t\tcr\.mu\.Unlock\(\)\n\t\ttime\.Sleep\(100 \* time\.Millisecond\)\n\t\tcr\.mu\.Lock\(\)\n\t\tres := rt\.tripLockedForGeneration\(cr, capb, driftCode, cr\.generation, now\)/'

# ── (4) THE RESERVATION ─────────────────────────────────────────────────────

run_mutation M05 \
  'trust is taken under G and the reservation is taken under whatever is current' \
  'TestAtomicBinding_E_TrustAndReservationShareOneGeneration' \
  . "$ADM" \
  's/\toutcome := rt\.reserveLocked\(cr, capb, gen, now, ident\)/\tcr\.mu\.Unlock\(\)\n\ttime\.Sleep\(100 \* time\.Millisecond\)\n\tcr\.mu\.Lock\(\)\n\toutcome := rt\.reserveLocked\(cr, capb, cr\.generation, now, ident\)/'

run_mutation M09 \
  'the budget reservation is moved outside the generation transaction' \
  'TestAtomicBinding_E_TrustAndReservationShareOneGeneration' \
  . "$ADM" \
  's/\toutcome := rt\.reserveLocked\(cr, capb, gen, now, ident\)/\tcr\.mu\.Unlock\(\)\n\ttime\.Sleep\(100 \* time\.Millisecond\)\n\toutcome, _ := rt\.reserveCanaryExecution\(capb, now, ident\)\n\tcr\.mu\.Lock\(\)/'

# ── (5) THE FINAL BOUNDARY (must remain undisturbed) ────────────────────────
# §9: the emergency kill stays the LAST security check before the irreversible call. This
# work is pre-admission and must not have moved it.

run_mutation M10 \
  'the final emergency-kill re-read is weakened at the side-effect boundary' \
  'TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\tif e\.cfg\.State\.KillGeneration\(\) != admKillGen \{/\tif false \{/'

# ── (6) THE PRE-EXECUTOR DRIFT LATCH ───────────────────────────────────────
# Codex round 20: a rug-pull landing BEFORE policy resolution is refused upstream of the
# admission transaction, and later requests resolve cleanly against the new fingerprint and
# fail approval validation — request-scoped, not drift. So a whole-Canary breach condition
# that is only ever latched inside admitLiveExecution stops nothing at all.
#
# M11 is deliberately aimed at the WIRING rather than the primitive: the §8 matrix drives
# latchDriftUnderActivation directly and stays green when the sink stops calling it.

run_mutation M11 \
  'the pre-executor path counts the drift as evidence and never latches' \
  'TestPreAdmissionDrift_E2E_ServerIdentityDriftStopsTheActivation' \
  . "$ADM" \
  's/\tglobalCanaryRuntime\.latchDriftUnderActivation\(.*?\n\t\}\)\n/\t_ = capb\n\t_ = now\n/s'

run_mutation M12 \
  'the latch trusts the callers unlocked verdict instead of re-deriving under the lock' \
  'TestAtomicBinding_I_PreExecutorLatchNeverInventsABreach' \
  . "$ADM" \
  's/\tcode := ""\n\tif trust != nil \{\n\t\t_, code = trust\(\)\n\t\}\n/\tcode := "tool_fingerprint_drift"\n/'

run_mutation M13 \
  'a pre-executor drift seen in the publication gap latches the next activation' \
  'TestAtomicBinding_H_PreExecutorDriftInThePublicationGapLatchesNothing' \
  . "$ADM" \
  's/\tif !cr\.active \|\| cr\.aborter == nil \|\| cr\.generation == 0 \{\n\t\t\/\/ §6 THE PUBLICATION GAP\./\tif false \{\n\t\t\/\/ §6 THE PUBLICATION GAP\./'

run_mutation M14 \
  'the drift target is dropped, so the root re-derives against an unmatchable target' \
  'TestCanaryBreach_PreExecutorDriftCarriesItsTarget' \
  ./internal/mcp/runtime/ internal/mcp/runtime/execute.go \
  's/\t\t\tServerID:   toolServerID\(in\),/\t\t\tServerID:   "",/'

# ── (8) TRUST IS EVALUATED WHOLLY INSIDE THE TRANSACTION ───────────────────
# Round 22: hoisting the approval lookup out of the lock to satisfy §5 bought a worse
# defect — a revocation landing during the lock wait was missed, and nothing downstream
# re-reads approval status. The store read is lock-free at the source instead.

run_mutation M16 \
  'the approval verdict is read before the lock and cached across it' \
  'TestAtomicBinding_ApprovalIsEvaluatedInsideTheTransaction' \
  . mcp_live_gate.go \
  's/\tadm := g\.admitUnderActivation\(in\.Now, canary\.ExecutionIdentity\{/\tpreHoist := g.trustPrecheck(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint)\n\thoistOK, hoistCode := false, ""\n\tif preHoist.Eligible \{ hoistOK, hoistCode = g.approvalOK(preHoist.Target, in.Now) \}\n\tadm := g.admitUnderActivation(in.Now, canary.ExecutionIdentity{/; s/\t\treturn g\.approvalOK\(live\.Target, in\.Now\)/\t\treturn hoistOK, hoistCode/'

run_mutation M18 \
  'the live-approval read takes the durable store lock again' \
  'TestLiveView_ActiveLiveApprovalsTakesNoStoreLock' \
  ./internal/mcp/tooltrust/ internal/mcp/tooltrust/store.go \
  's/\tview := s\.liveView\.Load\(\)/\ts.mu.Lock()\n\tdefer s.mu.Unlock()\n\tview := s.liveView.Load()/'

run_mutation M19 \
  'the commit chokepoint stops republishing the lock-free view' \
  'TestLiveView_EveryMutatorRepublishes' \
  ./internal/mcp/tooltrust/ internal/mcp/tooltrust/store.go \
  's/\ts\.publishLiveViewLocked\(\)\n\treturn nil\n\}\n\n\/\/ capacityCheckLocked/\treturn nil\n}\n\n\/\/ capacityCheckLocked/'

run_mutation M20 \
  'Load stops republishing, so a recovered store serves an empty view' \
  'TestLiveView_EveryMutatorRepublishes' \
  ./internal/mcp/tooltrust/ internal/mcp/tooltrust/store.go \
  's/\ts\.publishLiveViewLocked\(\)\n\treturn nil\n\}/\treturn nil\n}/'

run_mutation M21 \
  'the lock-free view publishes stored pointers instead of clones' \
  'TestLiveView_SnapshotHoldsClonesNotStoredPointers' \
  ./internal/mcp/tooltrust/ internal/mcp/tooltrust/store.go \
  's/\t\tsnap = append\(snap, a\.clone\(\)\)/\t\tsnap = append(snap, a)/'

# ── (9) THE PRE-EXECUTOR LATCH IS BOUND TO ITS OWN ACTIVATION ──────────────
# Round 22: the activation runtime holds no scope, so a stale observation from a superseded
# activation could stop a replacement whose scope excludes the target. The latch compares the
# generation captured before the resolution against one read inside the lock; generations are
# monotonic, so a mismatch means an activation intervened.

run_mutation M22 \
  'the latch ignores which activation the observation was made under' \
  'TestPreAdmissionDrift_E2E_StaleObservationCannotStopTheReplacement' \
  . "$ADM" \
  's/\tif cr\.generation != wantGen \{/\tif false \{/'

run_mutation M23 \
  'generation 0 is read as whatever is current (the round-18 wildcard)' \
  'TestPreAdmissionDrift_E2E_GenerationZeroLatchesNothing' \
  . "$ADM" \
  's/\tif wantGen == 0 \{.*?\n\t\treturn canaryDriftLatch\{\}\n\t\}\n//s; s/\tif cr\.generation != wantGen \{/\tif wantGen != 0 \&\& cr.generation != wantGen \{/'

run_mutation M24 \
  'the pipeline reports no generation, silently disabling every pre-executor latch' \
  'TestCanaryBreach_PreExecutorDriftCarriesItsTarget' \
  ./internal/mcp/runtime/ internal/mcp/runtime/execute.go \
  's/\t\t\tGeneration: genAtResolve,/\t\t\tGeneration: 0,/'

# ── (10) THE RUG-PULL LATCHES INSIDE THE TRANSACTION ───────────────────────
# Rounds 20 and 23: after a rug-pull the catalog settles at F2, so every later request is
# decided against F2 and the fingerprint comparison sees no drift — the breach read as
# ordinary unauthorized traffic and stopped nothing. The approval still pinned to F1 is the
# evidence, and it is available where the transaction already owns the activation lock.

run_mutation M25 \
  'the rug-pull reason is dropped, so the breach reads as a missing approval' \
  'TestLiveTrustRevalidate_RugPullReportsDriftNotMissingApproval' \
  . mcp_live_gate.go \
  's/\tif reviewedElsewhere \{\n\t\treturn false, "tool_fingerprint_drift"\n\t\}\n/\t_ = reviewedElsewhere\n/'

run_mutation M26 \
  'EVERY approval failure is classified as drift (the control)' \
  'TestLiveTrustRevalidate_UnapprovedIsNotDrift' \
  . mcp_live_gate.go \
  's/\tif reviewedElsewhere \{/\tif reviewedElsewhere || true \{/'

run_mutation M27 \
  'the lock-free view hands out its shared records instead of copies' \
  'TestLiveView_ReturnedRecordsAreCallerOwned' \
  ./internal/mcp/tooltrust/ internal/mcp/tooltrust/store.go \
  's/caller-owned records keeps that contract exactly \(Codex round 23\)\.\n\t\t\tout = append\(out, a\.clone\(\)\)/caller-owned records keeps that contract exactly (Codex round 23).\n\t\t\tout = append(out, a)/'

# ── (11) THE REVIEWED-TARGET OBSERVATION IS ABOVE EVERY EARLY RETURN ───────
# Round 24: dispatchPolicy returns from three places above the executor, and the F1→F2
# republish this mechanism exists to catch is commonly a schema change — which hard-fails
# inspection for every request still sending the old argument shape. Emitting below that
# return means the change hides its own evidence.

run_mutation M28 \
  'the reviewed-target observation is emitted below the inspection hard-fail return' \
  'TestCanaryReviewedTarget_(ReportedWhenInspectionHardFails|EmissionIsAboveEveryReturnInDispatchPolicy)' \
  ./internal/mcp/runtime/ internal/mcp/runtime/policy.go \
  's/\tobsServerID, obsToolName := p\.canaryObservedTarget\(req, msg\)\n\tp\.deps\.noteCanaryTargetObserved\(.*?\n\t\}\)\n//s' \
  's/\td, _, _ := p\.policyEngine\.Evaluate/\tobsServerID, obsToolName := p.canaryObservedTarget(req, msg)\n\tp.deps.noteCanaryTargetObserved(p.capability.String(), CanaryTargetObservation{Generation: p.deps.canaryGenerationAt(p.capability.String()), ServerID: obsServerID, ToolName: obsToolName})\n\td, _, _ := p.policyEngine.Evaluate/'

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
