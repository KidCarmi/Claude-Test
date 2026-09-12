#!/usr/bin/env bash
# mcp-canary-read-first-classification-mutations.sh — the §11 campaign for EXACT READ-FIRST
# TOOL CLASSIFICATION (blocker #4).
#
# Each mutation reintroduces ONE specific way a tools/call could be classified read-first without
# authority, then runs the NAMED gate that must catch it. A mutation that no test rejects is not a
# passing mutation: it is a hole in the gates.
#
# The twelve the specification requires, in order:
#
#   M01  a server-shaped hint parses into a reviewed determination
#   M02  a tool-NAME heuristic promotes the call
#   M03  a missing reviewed classification defaults to read
#   M04  F2 inherits F1's read-only classification
#   M05  the classifier ignores the fingerprint FORMAT
#   M06  policy sees write while the live gate sees read
#   M07  the classifier seam widens so a per-request value can reach it
#   M08  an unknown tool is classified
#   M09  a restart restores an unclassifiable record as armed
#   M10  a same-generation update mutates the classification
#   M11  a stale F1 decision reaches upstream after F1→F2
#   M12  tools/list is used as a substitute for exact tool execution
#
# Two more the campaign added because the code made them reachable:
#
#   M13  the read-first gate itself stops refusing a write-class operation
#   M14  the promotion is computed and then dropped before it reaches the decision tuple
#   M15  the classification outlives the activation that made it (Codex P1)
#   M16  the boundary revalidation reads an unspeakable record as agreement
#
# And the STALE-AUTHORIZATION family (Codex P1, round 2) — the same defect one axis over, where
# the fact decided at resolution is the rollout SCOPE rather than the operation class:
#
#   M17  the scope hash is not carried from resolution
#   M18  admission ignores the scope hash
#   M19  a missing scope hash is treated as a match
#   M20  admission compares only the generation, not scope identity
#   M21  a principal-only recheck misses a tool/server/exclusion scope edit
#   M22  the post-admission window is not revalidated for scope
#   M23  the boundary stops re-asking the live approval
#   M24  the executor does not supply the pre-send re-ask
#   M25  the upstream client never invokes the pre-send re-ask
#   M26  a boundary withdrawal is diagnosed by a fixed reason, not the gate's
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall whose stated purpose
# is compile-time prevention (those declare --compile-wall). Every other mutation here is written to
# compile and change behaviour, so the failure comes from an assertion.
#
# Usage:  scripts/mcp-canary-read-first-classification-mutations.sh [-k]
#         (-k: keep going after a surviving mutation; default stops at the first survivor)
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


printf 'MCP Canary READ-FIRST TOOL CLASSIFICATION mutation campaign\n'
printf '==========================================================\n'

REVOP=internal/mcp/tooltrust/reviewed_operation.go
REVIEWED=internal/mcp/canary/reviewed.go
RTPOLICY=internal/mcp/runtime/policy.go
RTDEPS=internal/mcp/runtime/deps.go
LIVEGATE=internal/mcp/execution/livegate.go
ROOTCLS=mcp_canary_read_first.go
RTSTATE=mcp_canary_runtime.go
LGATE=mcp_live_gate.go
ADM=mcp_canary_admission.go

# M01 — the SERVER's own vocabulary becomes Culvert's. A hint spelling parses into a reviewed
# determination, so anything that reaches the parser with "true" is read-only by assertion.
run_mutation M01 \
  'a server-shaped hint spelling parses into a reviewed read-only determination' \
  'TestReadFirstClass_C03_ServerHintIsNotAnInputToClassification' \
  . "$REVOP" \
  's/\tcase "read_only":\n\t\treturn ReviewedOpReadOnly, true/\tcase "read_only", "true", "readonly":\n\t\treturn ReviewedOpReadOnly, true/'

# M02 — a tool-NAME heuristic replaces the reviewed answer. "get_", "list_", "x" are conventions,
# not contracts, and a convention is trivially chosen by whoever names the tool.
run_mutation M02 \
  'a tool-name heuristic promotes the call instead of the reviewed classification' \
  'TestReadFirstRuntime_NonAffirmativeAnswersStayWrite' \
  ./internal/mcp/runtime "$RTPOLICY" \
  's/\tif p\.deps\.canaryReviewedReadFirst\(p\.capability\.String\(\), serverID, toolName\) \{\n\t\top\.Class = policy\.OpRead\n\t\}/\tif strings.HasPrefix(toolName, "x") || strings.HasPrefix(toolName, "get_") {\n\t\top.Class = policy.OpRead\n\t}/' \
  's/import \(\n\t"context"\n/import (\n\t"context"\n\t"strings"\n/'

# M03 — the MISSING answer becomes the permissive one: an activation arms carrying a target whose
# class nobody stated, and the unstated class reads as read.
run_mutation M03 \
  'a missing reviewed classification is admitted and defaults to read' \
  'TestReadFirstClass_C02_ReviewedTargetWithNoClassCannotArm' \
  . "$REVIEWED" \
  's/\t\tcase t\.OperationClass == policy\.OpUnset:\n\t\t\treturn ReviewedTargetSet\{\}, ReviewedNoOperationClass\n//' \
  's/\treturn \[\]policy\.OperationClass\{policy\.OpRead, policy\.OpWrite, policy\.OpDestructive\}/\treturn []policy.OperationClass{policy.OpUnset, policy.OpRead, policy.OpWrite, policy.OpDestructive}/' \
  's/func OperationClassFromReviewed\(c tooltrust\.ReviewedOperationClass\) \(policy\.OperationClass, bool\) \{\n\tswitch c \{/func OperationClassFromReviewed(c tooltrust.ReviewedOperationClass) (policy.OperationClass, bool) {\n\tswitch c {\n\tcase tooltrust.ReviewedOpUnset:\n\t\treturn policy.OpRead, true/'

# M04 — THE HEADLINE DEFECT. The classification stops being fingerprint-bound: it is looked up by
# (tenant, server, tool) alone, so a tool that republishes inherits the classification of the tool
# that was reviewed.
run_mutation M04 \
  'F2 inherits F1 read-only classification (the lookup stops consulting Compare)' \
  'TestReadFirstClass_C04_F2DoesNotInheritF1ReadClassification' \
  . "$REVIEWED" \
  's/\tif s\.Compare\(cur\) != ReviewedMatches \{\n\t\treturn policy\.OpUnset, false\n\t\}\n\tfor i := range s\.targets \{ \/\/ index-based: ReviewedTarget carries a 32-byte digest\n\t\tif s\.targets\[i\]\.key\(\) == cur\.key\(\) \{/\tfor i := range s.targets {\n\t\tif s.targets[i].key() == cur.key() {/'

# M05 — the fingerprint FORMAT stops being part of the binding, so two digests are compared without
# an agreed interpretation of what they mean.
run_mutation M05 \
  'the classifier ignores the fingerprint FORMAT version' \
  'TestReadFirstClass_FingerprintFormatIsPartOfTheBinding' \
  . "$REVIEWED" \
  's/\t\tif r\.Fingerprint != cur\.Fingerprint \|\| r\.FingerprintFormat != cur\.FingerprintFormat \{/\t\tif r.Fingerprint != cur.Fingerprint {/'

# M06 — POLICY AND EXECUTION DISAGREE. The live gate recomputes the class instead of reading the
# one the decision carried, so an authorized write is admitted as a read.
run_mutation M06 \
  'the live gate sees read while policy decided write (a SECOND classification)' \
  'TestReadFirstParity_GateReceivesTheDecidedClass|TestReadFirstParity_ClassIsReadFromTheDecisionAndNowhereElse' \
  ./internal/mcp/execution "$LIVEGATE" \
  's/\t\tOperation:   in\.Input\.Operation\.Class,/\t\tOperation:   policy.OpRead,/'

# M07 — THE SEAM WIDENS. A fourth parameter appears, through which a per-request value (arguments,
# a hint, a catalog annotation) can reach the classification decision.
run_mutation M07 \
  'the classifier seam widens so a per-request value can reach the decision' \
  'TestReadFirstClass_C01_ExactReviewedReadOnlyToolClassifiesAsRead' \
  --compile-wall . "$RTDEPS" \
  's/\tCanaryOperationClass func\(capability string, serverID, toolName string\) \(policy\.OperationClass, bool\)/\tCanaryOperationClass func(capability string, serverID, toolName, arguments string) (policy.OperationClass, bool)/' \
  's/\tclass, ok := d\.CanaryOperationClass\(capability, serverID, toolName\)/\tclass, ok := d.CanaryOperationClass(capability, serverID, toolName, "")/'

# M08 — an UNKNOWN tool is routed through the classifier. A tool Culvert cannot identify is the last
# thing that should be able to come back read-only.
run_mutation M08 \
  'an unknown (uncataloged) tool is routed through the classifier' \
  'TestReadFirstRuntime_UnknownToolIsNeverClassified' \
  ./internal/mcp/runtime "$RTPOLICY" \
  's/\ttl\.Disposition, tl\.Drift = policy\.DispQuarantined, policy\.DriftUnknownTool\n\tin\.Tool = tl\n\}/\ttl.Disposition, tl.Drift = policy.DispQuarantined, policy.DriftUnknownTool\n\tin.Tool = tl\n\tp.classifyReadFirstToolCall(op, serverID, name)\n}/'

# M09 — a RESTART loses the classification and the record comes back armed anyway, so the
# activation runs for the rest of its window unable to say what it was reviewed as.
run_mutation M09 \
  'a restart restores an unclassifiable reviewed record as ARMED' \
  'TestReadFirstClass_DurableRecordWithoutAClassDoesNotRestoreArmed' \
  . "$RTSTATE" \
  's/\trestoredReviewed, rr := canary\.CanonicalizeReviewedTargets\(st\.ReviewedTargets\)\n\tif rr != canary\.ReviewedOK \{/\trestoredReviewed, rr := canary.CanonicalizeReviewedTargets(st.ReviewedTargets)\n\tif false \&\& rr != canary.ReviewedOK {/'

# M10 — the SAME GENERATION is allowed to rebind its classification, so the control plane can
# promote a reviewed-mutating tool to read-only with nobody reviewing it.
run_mutation M10 \
  'a same-generation update may mutate the reviewed classification' \
  'TestReadFirstClass_C12_SameGenerationCannotMutateTheClassification' \
  . "$REVIEWED" \
  's/\t\tif s\.targets\[i\] != o\.targets\[i\] \{\n\t\t\treturn false\n\t\t\}/\t\tif s.targets[i].key() != o.targets[i].key() {\n\t\t\treturn false\n\t\t}/'

# M11 — a STALE decision reaches upstream: the fingerprint boundary stops being revalidated, so a
# request decided under F1 executes against F2.
#
# It takes TWO edits, and that is a finding rather than an inconvenience: the boundary is guarded
# twice, independently — the trust precheck revalidates the DECISION's fingerprint against current
# inventory, and the approval binds the tool it was granted for. Removing either alone changes
# nothing observable, because the other still denies; only removing both reintroduces the defect.
# A single-edit version of this mutation SURVIVED for exactly that reason, which is worth the
# comment: a survivor is not always a missing gate, sometimes it is a mutation that never managed
# to break anything.
run_mutation M11 \
  'a stale F1 decision reaches upstream after the target became F2 (BOTH fingerprint guards removed)' \
  'TestReadFirstClass_StaleF1DecisionIsRefusedAfterF2' \
  . "$LGATE" \
  's/\tif hex\.EncodeToString\(ti\.target\.Fingerprint\[:\]\) != decisionFP \{/\tif false \&\& hex.EncodeToString(ti.target.Fingerprint[:]) != decisionFP {/' \
  's/\treturn liveTrustPrecheck\{\n\t\tEligible: true,\n\t\tTarget: canary\.LiveTarget\{/\tclaimed := ti.target.Fingerprint\n\tif raw, derr := hex.DecodeString(decisionFP); derr == nil \&\& len(raw) == len(claimed) \{\n\t\tcopy(claimed[:], raw)\n\t\}\n\treturn liveTrustPrecheck{\n\t\tEligible: true,\n\t\tTarget: canary.LiveTarget{/' \
  's/\t\t\tFingerprint:       ti\.target\.Fingerprint,/\t\t\tFingerprint:       claimed,/'

# M12 — DISCOVERY IS USED AS THE SUBSTITUTE. A tools/call is defaulted to OpDiscovery, so it passes
# the read-first gate with no review at all — blocker #4 "closed" by pretending a listing is an
# invocation.
run_mutation M12 \
  'a tools/call is defaulted to OpDiscovery so it passes the read-first gate unreviewed' \
  'TestReadFirstRuntime_NoClassifierLeavesTheConservativeDefault' \
  ./internal/mcp/runtime "$RTPOLICY" \
  's/\tdefault: \/\/ tools\/call\n\t\t\/\/ Conservative default: a tool call is a write unless a later slice supplies a\n\t\t\/\/ finer class\. Destructive is NEVER assumed\.\n\t\top\.Class = policy\.OpWrite/\tdefault: \/\/ tools\/call\n\t\top.Class = policy.OpDiscovery/'

# M13 — THE READ-FIRST GATE IS DISABLED. Classification without a gate that consumes it is
# decoration: a write-class operation would cross the First-Canary boundary unremarked.
#
# It takes TWO edits, and the second one did not exist when this mutation was written. The
# boundary revalidation added for the Codex P1 (step 5b) requires the request's class to EQUAL the
# one the activation binds, so it refuses an OpWrite request on its own — and this mutation, which
# caught the defect before that guard existed, stopped reintroducing anything the moment the guard
# landed. That is the third time in this campaign a single-edit mutation was neutralised by an
# independent twin (see M03 and M11); it is defense-in-depth working, and it is also why a survivor
# is re-read before it is believed.
run_mutation M13 \
  'the read-first gate stops refusing a write-class operation (BOTH class gates removed)' \
  'TestReadFirstClass_LiveGateAdmitsTheReadClassAndRefusesTheWriteClass' \
  . "$LGATE" \
  's/\tif !g\.readFirst\(in\.Operation\) \{/\tif false \&\& !g.readFirst(in.Operation) {/' \
  's/\t\t\treturn globalCanaryRuntime\.admitLiveExecution\(capb, now, opClass, resolvedScope, scopeNow, ident, trust\)/\t\t\t_ = opClass\n\t\t\treturn globalCanaryRuntime.admitLiveExecution(capb, now, policy.OpRead, resolvedScope, scopeNow, ident, trust)/'

# M14 — THE PROMOTION IS DROPPED ON THE FLOOR. `in.Operation = op` moves ABOVE the call that may
# promote it, so the classification is computed correctly and then never reaches the decision tuple.
#
# It is in the campaign because it is the quietest way this feature can stop working: nothing fails
# to compile, nothing refuses, the classifier is consulted and answers correctly, and every
# fail-closed gate still passes — the exact reviewed call is simply denied read-first forever, with
# no signal anywhere. Only a gate that reads the class the EXECUTOR received can see it.
run_mutation M14 \
  'the promotion is computed and then dropped (in.Operation assigned before classification)' \
  'TestReadFirstRuntime_ReviewedReadAnswerPromotesTheToolCall' \
  ./internal/mcp/runtime "$RTPOLICY" \
  's/\top := policyOperation\(p\.capability, msg\.Method, req\.ServerID\)\n\tif p\.capability == protocol\.Gateway \{\n\t\tp\.attachGatewayRefs\(&in, req\.ServerID, msg, &op\)\n\t\}\n\tin\.Operation = op/\top := policyOperation(p.capability, msg.Method, req.ServerID)\n\tin.Operation = op\n\tif p.capability == protocol.Gateway \{\n\t\tp.attachGatewayRefs(&in, req.ServerID, msg, &op)\n\t}/'

# M15 — THE CLASSIFICATION OUTLIVES ITS ACTIVATION. The boundary stops revalidating the class, so a
# read-first decision taken under an activation that has since been replaced by one whose review
# says MUTATING still crosses. Every drift control stays silent, correctly: the target did not move,
# the review of it did (Codex P1, PR #1370).
run_mutation M15 \
  'a read-first decision crosses under an activation whose review says mutating' \
  'TestReadFirstClass_StaleReadClassIsRefusedAfterAReviewSaysMutating' \
  . "$ADM" \
  's/\tif !canaryClassInForce\(cr\.reviewed, obs\.Current, opClass\) \{\n\t\treturn canaryAdmission\{Denial: canaryAdmitClassNotInForce, Active: true, Generation: gen, Outcome: canary\.BudgetDeniedInvalid\}\n\t\}\n//'

# M16 — THE BOUNDARY CLASS REVALIDATION IS DISABLED. The predicate answers "still in force" for
# every request, so step (5b) stops refusing anything: the round-1 P1 is reintroduced at the
# transaction level, where M15 reintroduces it end to end. Two gates for one defect is deliberate —
# M15 drives the full G1→G2 sequence through the real gate, M16 pins the transaction itself.
#
# It is NOT written as "drop the !ok half", which is what the predicate's most interesting clause
# would suggest, because that mutation SURVIVES — the fourth instance of this campaign's recurring
# pattern. `!ok` means `Compare` did not return ReviewedMatches, and every request that can reach
# (5b) in that state has already been refused by step (5)'s ReviewedOutOfScope branch or, failing
# that, by the trust probe at (6), which has no live approval for a target nobody reviewed.
# Removing all three to make it reachable would no longer be a mutation of THIS invariant. So the
# !ok half stays what it is: defense in depth with no independently reachable case today, kept
# because the reachability argument depends on two guards that live elsewhere and could move.
run_mutation M16 \
  'the boundary class revalidation admits every class' \
  'TestAtomicBinding_I_ClassNotInForceIsRefused' \
  . "$ADM" \
  's/\tgot, ok := reviewed\.OperationClassFor\(current\)\n\treturn ok \&\& got == opClass/\tgot, ok := reviewed.OperationClassFor(current)\n\t_, _ = got, ok\n\treturn true/'

RESOLVE=internal/mcp/rollout/state.go
EXECUTOR=internal/mcp/execution/executor.go

# M17 — THE ENVELOPE IS NEVER CAPTURED. State.ResolveFor stops stamping the scope it decided
# against, so every request reaches the boundary carrying "" — which the boundary refuses, so the
# visible symptom is the POSITIVE control failing, not a permissive hole. That is the point: a
# fact that is not captured cannot be revalidated, and the gate that proves the happy path is the
# one that notices.
run_mutation M17 \
  'the scope hash is never captured at resolution' \
  'TestScopeInForce_EnvelopeIsCarriedFromResolutionToTheBoundary' \
  . "$RESOLVE" \
  's/\tr\.ScopeHash = a\.scope\.Hash\(\)\n//'

# M18 — ADMISSION IGNORES IT. The envelope is captured and carried and then not compared: the
# defect exactly as it stood before this fix.
run_mutation M18 \
  'the admission boundary ignores the scope hash' \
  'TestScopeInForce_StaleRequestRefusedAfterSameModeScopeUpdate' \
  . "$ADM" \
  's/\tif !canaryScopeInForce\(resolvedScope, scopeNow\) \{\n\t\treturn canaryAdmission\{Denial: canaryAdmitScopeNotInForce, Active: true, Generation: gen, Outcome: canary\.BudgetDeniedInvalid\}\n\t\}\n//'

# M19 — A MISSING ENVELOPE BECOMES A WILDCARD. The comparison keeps working for requests that
# carry a hash and silently exempts every request that does not — which is exactly the set that
# skipped the path that stamps it.
run_mutation M19 \
  'a missing scope hash is treated as a match' \
  'TestScopeInForce_MissingEnvelopeFailsClosed' \
  . "$ADM" \
  's/\tif scopeNow == nil \|\| resolvedScope == "" \{\n\t\treturn false\n\t\}/\tif scopeNow == nil \|\| resolvedScope == "" \{\n\t\treturn true\n\t\}/'

# M20 — GENERATION INSTEAD OF SCOPE IDENTITY. The plausible wrong fix: assume a scope change
# always mints a new generation, so comparing generations is enough. It is not — a SAME-MODE
# scope update deliberately keeps the generation, which is the whole reason the finding exists.
run_mutation M20 \
  'admission compares only the activation generation, not scope identity' \
  'TestScopeInForce_StaleRequestRefusedAfterSameModeScopeUpdate' \
  . "$ADM" \
  's/\tif !canaryScopeInForce\(resolvedScope, scopeNow\) \{/\tif gen == 0 \{/'

# M21 — PRINCIPAL-ONLY RECHECK. The other plausible wrong fix, and the reason hash equality was
# chosen: re-running membership for the principal closes the headline case and leaves every
# sibling dimension open. Modelled by comparing only the principal-bearing prefix of the two
# envelopes, so a principal edit is still caught and a tool/server/exclusion edit is not.
run_mutation M21 \
  'a principal-only recheck misses a tool/server/exclusion scope edit' \
  'TestScopeInForce_AnySelectorEditRefusesTheStaleRequest' \
  . "$ADM" \
  's/\tif !canaryScopeInForce\(resolvedScope, scopeNow\) \{/\tif cur := scopeNow; cur == nil \|\| resolvedScope == "" \|\| ident.Principal == "" \{/'

GATE=mcp_live_gate.go

# M22 — THE POST-ADMISSION WINDOW REOPENS. Step (5c) stays, so every direct-admission gate above
# still passes; only the FINAL-boundary half is removed. Admission then proves the envelope was in
# force at its own instant and nothing revalidates it across credential materialization, the
# durable commit and connection setup — exactly the window the kill re-read exists for. A scope
# update landing there is invisible, because a same-mode update deliberately leaves the activation
# generation alone and the generation half of Revalidate is all that is left.
run_mutation M22 \
  'the authorization envelope is not revalidated in the post-admission window' \
  'TestScopeInForce_ScopeWithdrawnAfterAdmissionRefusesBeforeUpstream' \
  . "$GATE" \
  's/\t\t\tif !canaryScopeInForce\(in\.ResolvedScopeHash, g\.currentScopeHash\) \{\n\t\t\t\treturn false\n\t\t\t\}\n//'

RUN=internal/mcp/execution/run.go
UCLIENT=internal/mcp/upstreamclient/client.go

# M23 — THE APPROVAL IS NOT RE-ASKED. Round 22 moved the approval lookup INTO the admission
# transaction so a revocation racing the lock could not be admitted, and recorded that the final
# boundary re-reads "tool freshness, generation and kill state, not approval status". This is that
# residual: a four-eyes grant revoked while the request waited on the durable commit or a pool slot.
# Neither the scope nor the generation moves when an approval is withdrawn.
run_mutation M23 \
  'the boundary stops re-asking the live approval' \
  'TestBoundaryAuthority_ApprovalRevokedAfterAdmissionRefusesBeforeUpstream' \
  . "$GATE" \
  's/\t\t\tif g\.approvalOK != nil \&\& g\.trustPrecheck != nil \{/\t\t\tif false \{/'

# M24 — THE EXECUTOR DOES NOT SUPPLY THE RE-ASK. The hook still exists and the client still honours
# it; the executor simply hands over one that always permits, so the pool wait is unguarded again.
run_mutation M24 \
  'the executor supplies a pre-send re-ask that always permits' \
  'TestBoundaryAuthority_ScopeWithdrawnDuringThePoolWaitRefusesBeforeSend' \
  . "$RUN" \
  's/AttemptID: attemptIDOf\(attempt\), PreSend: preSend,/AttemptID: attemptIDOf(attempt), PreSend: func() error \{ _ = preSend; return nil \},/'

# M25 — THE CLIENT NEVER INVOKES IT. The other half of the same contract, and the half the root
# gates cannot see: the root double calls the hook itself, deliberately, so that the executor's
# half is proven independently of the client's. Gated inside the client's own package.
run_mutation M25 \
  'the upstream client never invokes the pre-send re-ask' \
  'TestPreSend_RefusalStopsTheCallWithNothingSent' \
  ./internal/mcp/upstreamclient "$UCLIENT" \
  's/\t\tif opts\.PreSend != nil \{\n\t\t\tif perr := opts\.PreSend\(\); perr != nil \{\n\t\t\t\tif attempt == 0 \{\n\t\t\t\t\treturn nil, markNeverSent\(perr\)\n\t\t\t\t\}\n\t\t\t\treturn nil, markLegFacts\(perr, call\)\n\t\t\t\}\n\t\t\}\n//'

# M26 — THE REFUSAL IS DIAGNOSED BY A FIXED REASON. The bug this reintroduces is not a bypass: the
# request is still refused. It is that the SAME scope mismatch reads rollout_out_of_scope when
# admission catches it and rollout_mode_invalid when the boundary does — two contradictory answers
# for one fact, separated only by timing, in the telemetry an operator reads during an incident.
run_mutation M26 \
  'a boundary withdrawal is diagnosed by a fixed reason, not the gate own' \
  'TestBoundaryAuthority_ScopeWithdrawnDuringThePoolWaitRefusesBeforeSend' \
  . "$RUN" \
  's/\t\t\t\tr := cls\.withdrawnReason/\t\t\t\tr := mcperr.ReasonNone\n\t\t\t\t_ = cls.withdrawnReason/'

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
