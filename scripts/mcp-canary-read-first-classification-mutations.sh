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
  's/\t\t\tFingerprint:       ti\.target\.Fingerprint,/\t\t\tFingerprint:       mustDecodeDecisionFP(decisionFP, ti.target.Fingerprint),/' \
  's/\/\/ mcpLiveApprovalSatisfied answers the APPROVAL half/\/\/ mustDecodeDecisionFP is mutation scaffolding.\nfunc mustDecodeDecisionFP(fp string, fallback tooltrust.FingerprintDigest) tooltrust.FingerprintDigest \{\n\traw, err := hex.DecodeString(fp)\n\tif err != nil || len(raw) != len(fallback) \{\n\t\treturn fallback\n\t\}\n\tvar out tooltrust.FingerprintDigest\n\tcopy(out[:], raw)\n\treturn out\n\}\n\n\/\/ mcpLiveApprovalSatisfied answers the APPROVAL half/'

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
run_mutation M13 \
  'the read-first gate stops refusing a write-class operation' \
  'TestReadFirstClass_LiveGateAdmitsTheReadClassAndRefusesTheWriteClass' \
  . "$LGATE" \
  's/\tif !g\.readFirst\(in\.Operation\) \{/\tif false \&\& !g.readFirst(in.Operation) {/'

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
