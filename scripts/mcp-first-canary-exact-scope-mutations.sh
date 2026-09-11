#!/usr/bin/env bash
# mcp-first-canary-exact-scope-mutations.sh — the blocker #5 campaign for EXACT
# First-Canary scope enforcement.
#
# The First Controlled Canary is ONE exact experiment: one tenant, one server, one
# tool, one explicitly named principal. Each mutation below reintroduces ONE way a
# signed scope could authorize more than that — or one way the check could be
# bypassed — and runs the NAMED gate that must catch it. A mutation no test rejects
# is not a passing mutation: it is a hole in the gates.
#
# Two classes of mutation appear here and they are scored differently:
#
#   * WIDENING mutations relax a rule in internal/mcp/canary/firstcanary_scope.go.
#     They must be caught by an assertion in the exact-scope matrix.
#   * BYPASS mutations remove the check from the authoritative activation preflight,
#     or point it at something other than the signed scope. They must be caught by
#     the structural wall, which asks the AST where the verdict is taken.
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall whose
# stated purpose is compile-time prevention. Mutations here are written to compile
# and change behavior, so the failure comes from an assertion.
#
# Usage:  scripts/mcp-first-canary-exact-scope-mutations.sh [-k]   (-k: keep going
#         after a surviving mutation; default stops at the first survivor)
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


printf 'MCP FIRST-CANARY EXACT SCOPE mutation campaign (blocker #5)\n'
printf '===========================================================\n'

FC=internal/mcp/canary/firstcanary_scope.go
PF=mcp_canary_preflight.go
CANARY=./internal/mcp/canary

# ── (1) WIDENING THE ONE EXPERIMENT ─────────────────────────────────────────
# Each of these lets the signed scope authorize more than the ONE reviewed target.

run_mutation M01 \
  'the exact gate allows TWO tools' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tif len\(spec\.Tools\) > 1 \{\n\t\treturn FirstCanaryMultipleTools\n\t\}\n//'

run_mutation M02 \
  'the exact gate allows TWO principals' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\treturn exactlyOneString\(spec\.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals\)/\tif len(spec.Principals) == 0 \{\n\t\treturn FirstCanaryNoPrincipal\n\t\}\n\treturn FirstCanaryScopeOK/'

run_mutation M03 \
  'the identity requirement becomes an AGGREGATE count across principals+clients+agents' \
  'TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.Clients\) > 0:\n\t\treturn FirstCanaryClientsForbidden\n\tcase len\(spec\.Agents\) > 0:\n\t\treturn FirstCanaryAgentsForbidden\n//' \
  's/\treturn exactlyOneString\(spec\.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals\)/\tn := len(spec.Principals) + len(spec.Clients) + len(spec.Agents)\n\tif n == 0 \{\n\t\treturn FirstCanaryNoPrincipal\n\t\}\n\tif n > 1 \{\n\t\treturn FirstCanaryMultiplePrincipals\n\t\}\n\treturn FirstCanaryScopeOK/'

run_mutation M04 \
  'a CLIENT-only identity satisfies the exact-principal requirement' \
  'TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.Clients\) > 0:\n\t\treturn FirstCanaryClientsForbidden\n//' \
  's/\treturn exactlyOneString\(spec\.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals\)/\tif len(spec.Principals) == 0 \&\& len(spec.Clients) == 1 \{\n\t\treturn FirstCanaryScopeOK\n\t\}\n\treturn exactlyOneString(spec.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals)/'

run_mutation M05 \
  'an AGENT-only identity satisfies the exact-principal requirement' \
  'TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.Agents\) > 0:\n\t\treturn FirstCanaryAgentsForbidden\n//' \
  's/\treturn exactlyOneString\(spec\.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals\)/\tif len(spec.Principals) == 0 \&\& len(spec.Agents) == 1 \{\n\t\treturn FirstCanaryScopeOK\n\t\}\n\treturn exactlyOneString(spec.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals)/'

run_mutation M06 \
  'GROUP selectors become an admissible identity binding' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.Groups\) > 0:\n\t\treturn FirstCanaryGroupsForbidden\n//'

run_mutation M07 \
  'a WILDCARD identifier is accepted as a name' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\t\tcase strings\.ContainsAny\(v, firstCanaryGlobChars\):\n\t\t\treturn FirstCanaryWildcardIdentifier\n//'

run_mutation M08 \
  'a PERCENTAGE sub-sample is accepted' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tif spec\.Percent != 0 \{\n\t\treturn FirstCanaryPercentageForbidden\n\t\}\n//'

run_mutation M09 \
  'duplicates are silently DEDUPLICATED into validity instead of rejected' \
  'TestFirstCanary_NeverDeduplicatesAnInvalidSignedScope' \
  "$CANARY" "$FC" \
  's/\tseen := make\(map\[string\]struct\{\}, len\(vals\)\)\n\tfor _, v := range vals \{\n\t\tif _, ok := seen\[v\]; ok \{\n\t\t\treturn dup\n\t\t\}\n\t\tseen\[v\] = struct\{\}\{\}\n\t\}\n\tif len\(vals\) > 1 \{/\tseen := make(map[string]struct\{\}, len(vals))\n\tfor _, v := range vals \{\n\t\tseen[v] = struct\{\}\{\}\n\t\}\n\t_ = dup\n\tif len(seen) > 1 \{/'

run_mutation M10 \
  'a ZERO-principal scope is accidentally accepted' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tif len\(vals\) == 0 \{\n\t\treturn none\n\t\}/\tif len(vals) == 0 \{\n\t\t_ = none\n\t\treturn FirstCanaryScopeOK\n\t\}/'

run_mutation M11 \
  'TWO servers are accepted' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\treturn exactlyOneString\(spec\.Servers, FirstCanaryNoServer, FirstCanaryDuplicateServer, FirstCanaryMultipleServers\)/\tif len(spec.Servers) == 0 \{\n\t\treturn FirstCanaryNoServer\n\t\}\n\treturn FirstCanaryScopeOK/'

run_mutation M12 \
  'TWO tenants are accepted (identities are tenant-local, so this widens the WHO axis)' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\treturn exactlyOneString\(spec\.Tenants, FirstCanaryNoTenant, FirstCanaryDuplicateTenant, FirstCanaryMultipleTenants\)/\tif len(spec.Tenants) == 0 \{\n\t\treturn FirstCanaryNoTenant\n\t\}\n\treturn FirstCanaryScopeOK/'

run_mutation M13 \
  'the bare ToolFingerprints dimension — a second, server-unbound tool selector — is allowed' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.ToolFingerprints\) > 0:\n\t\treturn FirstCanaryBareFingerprintsForbidden\n//'

run_mutation M14 \
  'EXCLUSION selectors are allowed, so the signed set is described as "something broader, minus X"' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.ExcludeTenants\) > 0, len\(spec\.ExcludeServers\) > 0,\n\t\tlen\(spec\.ExcludeTools\) > 0, len\(spec\.ExcludePrincipals\) > 0:\n\t\treturn FirstCanaryExclusionsForbidden\n//'

run_mutation M15 \
  'the ENVIRONMENT dimension is allowed' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tcase len\(spec\.Environments\) > 0:\n\t\treturn FirstCanaryEnvironmentsForbidden\n//'

run_mutation M16 \
  'the one tool need not be hosted by the one named server' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tif len\(spec\.Servers\) == 1 \&\& spec\.Tools\[0\]\.Server != spec\.Servers\[0\] \{\n\t\treturn FirstCanaryToolServerMismatch\n\t\}\n//'

run_mutation M17 \
  'an EMPTY identifier is accepted as a name' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\t\tcase v == "":\n\t\t\treturn FirstCanaryEmptyIdentifier\n//'

run_mutation M18 \
  'an identifier past the rollout value bound is accepted' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\t\t\treturn FirstCanaryIdentifierTooLong\n/\t\t\t_ = maxBytes\n/'

run_mutation M19 \
  'a tool selector need not pin server+name+fingerprint' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\t\t\treturn FirstCanaryToolIncomplete\n/\t\t\t_ = t\n/'

run_mutation M20 \
  'the gate stops rejecting a MANAGEMENT-capability scope' \
  'TestFirstCanary_RejectionMatrix' \
  "$CANARY" "$FC" \
  's/\tif spec\.Capability != rollout\.CapabilityGateway \{\n\t\treturn FirstCanaryNotGateway\n\t\}\n//'

# ── (2) BYPASSING THE GATE ──────────────────────────────────────────────────
# The exact shape can be perfectly implemented and still prove nothing if the verdict
# is never taken, taken too late, or taken on the wrong object.

run_mutation M21 \
  'exact-scope validation is SKIPPED in the authoritative activation preflight' \
  'TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied' \
  . "$PF" \
  's/\tf\.ScopeExactFirstCanary = canary\.ValidateFirstCanaryScope\(in\.Scope, in\.ScopeRev\) == canary\.FirstCanaryScopeOK/\tf.ScopeExactFirstCanary = true/'

run_mutation M22 \
  'the preflight validates a REQUEST-DERIVED scope (the tool approvals actually seen) instead of the SIGNED scope' \
  'TestExactScope_EnforcedInTheAuthoritativePreflightNotOnlyAtRuntime' \
  . "$PF" \
  's/\tf\.ScopeExactFirstCanary = canary\.ValidateFirstCanaryScope\(in\.Scope, in\.ScopeRev\) == canary\.FirstCanaryScopeOK/\tnarrowed := in.Scope\n\tif len(in.ToolApprovals) > 0 \{\n\t\tnarrowed.Principals = []string\{in.ToolApprovals[0].Approval.ApprovedBy\}\n\t\tnarrowed.Tools = []rollout.ToolSel\{\{Server: in.ToolApprovals[0].Target.ServerID, Name: in.ToolApprovals[0].Target.ToolName, Fingerprint: in.Scope.Tools[0].Fingerprint\}\}\n\t\}\n\tf.ScopeExactFirstCanary = canary.ValidateFirstCanaryScope(narrowed, in.ScopeRev) == canary.FirstCanaryScopeOK/'

run_mutation M23 \
  'the exact-scope row is downgraded so a wider scope no longer holds the verdict back' \
  'TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied' \
  . internal/mcp/canary/readiness.go \
  's/\t\{func\(f Facts\) bool \{ return f\.ScopeExactFirstCanary \}, ReasonScopeNotExactFirstCanary, factActivation\},\n//'

run_mutation M24 \
  'the exact-scope fact is asserted at NODE level, so a scopeless node advertises exactness' \
  'TestExactScope_ReadinessRowIsActivationLevelAndFailClosed' \
  . "$PF" \
  's/\t\tScopeExactFirstCanary:  false,/\t\tScopeExactFirstCanary:  true,/'

run_mutation M25 \
  'the base Canary scope contract replaces the exact gate (the blocker #5 defect itself)' \
  'TestExactScope_IsNotSatisfiedByTheBoundedScopeRow' \
  . "$PF" \
  's/\tf\.ScopeExactFirstCanary = canary\.ValidateFirstCanaryScope\(in\.Scope, in\.ScopeRev\) == canary\.FirstCanaryScopeOK/\tf.ScopeExactFirstCanary = canary.ValidateScope(in.Scope, in.ScopeRev) == canary.ScopeOK/'

# ── (3) HOLLOWING OUT THE GATE ──────────────────────────────────────────────
# A gate that governs nothing, or one that rejects everything, both pass a careless
# matrix. These pin the two failure modes a rejection-only campaign cannot see.

run_mutation M26 \
  'the gate rejects EVERYTHING, making the first Canary unreachable rather than exact' \
  'TestFirstCanary_CanonicalExperimentPasses' \
  "$CANARY" "$FC" \
  's/\tfor _, check := range firstCanaryChecks \{/\tif true \{\n\t\treturn FirstCanaryNoPrincipal\n\t\}\n\tfor _, check := range firstCanaryChecks \{/'

run_mutation M27 \
  'the canonical experiment stops satisfying the activation row (anti-vacuity at the preflight)' \
  'TestExactScope_CanonicalExperimentSatisfiesTheActivationRow' \
  . "$PF" \
  's/\tf\.ScopeExactFirstCanary = canary\.ValidateFirstCanaryScope\(in\.Scope, in\.ScopeRev\) == canary\.FirstCanaryScopeOK/\tf.ScopeExactFirstCanary = false/'

run_mutation M28 \
  'a governed selector class is dropped from the enumeration, so a new one could arrive un-ruled' \
  'TestFirstCanary_GovernsEverySelectorClass' \
  "$CANARY" "$FC" \
  's/\t"Groups",            \/\/ must be EMPTY\n//'

run_mutation M29 \
  'exactness is implemented by GLOBALLY redefining the Canary architecture cap (the forbidden shortcut)' \
  'TestFirstCanary_ArchitectureBoundsAreNotRedefined' \
  "$CANARY" internal/mcp/canary/scope.go \
  's/\tMaxCanaryTools = 2/\tMaxCanaryTools = 1/'

run_mutation M30 \
  'the exact-scope reason is dropped from the advertised vocabulary, so operators never see the prerequisite' \
  'TestExactScope_ReadinessRowIsActivationLevelAndFailClosed' \
  . internal/mcp/canary/readiness.go \
  's/\t\tReasonScopeNotExactFirstCanary,\n//'

run_mutation M31 \
  'the commit gate builds its activation input from a REQUEST-derived scope instead of the signed config' \
  'TestExactScope_EveryActivationInputCarriesTheSignedScope' \
  . mcp_rollout.go \
  's/\t\t\tScope:              cfg\.Scope,/\t\t\tScope:              narrowedCanaryScope(cfg.Scope, ai.ToolApprovals),/' \
  's/\nfunc \(r \*mcpRollout\) commitRolloutTransitionAt/\nfunc narrowedCanaryScope(s rollout.ScopeSpec, _ []canary.ToolApprovalBinding) rollout.ScopeSpec \{ return s \}\n\nfunc (r *mcpRollout) commitRolloutTransitionAt/'

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
