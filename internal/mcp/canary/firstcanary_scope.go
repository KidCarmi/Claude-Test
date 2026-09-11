package canary

import (
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ---------------------------------------------------------------------------
// EXACT FIRST-CANARY SCOPE (blocker #5)
//
// The First Controlled Canary is specified as ONE exact experiment: one tenant,
// one server, one tool, one explicitly named principal. Nothing else.
//
// ValidateScope (scope.go) enforces the BROADER Canary scope architecture — the
// bounds a later, separately-reviewed graduation phase may raise (MaxCanaryTools,
// MaxCanaryPrincipals, ...). Those constants describe what the Canary MACHINERY
// may eventually carry. They deliberately admit more than the FIRST experiment,
// and they are NOT tightened here: tightening them would silently redefine the
// whole Canary architecture as "always exactly one", which is not the decision
// this gate makes.
//
// So the exact shape is a SEPARATE predicate, applied on top of — never instead
// of — the base contract. ValidateFirstCanaryScope answers exactly one question:
//
//	"Is this signed scope the ONE reviewed first experiment, and nothing wider?"
//
// Four properties are load-bearing and must not be relaxed:
//
//  1. NO AGGREGATE IDENTITY COUNTING. The reviewed shape is literally one NAMED
//     PRINCIPAL. A client is not a principal; an agent is not a principal; a
//     group is not a principal. principalCount() (scope.go) sums
//     Principals+Clients+Agents for the BASE contract's "name somebody" rule —
//     that sum can never satisfy this gate. Here each identity class is judged
//     on its own: Principals must be exactly one, and Clients/Agents/Groups must
//     be EMPTY. A one-client, zero-principal scope is rejected, and removing the
//     client leaves it still rejected (the client contributed nothing positive).
//
//  2. THE SIGNED OBJECT IS THE SUBJECT. Every check reads the RAW ScopeSpec —
//     the signed activation scope — and never a compiled scope, a request, an
//     operator convention, or runtime telemetry. rollout.Compile builds SETS, so
//     it silently collapses [P1,P1] to one principal; validating a compiled scope
//     would therefore DEDUPLICATE AN INVALID SIGNED SCOPE INTO A VALID ONE. The
//     duplicate checks below run on the raw slices for exactly that reason:
//     exactness must be present in the signed bytes, not manufactured by us.
//     "Only one identity ever showed up at runtime" is not exactness either — if
//     the signed scope COULD authorize two, the First Canary is not exact.
//
//  3. EVERY SELECTOR CLASS IS DECIDED EXPLICITLY. firstCanaryGovernedFields
//     enumerates all 19 fields of rollout.ScopeSpec, and a reflection wall
//     (TestFirstCanary_GovernsEverySelectorClass) fails the build if rollout
//     grows a field this gate has not ruled on. A new selector class can never
//     arrive un-governed and quietly widen the first experiment.
//
//  4. IT IS PURE. No clock, no I/O, no package-level state: the same signed
//     scope always yields the same verdict on every node and across restarts.
//
// WHAT AN EMPTY DIMENSION MEANS HERE, stated plainly because it is the one place
// this gate is deliberately not narrowing. In rollout's matcher an EMPTY inclusion
// dimension matches anything, so requiring Clients/Agents/Groups/Environments to be
// empty leaves those attributes UNCONSTRAINED on an admitted request: principal P1
// may arrive through any client id, any agent id, in any group. That is the
// reviewed shape — the experiment names one PRINCIPAL, and pinning a client would
// add a selector class the review did not authorize — and it does not widen the
// identity axis, because every admitted request must still carry PrincipalID == P1.
// The alternative reading, "an empty client dimension authorizes many clients, so
// require exactly one", is what produces the aggregate-counting error this gate
// exists to prevent: it treats a client as an identity peer of a principal.
//
// This gate establishes ONLY that exactly one tool is AUTHORIZED BY SCOPE. It
// establishes nothing about whether a tools/call for that tool is read-first
// EXECUTABLE (the operation-classifier problem), nor that the target is Usable,
// policy-ALLOWed, or has satisfiable obligations. Those are separate,
// still-open prerequisites with their own gates.
// ---------------------------------------------------------------------------

// FirstCanaryScopeReason is a bounded classification for WHY a signed scope is not the
// ONE exact first-Canary experiment. Fixed vocabulary; never interpolated with runtime
// data, so it is safe on a read-only operator surface. FirstCanaryScopeOK ("") is the
// sole admissible value.
//
// It is deliberately DISJOINT from ScopeReason: the base Canary scope contract and the
// exact first-experiment shape are different questions with different futures, and a
// shared vocabulary would let a base-contract change silently redefine exactness.
type FirstCanaryScopeReason string

// The complete exact-first-Canary rejection vocabulary. Declaration order is the
// canonical evaluation order (see ValidateFirstCanaryScope).
const (
	// FirstCanaryScopeOK — the signed scope IS the one exact reviewed experiment.
	FirstCanaryScopeOK FirstCanaryScopeReason = ""

	// -- capability + posture ------------------------------------------------
	// FirstCanaryNotGateway — Canary execution is Gateway-only.
	FirstCanaryNotGateway FirstCanaryScopeReason = "first_canary_not_gateway"
	// FirstCanaryHighRisk — the scope is flagged high-risk (write/destructive capable).
	FirstCanaryHighRisk FirstCanaryScopeReason = "first_canary_high_risk"
	// FirstCanaryOperationsNotExactlyRead — Operations is neither empty (read-only by
	// rollout semantics) nor exactly one RiskRead. A repeated read entry is ambiguity,
	// not a read-only scope.
	FirstCanaryOperationsNotExactlyRead FirstCanaryScopeReason = "first_canary_operations_not_exactly_read"

	// -- non-deterministic sub-sampling --------------------------------------
	// FirstCanaryPercentageForbidden — any percentage sub-sample (Percent != 0).
	FirstCanaryPercentageForbidden FirstCanaryScopeReason = "first_canary_percentage_forbidden"
	// FirstCanaryBucketSaltForbidden — a percentage-bucket salt is present.
	FirstCanaryBucketSaltForbidden FirstCanaryScopeReason = "first_canary_bucket_salt_forbidden"
	// FirstCanaryBucketKeyForbidden — a non-default percentage-bucket key is selected.
	FirstCanaryBucketKeyForbidden FirstCanaryScopeReason = "first_canary_bucket_key_forbidden"

	// -- forbidden selector classes (each named on its own) -------------------
	// FirstCanaryClientsForbidden — a client selector is present. A client is NOT an
	// explicit principal; it can never contribute to the exact-principal requirement.
	FirstCanaryClientsForbidden FirstCanaryScopeReason = "first_canary_clients_forbidden"
	// FirstCanaryAgentsForbidden — an agent selector is present. Same reasoning.
	FirstCanaryAgentsForbidden FirstCanaryScopeReason = "first_canary_agents_forbidden"
	// FirstCanaryGroupsForbidden — a group selector is present. A group expands to a
	// membership set that changes without a scope edit, so it is not an exact identity.
	FirstCanaryGroupsForbidden FirstCanaryScopeReason = "first_canary_groups_forbidden"
	// FirstCanaryEnvironmentsForbidden — an environment selector is present.
	FirstCanaryEnvironmentsForbidden FirstCanaryScopeReason = "first_canary_environments_forbidden"
	// FirstCanaryBareFingerprintsForbidden — the ToolFingerprints dimension is a SECOND,
	// server-unbound tool-selecting class. The one reviewed tool is named by the Tools
	// selector (server+name+fingerprint); a bare fingerprint list must be empty.
	FirstCanaryBareFingerprintsForbidden FirstCanaryScopeReason = "first_canary_bare_tool_fingerprints_forbidden"
	// FirstCanaryExclusionsForbidden — any Exclude* selector is present. The exact shape
	// needs no carve-out; an exclusion in the signed object means the reviewed set was
	// described as "something broader, minus X", which is not one exact experiment.
	FirstCanaryExclusionsForbidden FirstCanaryScopeReason = "first_canary_exclusions_forbidden"

	// -- identifier hygiene ---------------------------------------------------
	// FirstCanaryEmptyIdentifier — a selector value is the empty string.
	FirstCanaryEmptyIdentifier FirstCanaryScopeReason = "first_canary_empty_identifier"
	// FirstCanaryIdentifierTooLong — a selector value exceeds the rollout value bound.
	FirstCanaryIdentifierTooLong FirstCanaryScopeReason = "first_canary_identifier_too_long"
	// FirstCanaryWildcardIdentifier — a selector value carries a glob metacharacter.
	// rollout matches selector values EXACTLY, so "*" is today just a strange name — but
	// the reviewed shape is one NAMED principal on one NAMED server, and a pattern-shaped
	// identifier is not a name. Rejecting it keeps the signed object unambiguous no
	// matter how an upstream identity system spells "any".
	FirstCanaryWildcardIdentifier FirstCanaryScopeReason = "first_canary_wildcard_identifier"

	// -- tenant ---------------------------------------------------------------
	// FirstCanaryNoTenant — zero tenants. An empty tenant dimension is the structural
	// wildcard: it admits the same subject id in EVERY tenant.
	FirstCanaryNoTenant FirstCanaryScopeReason = "first_canary_no_tenant"
	// FirstCanaryDuplicateTenant — the same tenant appears twice (ambiguous signed object).
	FirstCanaryDuplicateTenant FirstCanaryScopeReason = "first_canary_duplicate_tenant"
	// FirstCanaryMultipleTenants — more than one distinct tenant.
	FirstCanaryMultipleTenants FirstCanaryScopeReason = "first_canary_multiple_tenants"

	// -- server ---------------------------------------------------------------
	// FirstCanaryNoServer — zero servers (structural wildcard over servers).
	FirstCanaryNoServer FirstCanaryScopeReason = "first_canary_no_server"
	// FirstCanaryDuplicateServer — the same server appears twice.
	FirstCanaryDuplicateServer FirstCanaryScopeReason = "first_canary_duplicate_server"
	// FirstCanaryMultipleServers — more than one distinct server.
	FirstCanaryMultipleServers FirstCanaryScopeReason = "first_canary_multiple_servers"

	// -- tool -----------------------------------------------------------------
	// FirstCanaryNoTool — zero tools (structural wildcard over tools).
	FirstCanaryNoTool FirstCanaryScopeReason = "first_canary_no_tool"
	// FirstCanaryToolIncomplete — a tool selector does not pin server+name+fingerprint.
	FirstCanaryToolIncomplete FirstCanaryScopeReason = "first_canary_tool_incomplete"
	// FirstCanaryDuplicateTool — the same exact tool triple appears twice.
	FirstCanaryDuplicateTool FirstCanaryScopeReason = "first_canary_duplicate_tool"
	// FirstCanaryMultipleTools — more than one distinct tool.
	FirstCanaryMultipleTools FirstCanaryScopeReason = "first_canary_multiple_tools"
	// FirstCanaryToolServerMismatch — the one tool is not hosted by the one named server,
	// so the signed object describes two different servers in two different dimensions.
	FirstCanaryToolServerMismatch FirstCanaryScopeReason = "first_canary_tool_server_mismatch"

	// -- principal ------------------------------------------------------------
	// FirstCanaryNoPrincipal — zero explicitly named principals. NOTHING else (client,
	// agent, group) can stand in for one.
	FirstCanaryNoPrincipal FirstCanaryScopeReason = "first_canary_no_principal"
	// FirstCanaryDuplicatePrincipal — the same principal appears twice.
	FirstCanaryDuplicatePrincipal FirstCanaryScopeReason = "first_canary_duplicate_principal"
	// FirstCanaryMultiplePrincipals — more than one distinct principal.
	FirstCanaryMultiplePrincipals FirstCanaryScopeReason = "first_canary_multiple_principals"

	// -- base contract --------------------------------------------------------
	// FirstCanaryBaseContractFailed — the scope is shaped exactly right but fails the
	// underlying Canary scope contract (uncompilable, matches nothing, not enumerable,
	// not realizable, ...). Exactness is layered ON TOP of that contract, never instead
	// of it, so this stays a conjunct. The precise base sub-reason is reported separately
	// by ValidateScope / the canary_scope_not_bounded readiness row.
	FirstCanaryBaseContractFailed FirstCanaryScopeReason = "first_canary_base_contract_failed"
)

// firstCanaryGlobChars are the pattern metacharacters an exact identifier may not carry.
const firstCanaryGlobChars = "*?"

// firstCanaryGovernedFields names every field of rollout.ScopeSpec this gate rules on.
// It is the machine-checked enumeration §2 requires: TestFirstCanary_GovernsEverySelectorClass
// compares it against reflect over rollout.ScopeSpec, so a new selector class added to the
// rollout model fails the build until the First-Canary decision about it is written here.
// Adding a name to this list without adding its rule below is caught by the same test's
// companion (the rule table must decide every governed field).
var firstCanaryGovernedFields = []string{
	"Capability",        // must be Gateway
	"Tenants",           // exactly 1, distinct, non-empty, non-glob
	"Servers",           // exactly 1, distinct, non-empty, non-glob
	"ToolFingerprints",  // must be EMPTY (second, server-unbound tool-selecting class)
	"Tools",             // exactly 1, fully pinned, hosted by the one server
	"Principals",        // exactly 1, distinct, non-empty, non-glob
	"Agents",            // must be EMPTY
	"Clients",           // must be EMPTY
	"Groups",            // must be EMPTY
	"Environments",      // must be EMPTY
	"Operations",        // empty, or exactly one RiskRead
	"Percent",           // must be 0
	"BucketSalt",        // must be ""
	"BucketKey",         // must be the default (BucketByPrincipal)
	"ExcludeTenants",    // must be EMPTY
	"ExcludeServers",    // must be EMPTY
	"ExcludeTools",      // must be EMPTY
	"ExcludePrincipals", // must be EMPTY
	"HighRisk",          // must be false
}

// ValidateFirstCanaryScope reports whether spec is the ONE exact reviewed first-Canary
// experiment: exactly one tenant, one server, one fully-pinned tool on that server, and
// one explicitly named principal — with every other selector class empty, no percentage
// sub-sampling, no exclusions, and no duplicate or pattern-shaped identifier.
//
// It returns FirstCanaryScopeOK ("") when the scope is exact, else the FIRST violated
// reason in the canonical order below. That order is chosen so each rejection names the
// reason a reviewer actually cares about rather than an unrelated prerequisite that
// happened to be false: a forbidden selector CLASS is reported before the counts (a
// one-client scope is rejected for carrying a client, not merely for lacking a
// principal), and identifier hygiene is reported before arity.
//
// The argument is the SIGNED activation scope. It is read RAW — never compiled first —
// so a duplicate in the signed object cannot be deduplicated into validity.
//
// Pure: no clock, no I/O, no package state.
func ValidateFirstCanaryScope(spec rollout.ScopeSpec, scopeRev uint64) FirstCanaryScopeReason {
	for _, check := range firstCanaryChecks {
		if r := check(spec); r != FirstCanaryScopeOK {
			return r
		}
	}
	// Exactness is layered ON TOP of the base Canary scope contract, never instead of it:
	// an exactly-shaped scope that cannot compile, matches nothing, or is unrealizable is
	// still not an admissible first Canary.
	if ValidateScope(spec, scopeRev) != ScopeOK {
		return FirstCanaryBaseContractFailed
	}
	return FirstCanaryScopeOK
}

// firstCanaryChecks is the canonical-ordered exact-shape rule table. One entry per rule,
// evaluated in order; the first non-OK result is the verdict.
var firstCanaryChecks = []func(rollout.ScopeSpec) FirstCanaryScopeReason{
	firstCanaryCapability,
	firstCanaryPosture,
	firstCanarySubSampling,
	firstCanaryForbiddenClasses,
	firstCanaryIdentifierHygiene,
	firstCanaryTenant,
	firstCanaryServer,
	firstCanaryTool,
	firstCanaryPrincipal,
}

func firstCanaryCapability(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	if spec.Capability != rollout.CapabilityGateway {
		return FirstCanaryNotGateway
	}
	return FirstCanaryScopeOK
}

// firstCanaryPosture enforces the read-only posture on the signed object. Operations must
// be empty (read-only by rollout semantics) or exactly one RiskRead — a repeated entry is
// an ambiguous signed object, and any non-read class is out of the experiment entirely.
func firstCanaryPosture(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	if spec.HighRisk {
		return FirstCanaryHighRisk
	}
	if len(spec.Operations) > 1 {
		return FirstCanaryOperationsNotExactlyRead
	}
	if len(spec.Operations) == 1 && spec.Operations[0] != rollout.RiskRead {
		return FirstCanaryOperationsNotExactlyRead
	}
	return FirstCanaryScopeOK
}

// firstCanarySubSampling forbids every percentage-bucket field. The experiment is a named
// set of one; a probabilistic sub-sample over it only makes WHICH requests execute
// non-deterministic. All three fields are checked independently so an inert-looking
// leftover (a salt or bucket key with Percent==0) cannot sit in a signed object waiting
// for a future Percent edit.
func firstCanarySubSampling(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	if spec.Percent != 0 {
		return FirstCanaryPercentageForbidden
	}
	if spec.BucketSalt != "" {
		return FirstCanaryBucketSaltForbidden
	}
	if spec.BucketKey != rollout.BucketByPrincipal {
		return FirstCanaryBucketKeyForbidden
	}
	return FirstCanaryScopeOK
}

// firstCanaryForbiddenClasses rejects every selector class that has no place in the exact
// shape. Each class gets its OWN reason, and this runs BEFORE the arity checks so a
// client-only or agent-only scope is rejected for the class it uses — never reported as a
// mere "no principal", which would leave open the reading that the class nearly counted.
func firstCanaryForbiddenClasses(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	switch {
	case len(spec.Clients) > 0:
		return FirstCanaryClientsForbidden
	case len(spec.Agents) > 0:
		return FirstCanaryAgentsForbidden
	case len(spec.Groups) > 0:
		return FirstCanaryGroupsForbidden
	case len(spec.Environments) > 0:
		return FirstCanaryEnvironmentsForbidden
	case len(spec.ToolFingerprints) > 0:
		return FirstCanaryBareFingerprintsForbidden
	case len(spec.ExcludeTenants) > 0, len(spec.ExcludeServers) > 0,
		len(spec.ExcludeTools) > 0, len(spec.ExcludePrincipals) > 0:
		return FirstCanaryExclusionsForbidden
	}
	return FirstCanaryScopeOK
}

// firstCanaryIdentifierHygiene checks every identifier the exact shape may carry: no empty
// string, nothing past the rollout value bound, no glob metacharacter. It runs over the
// three surviving string dimensions plus the tool triple. The forbidden classes are
// already empty by the time this runs, so there is nothing else to walk.
func firstCanaryIdentifierHygiene(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	maxBytes := rollout.DefaultLimits().MaxValueBytes()
	one := func(v string) FirstCanaryScopeReason {
		switch {
		case v == "":
			return FirstCanaryEmptyIdentifier
		case len(v) > maxBytes:
			return FirstCanaryIdentifierTooLong
		case strings.ContainsAny(v, firstCanaryGlobChars):
			return FirstCanaryWildcardIdentifier
		}
		return FirstCanaryScopeOK
	}
	groups := [][]string{spec.Tenants, spec.Servers, spec.Principals}
	for i := range spec.Tools {
		t := spec.Tools[i]
		// A tool triple with a MISSING component is an incompleteness, not a hygiene
		// problem — firstCanaryTool names that. Only non-empty components are checked
		// here so the two rules cannot claim each other's rejections.
		groups = append(groups, nonEmptyOf(t.Server, t.Name, t.Fingerprint))
	}
	for _, g := range groups {
		for _, v := range g {
			if r := one(v); r != FirstCanaryScopeOK {
				return r
			}
		}
	}
	return FirstCanaryScopeOK
}

// nonEmptyOf returns the non-empty members of vals.
func nonEmptyOf(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func firstCanaryTenant(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	return exactlyOneString(spec.Tenants, FirstCanaryNoTenant, FirstCanaryDuplicateTenant, FirstCanaryMultipleTenants)
}

func firstCanaryServer(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	return exactlyOneString(spec.Servers, FirstCanaryNoServer, FirstCanaryDuplicateServer, FirstCanaryMultipleServers)
}

func firstCanaryPrincipal(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	// Principals ALONE. Clients/Agents/Groups were already rejected as classes above, so
	// there is structurally nothing to aggregate with: this is a count of ONE dimension,
	// and it can never be satisfied by a different identity class.
	return exactlyOneString(spec.Principals, FirstCanaryNoPrincipal, FirstCanaryDuplicatePrincipal, FirstCanaryMultiplePrincipals)
}

// exactlyOneString requires a raw selector slice to hold exactly one value, with duplicates
// reported BEFORE arity so [X,X] is named as the ambiguity it is rather than as "two
// values". It never deduplicates: the slice is the signed object, and collapsing it is the
// one thing that would turn an invalid signed scope into a valid one.
func exactlyOneString(vals []string, none, dup, many FirstCanaryScopeReason) FirstCanaryScopeReason {
	if len(vals) == 0 {
		return none
	}
	seen := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		if _, ok := seen[v]; ok {
			return dup
		}
		seen[v] = struct{}{}
	}
	if len(vals) > 1 {
		return many
	}
	return FirstCanaryScopeOK
}

// firstCanaryTool requires exactly one fully-pinned tool, hosted by the one named server.
// The server cross-check is what stops the signed object from naming two different servers
// in two different dimensions (Servers:[S1] with the tool on S2), which the base contract's
// realizability check would reject only as a generic "not realizable".
func firstCanaryTool(spec rollout.ScopeSpec) FirstCanaryScopeReason {
	if len(spec.Tools) == 0 {
		return FirstCanaryNoTool
	}
	for i := range spec.Tools {
		t := spec.Tools[i]
		if t.Server == "" || t.Name == "" || t.Fingerprint == "" {
			return FirstCanaryToolIncomplete
		}
	}
	seen := make(map[rollout.ToolSel]struct{}, len(spec.Tools))
	for i := range spec.Tools {
		if _, ok := seen[spec.Tools[i]]; ok {
			return FirstCanaryDuplicateTool
		}
		seen[spec.Tools[i]] = struct{}{}
	}
	if len(spec.Tools) > 1 {
		return FirstCanaryMultipleTools
	}
	// firstCanaryServer has already established exactly one server by the time this runs, so
	// the length guard is defense-in-depth against a future reordering of firstCanaryChecks:
	// it keeps the server ARITY rejections with their own rule rather than surfacing them
	// here as a mismatch.
	if len(spec.Servers) == 1 && spec.Tools[0].Server != spec.Servers[0] {
		return FirstCanaryToolServerMismatch
	}
	return FirstCanaryScopeOK
}

// AllFirstCanaryScopeReasons returns the complete exact-first-Canary rejection vocabulary in
// canonical order. It exists so a test can prove every declared reason is reachable (no
// orphan) and so an operator dry-run surface can advertise the full rule set.
func AllFirstCanaryScopeReasons() []FirstCanaryScopeReason {
	return []FirstCanaryScopeReason{
		FirstCanaryNotGateway,
		FirstCanaryHighRisk,
		FirstCanaryOperationsNotExactlyRead,
		FirstCanaryPercentageForbidden,
		FirstCanaryBucketSaltForbidden,
		FirstCanaryBucketKeyForbidden,
		FirstCanaryClientsForbidden,
		FirstCanaryAgentsForbidden,
		FirstCanaryGroupsForbidden,
		FirstCanaryEnvironmentsForbidden,
		FirstCanaryBareFingerprintsForbidden,
		FirstCanaryExclusionsForbidden,
		FirstCanaryEmptyIdentifier,
		FirstCanaryIdentifierTooLong,
		FirstCanaryWildcardIdentifier,
		FirstCanaryNoTenant,
		FirstCanaryDuplicateTenant,
		FirstCanaryMultipleTenants,
		FirstCanaryNoServer,
		FirstCanaryDuplicateServer,
		FirstCanaryMultipleServers,
		FirstCanaryNoTool,
		FirstCanaryToolIncomplete,
		FirstCanaryDuplicateTool,
		FirstCanaryMultipleTools,
		FirstCanaryToolServerMismatch,
		FirstCanaryNoPrincipal,
		FirstCanaryDuplicatePrincipal,
		FirstCanaryMultiplePrincipals,
		FirstCanaryBaseContractFailed,
	}
}
