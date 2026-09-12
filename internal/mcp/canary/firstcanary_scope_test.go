package canary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ---------------------------------------------------------------------------
// THE ONE CANONICAL EXPERIMENT (§6, the anti-vacuity control).
//
// Tenant T1, Server S1, Tool Tool1 on S1, Principal P1. No other selector class.
// Every rejection case below is this fixture with exactly ONE thing changed, so a
// rejection can only be attributed to that change — never to an unrelated
// prerequisite that happened to be false.
// ---------------------------------------------------------------------------

const (
	fcTenant = "T1"
	fcServer = "S1"
	fcTool   = "Tool1"
	fcFP     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fcPrinc  = "P1"
)

// canonicalFirstCanaryScope is the ONE reviewed first-Canary experiment.
func canonicalFirstCanaryScope() rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Tenants:    []string{fcTenant},
		Servers:    []string{fcServer},
		Tools:      []rollout.ToolSel{{Server: fcServer, Name: fcTool, Fingerprint: fcFP}},
		Principals: []string{fcPrinc},
	}
}

// TestFirstCanary_CanonicalExperimentPasses is the ANTI-VACUITY CONTROL. Without it every
// gate below would also pass an implementation that rejects everything, which would prove
// nothing about exactness and would make the whole first-Canary design unreachable.
func TestFirstCanary_CanonicalExperimentPasses(t *testing.T) {
	spec := canonicalFirstCanaryScope()
	if r := ValidateFirstCanaryScope(spec, 1); r != FirstCanaryScopeOK {
		t.Fatalf("the ONE canonical reviewed experiment (T1/S1/Tool1/P1) must pass the exact-scope gate, got %q", r)
	}
	// It must also satisfy the pre-existing base contract — exactness is layered on top of
	// it, so a fixture that passed only the new gate would be proving the wrong thing.
	if r := ValidateScope(spec, 1); r != ScopeOK {
		t.Fatalf("the canonical experiment must also satisfy the base Canary scope contract, got %q", r)
	}
	if !ScopeReadFirst(spec) {
		t.Fatal("the canonical experiment must be read-first")
	}
	// An explicit single read operation is the same experiment written out longhand.
	explicit := canonicalFirstCanaryScope()
	explicit.Operations = []rollout.RiskClass{rollout.RiskRead}
	if r := ValidateFirstCanaryScope(explicit, 1); r != FirstCanaryScopeOK {
		t.Fatalf("Operations:[RiskRead] is the canonical experiment written longhand, got %q", r)
	}
}

// TestFirstCanary_RejectionMatrix is the required rejection matrix (§7). Every case starts
// from the canonical experiment and changes exactly ONE thing, and each asserts the SPECIFIC
// reason — so a case can never be counted as passing because some unrelated prerequisite
// was false.
func TestFirstCanary_RejectionMatrix(t *testing.T) {
	longID := strings.Repeat("a", rollout.DefaultLimits().MaxValueBytes()+1)
	other := rollout.ToolSel{Server: fcServer, Name: "Tool2", Fingerprint: "sha256:2222222222222222222222222222222222222222222222222222222222222222"}

	cases := []struct {
		name   string
		mutate func(*rollout.ScopeSpec)
		want   FirstCanaryScopeReason
	}{
		// -- identity: the exact-principal requirement ------------------------
		{"zero principals", func(s *rollout.ScopeSpec) { s.Principals = nil }, FirstCanaryNoPrincipal},
		{"two principals", func(s *rollout.ScopeSpec) { s.Principals = []string{fcPrinc, "P2"} }, FirstCanaryMultiplePrincipals},
		{"duplicate principal", func(s *rollout.ScopeSpec) { s.Principals = []string{fcPrinc, fcPrinc} }, FirstCanaryDuplicatePrincipal},
		{"one principal + one client", func(s *rollout.ScopeSpec) { s.Clients = []string{"C1"} }, FirstCanaryClientsForbidden},
		{"one principal + one agent", func(s *rollout.ScopeSpec) { s.Agents = []string{"A1"} }, FirstCanaryAgentsForbidden},
		{"one principal + group selector", func(s *rollout.ScopeSpec) { s.Groups = []string{"G1"} }, FirstCanaryGroupsForbidden},
		{"client-only identity", func(s *rollout.ScopeSpec) { s.Principals = nil; s.Clients = []string{"C1"} }, FirstCanaryClientsForbidden},
		{"agent-only identity", func(s *rollout.ScopeSpec) { s.Principals = nil; s.Agents = []string{"A1"} }, FirstCanaryAgentsForbidden},
		{"group-only identity", func(s *rollout.ScopeSpec) { s.Principals = nil; s.Groups = []string{"G1"} }, FirstCanaryGroupsForbidden},

		// -- tool --------------------------------------------------------------
		{"zero tools", func(s *rollout.ScopeSpec) { s.Tools = nil }, FirstCanaryNoTool},
		{"two tools", func(s *rollout.ScopeSpec) { s.Tools = append(s.Tools, other) }, FirstCanaryMultipleTools},
		{"duplicate tool", func(s *rollout.ScopeSpec) { s.Tools = append(s.Tools, s.Tools[0]) }, FirstCanaryDuplicateTool},

		// -- server ------------------------------------------------------------
		{"zero servers", func(s *rollout.ScopeSpec) { s.Servers = nil }, FirstCanaryNoServer},
		{"two servers", func(s *rollout.ScopeSpec) { s.Servers = []string{fcServer, "S2"} }, FirstCanaryMultipleServers},
		{"duplicate server", func(s *rollout.ScopeSpec) { s.Servers = []string{fcServer, fcServer} }, FirstCanaryDuplicateServer},

		// -- tenant ------------------------------------------------------------
		{"zero tenants", func(s *rollout.ScopeSpec) { s.Tenants = nil }, FirstCanaryNoTenant},
		{"two tenants", func(s *rollout.ScopeSpec) { s.Tenants = []string{fcTenant, "T2"} }, FirstCanaryMultipleTenants},
		{"duplicate tenant", func(s *rollout.ScopeSpec) { s.Tenants = []string{fcTenant, fcTenant} }, FirstCanaryDuplicateTenant},

		// -- wildcard / percentage ---------------------------------------------
		{"wildcard principal selector", func(s *rollout.ScopeSpec) { s.Principals = []string{"*"} }, FirstCanaryWildcardIdentifier},
		{"wildcard server selector", func(s *rollout.ScopeSpec) { s.Servers = []string{fcServer + "*"}; s.Tools[0].Server = fcServer + "*" }, FirstCanaryWildcardIdentifier},
		{"single-char wildcard identifier", func(s *rollout.ScopeSpec) { s.Tenants = []string{"T?"} }, FirstCanaryWildcardIdentifier},
		{"percentage selector", func(s *rollout.ScopeSpec) { s.Percent = 50; s.BucketSalt = "salt" }, FirstCanaryPercentageForbidden},
		{"percentage 100 selector", func(s *rollout.ScopeSpec) { s.Percent = 100 }, FirstCanaryPercentageForbidden},
		{"bucket salt without percent", func(s *rollout.ScopeSpec) { s.BucketSalt = "salt" }, FirstCanaryBucketSaltForbidden},
		{"non-default bucket key", func(s *rollout.ScopeSpec) { s.BucketKey = rollout.BucketByTenant }, FirstCanaryBucketKeyForbidden},

		// -- empty / bounded-invalid identifiers --------------------------------
		{"empty principal identifier", func(s *rollout.ScopeSpec) { s.Principals = []string{""} }, FirstCanaryEmptyIdentifier},
		{"empty tenant identifier", func(s *rollout.ScopeSpec) { s.Tenants = []string{""} }, FirstCanaryEmptyIdentifier},
		{"empty server identifier", func(s *rollout.ScopeSpec) { s.Servers = []string{""} }, FirstCanaryEmptyIdentifier},
		{"over-long principal identifier", func(s *rollout.ScopeSpec) { s.Principals = []string{longID} }, FirstCanaryIdentifierTooLong},
		{"over-long tool fingerprint", func(s *rollout.ScopeSpec) { s.Tools[0].Fingerprint = longID }, FirstCanaryIdentifierTooLong},
		{"tool missing fingerprint", func(s *rollout.ScopeSpec) { s.Tools[0].Fingerprint = "" }, FirstCanaryToolIncomplete},
		{"tool missing name", func(s *rollout.ScopeSpec) { s.Tools[0].Name = "" }, FirstCanaryToolIncomplete},
		{"tool missing server", func(s *rollout.ScopeSpec) { s.Tools[0].Server = "" }, FirstCanaryToolIncomplete},

		// -- additional selector classes ----------------------------------------
		{"environment selector", func(s *rollout.ScopeSpec) { s.Environments = []string{"prod"} }, FirstCanaryEnvironmentsForbidden},
		{"bare tool fingerprint selector", func(s *rollout.ScopeSpec) { s.ToolFingerprints = []string{fcFP} }, FirstCanaryBareFingerprintsForbidden},
		{"exclude tenants", func(s *rollout.ScopeSpec) { s.ExcludeTenants = []string{"T9"} }, FirstCanaryExclusionsForbidden},
		{"exclude servers", func(s *rollout.ScopeSpec) { s.ExcludeServers = []string{"S9"} }, FirstCanaryExclusionsForbidden},
		{"exclude tools", func(s *rollout.ScopeSpec) { s.ExcludeTools = []rollout.ToolSel{other} }, FirstCanaryExclusionsForbidden},
		{"exclude principals", func(s *rollout.ScopeSpec) { s.ExcludePrincipals = []string{"P9"} }, FirstCanaryExclusionsForbidden},

		// -- posture / capability ------------------------------------------------
		{"management capability", func(s *rollout.ScopeSpec) { s.Capability = rollout.CapabilityManagement }, FirstCanaryNotGateway},
		{"high risk", func(s *rollout.ScopeSpec) { s.HighRisk = true }, FirstCanaryHighRisk},
		{"write operation", func(s *rollout.ScopeSpec) { s.Operations = []rollout.RiskClass{rollout.RiskWrite} }, FirstCanaryOperationsNotExactlyRead},
		{"duplicated read operation", func(s *rollout.ScopeSpec) {
			s.Operations = []rollout.RiskClass{rollout.RiskRead, rollout.RiskRead}
		}, FirstCanaryOperationsNotExactlyRead},

		// -- cross-dimension coherence -------------------------------------------
		{"tool hosted by a different server", func(s *rollout.ScopeSpec) { s.Tools[0].Server = "S2" }, FirstCanaryToolServerMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := canonicalFirstCanaryScope()
			tc.mutate(&spec)
			got := ValidateFirstCanaryScope(spec, 1)
			if got != tc.want {
				t.Fatalf("exact-scope verdict for %q = %q, want %q (each case must fail for its OWN reason, "+
					"never because an unrelated prerequisite happened to be false)", tc.name, got, tc.want)
			}
			if got == FirstCanaryScopeOK {
				t.Fatalf("%q must NOT be admissible as the first Canary", tc.name)
			}
		})
	}
}

// TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal is the direct answer to the
// aggregate-counting attack (§2/§12). principalCount() — the BASE contract's identity rule —
// sums Principals+Clients+Agents, so a one-client (or one-agent) zero-principal scope
// satisfies it: the base contract is happy that "somebody" was named. The exact gate must not
// inherit that. A client is not a principal, an agent is not a principal, and a group is not a
// principal; each is rejected on its own, and each contributes NOTHING positive — proved by
// removing it and observing the scope is still rejected for lacking a principal.
func TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal(t *testing.T) {
	for _, tc := range []struct {
		name string
		// aggregated: the base contract's principalCount() counts this class, so a lone one of
		// it satisfies the base identity rule. This is precisely the hazard the exact gate closes.
		aggregated bool
		apply      func(*rollout.ScopeSpec)
		want       FirstCanaryScopeReason
	}{
		{"client", true, func(s *rollout.ScopeSpec) { s.Clients = []string{"C1"} }, FirstCanaryClientsForbidden},
		{"agent", true, func(s *rollout.ScopeSpec) { s.Agents = []string{"A1"} }, FirstCanaryAgentsForbidden},
		{"group", false, func(s *rollout.ScopeSpec) { s.Groups = []string{"G1"} }, FirstCanaryGroupsForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := canonicalFirstCanaryScope()
			spec.Principals = nil
			tc.apply(&spec)
			base := ValidateScope(spec, 1)
			if tc.aggregated {
				// Assert the hazard is real before asserting it is closed: if the base contract ever
				// stops aggregating this class, this test would otherwise keep passing while proving
				// nothing.
				if n := principalCount(spec); n != 1 {
					t.Fatalf("precondition: the base contract's aggregate identity count must be 1 for a lone %s, got %d", tc.name, n)
				}
				if base == ScopeNoIdentity {
					t.Fatalf("precondition: the base contract must ACCEPT a lone %s on the identity axis "+
						"(that aggregate is the hazard being closed)", tc.name)
				}
			} else if base != ScopeNoIdentity {
				// A group is deliberately NOT aggregated by the base contract either; pin that so the
				// exact gate's group rule is understood as a more precise restatement, not as the only
				// thing standing between a group and a live Canary.
				t.Fatalf("precondition: the base contract already rejects a lone %s as %q, got %q", tc.name, ScopeNoIdentity, base)
			}
			if got := ValidateFirstCanaryScope(spec, 1); got != tc.want {
				t.Fatalf("a lone %s must be rejected as %q, got %q — a non-principal class may never satisfy "+
					"the exact-principal requirement", tc.name, tc.want, got)
			}
			// And it contributed nothing positive: strip it and the scope is still rejected, now
			// for the real deficiency.
			bare := canonicalFirstCanaryScope()
			bare.Principals = nil
			if got := ValidateFirstCanaryScope(bare, 1); got != FirstCanaryNoPrincipal {
				t.Fatalf("with the %s removed the scope must still be rejected for having no principal, got %q", tc.name, got)
			}
			// The class also cannot ACCOMPANY the one principal: the reviewed shape is one named
			// principal and nothing else on the identity axis.
			withBoth := canonicalFirstCanaryScope()
			tc.apply(&withBoth)
			if got := ValidateFirstCanaryScope(withBoth, 1); got != tc.want {
				t.Fatalf("one principal PLUS one %s must be rejected as %q, got %q", tc.name, tc.want, got)
			}
		})
	}
}

// TestFirstCanary_NeverDeduplicatesAnInvalidSignedScope pins §5: exactness must be present in
// the SIGNED object. rollout.Compile builds sets, so it collapses [P1,P1] to one principal —
// validating a COMPILED scope would therefore turn an ambiguous signed object into a valid
// one. The gate must read the raw slices.
func TestFirstCanary_NeverDeduplicatesAnInvalidSignedScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		// baseAccepts: the base contract lets this duplicate through (it counts principals via
		// principalCount and tools via len(), both within the architecture's caps of 2), so the
		// exact gate is the ONLY thing rejecting it. Server/tenant duplicates are already over
		// the base caps of 1 by raw length — still asserted here, because the property under
		// test is "never deduplicated", which must hold for every dimension.
		baseAccepts bool
		mutate      func(*rollout.ScopeSpec)
		want        FirstCanaryScopeReason
	}{
		{"principals", true, func(s *rollout.ScopeSpec) { s.Principals = []string{fcPrinc, fcPrinc} }, FirstCanaryDuplicatePrincipal},
		{"tools", true, func(s *rollout.ScopeSpec) {
			s.Tools = []rollout.ToolSel{s.Tools[0], s.Tools[0]}
		}, FirstCanaryDuplicateTool},
		{"servers", false, func(s *rollout.ScopeSpec) { s.Servers = []string{fcServer, fcServer} }, FirstCanaryDuplicateServer},
		{"tenants", false, func(s *rollout.ScopeSpec) { s.Tenants = []string{fcTenant, fcTenant} }, FirstCanaryDuplicateTenant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := canonicalFirstCanaryScope()
			tc.mutate(&spec)
			// The compiled scope genuinely collapses the duplicate — that is the hazard.
			sc, err := rollout.Compile(spec, 1, rollout.DefaultLimits())
			if err != nil {
				t.Fatalf("precondition: the duplicated scope must still COMPILE (that is why compiling first would hide it): %v", err)
			}
			if !sc.Enumerable() {
				t.Fatal("precondition: the duplicated scope must compile to an enumerable scope")
			}
			// The compiled scope must genuinely have collapsed the duplicate: that is what a
			// validator reading the COMPILED form would see, and why exactness has to be read
			// from the raw signed slices.
			if sc.Hash() != mustCompileHash(t, dedupedCounterpart(spec)) {
				t.Fatalf("precondition: compiling %q must produce the same scope as its deduplicated counterpart — "+
					"that collapse is the hazard", tc.name)
			}
			base := ValidateScope(spec, 1)
			if tc.baseAccepts && base != ScopeOK {
				t.Fatalf("precondition: the base contract accepts the duplicated %s (got %q) — the exact gate is the only rejecter", tc.name, base)
			}
			if !tc.baseAccepts && base == ScopeOK {
				t.Fatalf("precondition: the base contract was expected to also reject the duplicated %s", tc.name)
			}
			if got := ValidateFirstCanaryScope(spec, 1); got != tc.want {
				t.Fatalf("a duplicated %s in the SIGNED scope must be rejected as %q, got %q — never deduplicated into validity", tc.name, tc.want, got)
			}
		})
	}
}

// TestFirstCanary_GovernsEverySelectorClass is the anti-drift wall for §2: every field of
// rollout.ScopeSpec must be explicitly ruled on. If rollout grows a new selector class, this
// fails until the First-Canary decision about it is written down — a new class can never
// arrive un-governed and quietly widen the one reviewed experiment.
func TestFirstCanary_GovernsEverySelectorClass(t *testing.T) {
	rt := reflect.TypeOf(rollout.ScopeSpec{})
	declared := map[string]bool{}
	for _, f := range firstCanaryGovernedFields {
		if declared[f] {
			t.Fatalf("firstCanaryGovernedFields lists %q twice", f)
		}
		declared[f] = true
	}
	actual := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		actual[rt.Field(i).Name] = true
	}
	for name := range actual {
		if !declared[name] {
			t.Errorf("rollout.ScopeSpec.%s is a selector class the exact first-Canary gate does not rule on. "+
				"Add it to firstCanaryGovernedFields AND give it a rule in firstCanaryChecks — an un-governed "+
				"selector class can silently widen the one reviewed experiment.", name)
		}
	}
	for name := range declared {
		if !actual[name] {
			t.Errorf("firstCanaryGovernedFields names %q but rollout.ScopeSpec has no such field (stale governance)", name)
		}
	}
	if len(declared) != rt.NumField() {
		t.Fatalf("governed fields %d != rollout.ScopeSpec fields %d", len(declared), rt.NumField())
	}
}

// TestFirstCanary_EveryGovernedFieldIsDecisive proves the governance list is not decorative:
// for every field of rollout.ScopeSpec other than the four that the canonical experiment
// legitimately populates, setting it must flip the verdict away from OK. A field named in
// firstCanaryGovernedFields but never consulted would otherwise pass the reflection wall
// above while governing nothing.
func TestFirstCanary_EveryGovernedFieldIsDecisive(t *testing.T) {
	// The canonical experiment populates exactly these; they are proven decisive by the
	// rejection matrix's zero/duplicate/multiple rows instead.
	populated := map[string]bool{"Capability": true, "Tenants": true, "Servers": true, "Tools": true, "Principals": true}
	// A non-zero value for each remaining field that a signed object could carry.
	nonZero := map[string]func(*rollout.ScopeSpec){
		"ToolFingerprints": func(s *rollout.ScopeSpec) { s.ToolFingerprints = []string{fcFP} },
		"Agents":           func(s *rollout.ScopeSpec) { s.Agents = []string{"A1"} },
		"Clients":          func(s *rollout.ScopeSpec) { s.Clients = []string{"C1"} },
		"Groups":           func(s *rollout.ScopeSpec) { s.Groups = []string{"G1"} },
		"Environments":     func(s *rollout.ScopeSpec) { s.Environments = []string{"prod"} },
		"Operations":       func(s *rollout.ScopeSpec) { s.Operations = []rollout.RiskClass{rollout.RiskWrite} },
		"Percent":          func(s *rollout.ScopeSpec) { s.Percent = 100 },
		"BucketSalt":       func(s *rollout.ScopeSpec) { s.BucketSalt = "salt" },
		"BucketKey":        func(s *rollout.ScopeSpec) { s.BucketKey = rollout.BucketByTenant },
		"ExcludeTenants":   func(s *rollout.ScopeSpec) { s.ExcludeTenants = []string{"T9"} },
		"ExcludeServers":   func(s *rollout.ScopeSpec) { s.ExcludeServers = []string{"S9"} },
		"ExcludeTools": func(s *rollout.ScopeSpec) {
			s.ExcludeTools = []rollout.ToolSel{{Server: "S9", Name: "n", Fingerprint: "f"}}
		},
		"ExcludePrincipals": func(s *rollout.ScopeSpec) { s.ExcludePrincipals = []string{"P9"} },
		"HighRisk":          func(s *rollout.ScopeSpec) { s.HighRisk = true },
	}
	rt := reflect.TypeOf(rollout.ScopeSpec{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if populated[name] {
			continue
		}
		apply, ok := nonZero[name]
		if !ok {
			t.Fatalf("no non-zero probe for rollout.ScopeSpec.%s — add one so the field is proven decisive", name)
		}
		spec := canonicalFirstCanaryScope()
		apply(&spec)
		if got := ValidateFirstCanaryScope(spec, 1); got == FirstCanaryScopeOK {
			t.Errorf("setting rollout.ScopeSpec.%s on the canonical experiment left it admissible — the field is governed in name only", name)
		}
	}
}

// TestFirstCanary_ExactShapeImpliesBaseContract proves the exact shape is STRICTLY STRONGER
// than the base Canary scope contract: every exactly-shaped scope also satisfies ValidateScope.
// That is why FirstCanaryBaseContractFailed is currently unreachable (see the parity test) —
// the conjunct is defense-in-depth, not dead weight. If a future change adds a base rule the
// exact shape does not already imply, THIS test fails first and names the gap, instead of the
// conjunct silently becoming the reason operators see.
func TestFirstCanary_ExactShapeImpliesBaseContract(t *testing.T) {
	maxLen := rollout.DefaultLimits().MaxValueBytes()
	variants := []struct {
		name string
		spec rollout.ScopeSpec
	}{
		{"canonical", canonicalFirstCanaryScope()},
		{"explicit read op", func() rollout.ScopeSpec {
			s := canonicalFirstCanaryScope()
			s.Operations = []rollout.RiskClass{rollout.RiskRead}
			return s
		}()},
		{"identifiers at the byte bound", func() rollout.ScopeSpec {
			at := strings.Repeat("z", maxLen)
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway,
				Tenants:    []string{at},
				Servers:    []string{at},
				Tools:      []rollout.ToolSel{{Server: at, Name: at, Fingerprint: at}},
				Principals: []string{at},
			}
		}()},
		{"single-character identifiers", rollout.ScopeSpec{
			Capability: rollout.CapabilityGateway,
			Tenants:    []string{"t"},
			Servers:    []string{"s"},
			Tools:      []rollout.ToolSel{{Server: "s", Name: "n", Fingerprint: "f"}},
			Principals: []string{"p"},
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			if r := ValidateFirstCanaryScope(v.spec, 1); r != FirstCanaryScopeOK {
				t.Fatalf("precondition: %s must be exactly shaped, got %q", v.name, r)
			}
			if r := ValidateScope(v.spec, 1); r != ScopeOK {
				t.Fatalf("an exactly-shaped scope must also satisfy the base Canary contract; %s failed with %q. "+
					"Either the base contract grew a rule the exact shape does not imply (add it to firstCanaryChecks "+
					"so operators get the precise reason) or the exact rules drifted.", v.name, r)
			}
		})
	}
}

// TestFirstCanary_VocabularyParity proves every declared rejection reason is driven by a real
// scope (no orphaned rule — a rule someone believes exists and does not), and that
// AllFirstCanaryScopeReasons advertises exactly that set.
//
// FirstCanaryBaseContractFailed is the one deliberate exception: the exact shape IMPLIES the
// base contract (proved above), so no exactly-shaped scope can reach the conjunct today. It is
// asserted UNREACHABLE here rather than quietly dropped, so the day a base rule stops being
// implied, both tests speak.
func TestFirstCanary_VocabularyParity(t *testing.T) {
	longID := strings.Repeat("a", rollout.DefaultLimits().MaxValueBytes()+1)
	drivers := []func(*rollout.ScopeSpec){
		func(s *rollout.ScopeSpec) { s.Capability = rollout.CapabilityManagement },
		func(s *rollout.ScopeSpec) { s.HighRisk = true },
		func(s *rollout.ScopeSpec) { s.Operations = []rollout.RiskClass{rollout.RiskWrite} },
		func(s *rollout.ScopeSpec) { s.Percent = 100 },
		func(s *rollout.ScopeSpec) { s.BucketSalt = "salt" },
		func(s *rollout.ScopeSpec) { s.BucketKey = rollout.BucketByAgent },
		func(s *rollout.ScopeSpec) { s.Clients = []string{"C1"} },
		func(s *rollout.ScopeSpec) { s.Agents = []string{"A1"} },
		func(s *rollout.ScopeSpec) { s.Groups = []string{"G1"} },
		func(s *rollout.ScopeSpec) { s.Environments = []string{"prod"} },
		func(s *rollout.ScopeSpec) { s.ToolFingerprints = []string{fcFP} },
		func(s *rollout.ScopeSpec) { s.ExcludePrincipals = []string{"P9"} },
		func(s *rollout.ScopeSpec) { s.Principals = []string{""} },
		func(s *rollout.ScopeSpec) { s.Principals = []string{longID} },
		func(s *rollout.ScopeSpec) { s.Principals = []string{"*"} },
		func(s *rollout.ScopeSpec) { s.Tenants = nil },
		func(s *rollout.ScopeSpec) { s.Tenants = []string{fcTenant, fcTenant} },
		func(s *rollout.ScopeSpec) { s.Tenants = []string{fcTenant, "T2"} },
		func(s *rollout.ScopeSpec) { s.Servers = nil },
		func(s *rollout.ScopeSpec) { s.Servers = []string{fcServer, fcServer} },
		func(s *rollout.ScopeSpec) { s.Servers = []string{fcServer, "S2"} },
		func(s *rollout.ScopeSpec) { s.Tools = nil },
		func(s *rollout.ScopeSpec) { s.Tools[0].Fingerprint = "" },
		func(s *rollout.ScopeSpec) { s.Tools = []rollout.ToolSel{s.Tools[0], s.Tools[0]} },
		func(s *rollout.ScopeSpec) {
			s.Tools = append(s.Tools, rollout.ToolSel{Server: fcServer, Name: "Tool2", Fingerprint: fcFP})
		},
		func(s *rollout.ScopeSpec) { s.Tools[0].Server = "S2" },
		func(s *rollout.ScopeSpec) { s.Principals = nil },
		func(s *rollout.ScopeSpec) { s.Principals = []string{fcPrinc, fcPrinc} },
		func(s *rollout.ScopeSpec) { s.Principals = []string{fcPrinc, "P2"} },
	}
	reachable := map[FirstCanaryScopeReason]bool{}
	for _, d := range drivers {
		spec := canonicalFirstCanaryScope()
		d(&spec)
		if r := ValidateFirstCanaryScope(spec, 1); r != FirstCanaryScopeOK {
			reachable[r] = true
		}
	}
	if reachable[FirstCanaryScopeOK] {
		t.Fatal("FirstCanaryScopeOK must never appear as a rejection reason")
	}
	if reachable[FirstCanaryBaseContractFailed] {
		t.Fatal("FirstCanaryBaseContractFailed was reached by an exact-shape driver — the shape/contract " +
			"implication in TestFirstCanary_ExactShapeImpliesBaseContract no longer holds")
	}
	for _, r := range AllFirstCanaryScopeReasons() {
		if r == FirstCanaryBaseContractFailed {
			continue // unreachable by theorem; see the doc comment above
		}
		if !reachable[r] {
			t.Errorf("AllFirstCanaryScopeReasons advertises %q but no scope drives it (orphaned rule)", r)
		}
	}
	if want := len(AllFirstCanaryScopeReasons()) - 1; len(reachable) != want {
		t.Errorf("AllFirstCanaryScopeReasons has %d reachable entries but %d were driven — vocabulary drift",
			want, len(reachable))
	}
}

// TestFirstCanary_IsPureAndDeterministic pins §3/§4: the verdict is a function of the signed
// scope alone. Repeated evaluation yields the same reason, the revision never changes it, and
// evaluating a scope never mutates it — a gate that normalized its input would be
// deduplicating the signed object by another name.
func TestFirstCanary_IsPureAndDeterministic(t *testing.T) {
	specs := []rollout.ScopeSpec{
		canonicalFirstCanaryScope(),
		func() rollout.ScopeSpec {
			s := canonicalFirstCanaryScope()
			s.Principals = []string{fcPrinc, "P2"}
			return s
		}(),
		func() rollout.ScopeSpec { s := canonicalFirstCanaryScope(); s.Clients = []string{"C1"}; return s }(),
		func() rollout.ScopeSpec {
			s := canonicalFirstCanaryScope()
			s.Tenants = []string{fcTenant, fcTenant}
			return s
		}(),
	}
	for _, spec := range specs {
		before := deepCopyScopeSpec(spec)
		first := ValidateFirstCanaryScope(spec, 7)
		for i := 0; i < 25; i++ {
			if got := ValidateFirstCanaryScope(spec, 7); got != first {
				t.Fatalf("verdict is not deterministic: %q then %q", first, got)
			}
		}
		for _, rev := range []uint64{0, 1, 999999} {
			if got := ValidateFirstCanaryScope(spec, rev); got != first {
				t.Fatalf("the scope revision must not change the exact-shape verdict: rev %d gave %q, want %q", rev, got, first)
			}
		}
		if !reflect.DeepEqual(before, spec) {
			t.Fatalf("ValidateFirstCanaryScope mutated the signed scope: %+v -> %+v", before, spec)
		}
	}
}

func deepCopyScopeSpec(s rollout.ScopeSpec) rollout.ScopeSpec {
	cp := s
	cp.Tenants = append([]string(nil), s.Tenants...)
	cp.Servers = append([]string(nil), s.Servers...)
	cp.ToolFingerprints = append([]string(nil), s.ToolFingerprints...)
	cp.Tools = append([]rollout.ToolSel(nil), s.Tools...)
	cp.Principals = append([]string(nil), s.Principals...)
	cp.Agents = append([]string(nil), s.Agents...)
	cp.Clients = append([]string(nil), s.Clients...)
	cp.Groups = append([]string(nil), s.Groups...)
	cp.Environments = append([]string(nil), s.Environments...)
	cp.Operations = append([]rollout.RiskClass(nil), s.Operations...)
	cp.ExcludeTenants = append([]string(nil), s.ExcludeTenants...)
	cp.ExcludeServers = append([]string(nil), s.ExcludeServers...)
	cp.ExcludeTools = append([]rollout.ToolSel(nil), s.ExcludeTools...)
	cp.ExcludePrincipals = append([]string(nil), s.ExcludePrincipals...)
	return cp
}

// TestFirstCanary_ArchitectureBoundsAreNotRedefined pins §1: the exact gate must be a
// SEPARATE predicate, not a global tightening of the Canary architecture's caps. If a future
// change "simplifies" this by setting MaxCanaryTools/MaxCanaryPrincipals to 1, the broader
// Canary architecture silently becomes exact-only — a different decision from the one this
// gate makes, and one no reviewer of this change agreed to.
func TestFirstCanary_ArchitectureBoundsAreNotRedefined(t *testing.T) {
	if MaxCanaryTools < 2 {
		t.Errorf("MaxCanaryTools = %d: the exact first-experiment shape must be enforced by "+
			"ValidateFirstCanaryScope, NOT by globally redefining the Canary architecture's cap. "+
			"Raising exactness into this constant changes what a LATER graduation phase may do.", MaxCanaryTools)
	}
	if MaxCanaryPrincipals < 2 {
		t.Errorf("MaxCanaryPrincipals = %d: same — the architecture cap and the first experiment "+
			"are different decisions with different futures.", MaxCanaryPrincipals)
	}
	// And the separation must be REAL: a scope inside the architecture's bounds but wider than
	// the one experiment must pass the base contract and fail the exact gate. If this ever
	// stops holding, the two predicates have collapsed into one.
	two := canonicalFirstCanaryScope()
	two.Tools = append(two.Tools, rollout.ToolSel{Server: fcServer, Name: "Tool2", Fingerprint: fcFP})
	if r := ValidateScope(two, 1); r != ScopeOK {
		t.Fatalf("a two-tool scope must remain admissible to the base Canary contract (got %q) — "+
			"otherwise the architecture cap was tightened after all", r)
	}
	if r := ValidateFirstCanaryScope(two, 1); r != FirstCanaryMultipleTools {
		t.Fatalf("a two-tool scope must be rejected by the exact gate as %q, got %q", FirstCanaryMultipleTools, r)
	}
}

// TestFirstCanary_ValidatorReadsNoClockOrIO is the structural purity wall for §3: the exact
// gate must decide from the signed object alone. It may import only the rollout model and
// strings — never time, net, os, or any runtime observation — so "only one identity ever
// showed up" can never become an input to exactness.
func TestFirstCanary_ValidatorReadsNoClockOrIO(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "firstcanary_scope.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse firstcanary_scope.go: %v", err)
	}
	allowed := map[string]bool{
		`"strings"`: true,
		`"github.com/KidCarmi/Culvert/internal/mcp/rollout"`: true,
	}
	for _, imp := range f.Imports {
		if !allowed[imp.Path.Value] {
			t.Errorf("firstcanary_scope.go imports %s — the exact first-Canary gate must decide from the "+
				"SIGNED scope alone: no clock, no I/O, no runtime observation.", imp.Path.Value)
		}
	}
	// Belt and braces: no identifier named time/now anywhere in the file.
	full, err := parser.ParseFile(fset, "firstcanary_scope.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ast.Inspect(full, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "time" || id.Name == "os" || id.Name == "net" {
			t.Errorf("firstcanary_scope.go references %s.%s — the gate must be pure", id.Name, sel.Sel.Name)
		}
		return true
	})
}

// dedupedCounterpart returns spec with each raw selector slice collapsed to its distinct
// values — exactly what rollout.Compile's set-building does internally.
func dedupedCounterpart(s rollout.ScopeSpec) rollout.ScopeSpec {
	cp := deepCopyScopeSpec(s)
	cp.Tenants = distinct(s.Tenants)
	cp.Servers = distinct(s.Servers)
	cp.Principals = distinct(s.Principals)
	seen := map[rollout.ToolSel]struct{}{}
	tools := make([]rollout.ToolSel, 0, len(s.Tools))
	for _, t := range s.Tools {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		tools = append(tools, t)
	}
	cp.Tools = tools
	return cp
}

func distinct(vals []string) []string {
	seen := make(map[string]struct{}, len(vals))
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func mustCompileHash(t *testing.T, spec rollout.ScopeSpec) string {
	t.Helper()
	sc, err := rollout.Compile(spec, 1, rollout.DefaultLimits())
	if err != nil {
		t.Fatalf("compile deduplicated counterpart: %v", err)
	}
	return sc.Hash()
}
