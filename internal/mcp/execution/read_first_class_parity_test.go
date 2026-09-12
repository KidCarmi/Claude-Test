package execution

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// read_first_class_parity_test.go — the EXECUTION-SIDE half of §8 operation-class parity
// (blocker #4).
//
// The runtime package proves that a tools/call is classified at exactly one site and that the
// class flows into the DecisionInput the executor receives. What is proven HERE is the last link:
// that the live side-effect gate is handed THAT class and not a recomputed one.
//
// The link is a single field read, `in.Input.Operation.Class`, and it is easy to lose without
// anyone noticing. A future change that wanted the gate to "know better" — re-deriving the class
// from the tool record, from an MCP annotation, from the method name — would be a local, plausible
// edit inside liveGateInput, and nothing else in the tree would fail. The two failure modes it
// produces are the ones the whole read-first design exists to prevent:
//
//	policy authorizes a WRITE, the gate admits a READ   → the side effect exceeds anything reviewed
//	policy authorizes a READ, the gate refuses it       → the experiment cannot run, invisibly
//
// So the read is pinned twice — once behaviourally (the class the gate receives is the class the
// decision carried, for every class in the vocabulary) and once structurally (the class field is
// assigned from the decision input and nowhere else in this package).

// TestReadFirstParity_GateReceivesTheDecidedClass drives liveGateInput for every class in the
// vocabulary and requires the gate's input to carry exactly what the decision carried.
//
// OpRead is the case blocker #4 adds and the one that must arrive intact, but the whole vocabulary
// is walked on purpose: a builder that special-cased OpRead — hard-coding it, or mapping anything
// unrecognised to it — would pass a single-value test and is precisely the shape to refuse.
func TestReadFirstParity_GateReceivesTheDecidedClass(t *testing.T) {
	boundary := time.Unix(1_700_000_500, 0)
	e, err := New(Config{
		State:           stateForMode(t, rollout.ModeCanary),
		Upstream:        &fakeUpstream{},
		Events:          realEvents(t, nil),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return boundary },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, class := range []policy.OperationClass{
		policy.OpUnset, policy.OpRead, policy.OpWrite,
		policy.OpDestructive, policy.OpDiscovery, policy.OpControl,
	} {
		in := runtime.ExecInput{
			Now:   boundary,
			Input: policy.DecisionInput{Operation: policy.Operation{Class: class}},
		}
		if got := e.liveGateInput(in).Operation; got != class {
			t.Fatalf("SECURITY: the live gate must receive the class the decision carried; "+
				"decision said %v, gate was handed %v", class, got)
		}
	}
}

// TestReadFirstParity_ClassIsReadFromTheDecisionAndNowhereElse is the structural half.
//
// It walks this package's sources and requires that every assignment to a LiveGateInput.Operation
// field reads it from the decision input. A behavioural test cannot prove this: it can only show
// that the values agreed for the inputs it happened to try, whereas a recomputation that agreed
// with the decision in six out of six cases and diverged in the seventh would pass the test above
// and be exactly the bug.
func TestReadFirstParity_ClassIsReadFromTheDecisionAndNowhereElse(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "livegate.go", nil, 0)
	if err != nil {
		t.Fatalf("parse livegate.go: %v", err)
	}
	var fn *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "liveGateInput" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("liveGateInput not found in livegate.go — this gate's selector is stale, not the code")
	}
	var sources []string
	ast.Inspect(fn, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Operation" {
			return true
		}
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, kv.Value); err != nil {
			t.Fatalf("render Operation value: %v", err)
		}
		sources = append(sources, b.String())
		return true
	})
	if len(sources) != 1 {
		t.Fatalf("liveGateInput must set Operation exactly once, found %d (%v)", len(sources), sources)
	}
	const want = "in.Input.Operation.Class"
	if sources[0] != want {
		t.Fatalf("SECURITY: the live gate's operation class must be read from the decision input "+
			"(%s), got %q. A class recomputed here is a SECOND classification, and the policy "+
			"engine and the gate would then be free to disagree about the same call.", want, sources[0])
	}
}
