package runtime

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// canary_read_first_class_test.go — the RUNTIME half of exact read-first tool classification
// (blocker #4), and the §8 parity wall that keeps the classification singular.
//
// The root package proves WHAT may be classified (an exact reviewed fingerprint bound by a
// four-eyes review to a read-only class). What is proven HERE is the other half: that the
// classification happens ONCE, at one site, on authoritative facts alone, and then FLOWS — so the
// policy engine, the Canary activation gate and the live side-effect gate are looking at one
// value rather than at three independently computed answers that happen to agree today.
//
// Why that is the dangerous part. `op.Class` is read by the policy engine to authorize, by the
// executor's liveGateInput to build the side-effect gate input, and by the gate's read-first
// predicate to admit. A second classification anywhere in that chain produces the two failures
// that matter in opposite directions: policy authorizing a WRITE while the read-first gate admits
// it as a READ (the blast radius is larger than anything reviewed), or policy authorizing a READ
// the gate then refuses (the experiment cannot run and the reason is invisible). Both are
// impossible by construction if there is exactly one assignment and one value.

// classifierCall records one question the pipeline asked the classifier seam.
type classifierCall struct {
	capability string
	serverID   string
	toolName   string
}

// recordingClassifier is a composed CanaryOperationClass seam that answers a fixed verdict and
// remembers every question. Remembering is half the point: several gates below assert on what the
// pipeline was ABLE to tell the classifier, which is how "no argument can upgrade authority" is
// proven rather than asserted.
type recordingClassifier struct {
	mu    sync.Mutex
	class policy.OperationClass
	ok    bool
	calls []classifierCall
}

func (r *recordingClassifier) fn(capability, serverID, toolName string) (policy.OperationClass, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, classifierCall{capability: capability, serverID: serverID, toolName: toolName})
	return r.class, r.ok
}

func (r *recordingClassifier) seen() []classifierCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]classifierCall(nil), r.calls...)
}

// readFirstFixture composes a Gateway pipeline with one ingested tool, an ALLOW-all policy and a
// record-only executor that captures the DecisionInput. Every gate below reads the captured input,
// which is the exact value the executor — and therefore liveGateInput — receives.
func readFirstFixture(t *testing.T, cls *recordingClassifier, opts ...func(*Deps)) (*pipeline, *recordOnlyExec, *esKey) {
	t.Helper()
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	ex := &recordOnlyExec{}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	if cls != nil {
		deps.CanaryOperationClass = cls.fn
	}
	for _, o := range opts {
		o(&deps)
	}
	return newGatewayPipeline(t, deps), ex, k
}

// decidedClass drives one tools/call and returns the operation class the executor was handed.
func decidedClass(t *testing.T, p *pipeline, ex *recordOnlyExec, k *esKey, body []byte) policy.OperationClass {
	t.Helper()
	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, body), sid), fixedClock())
	got := ex.resolvedInputs()
	if len(got) != 1 {
		t.Fatalf("expected exactly one decision to reach the executor, got %d", len(got))
	}
	return got[0].Operation.Class
}

// THE POSITIVE CONTROL. An affirmative reviewed-read answer promotes the tools/call to OpRead,
// and the promoted class is what the executor — and therefore the live gate — sees.
//
// Without this gate every negative gate below would be satisfied by a runtime that never consulted
// the classifier at all, which is the feature deleted rather than implemented.
func TestReadFirstRuntime_ReviewedReadAnswerPromotesTheToolCall(t *testing.T) {
	cls := &recordingClassifier{class: policy.OpRead, ok: true}
	p, ex, k := readFirstFixture(t, cls)
	if got := decidedClass(t, p, ex, k, toolsCallBody(2)); got != policy.OpRead {
		t.Fatalf("an affirmative reviewed-read answer must promote the call to OpRead, got %v", got)
	}
	calls := cls.seen()
	if len(calls) != 1 {
		t.Fatalf("the classifier must be consulted exactly once per tools/call, got %d", len(calls))
	}
	if calls[0].serverID != testServerID || calls[0].toolName != "x" {
		t.Fatalf("the classifier must be asked about the tool the request named, got %+v", calls[0])
	}
	if calls[0].capability != protocol.Gateway.String() {
		t.Fatalf("the classifier must be told which capability is asking, got %q", calls[0].capability)
	}
}

// The DEFAULT posture. With no classifier composed — which is every build that has not armed a
// Canary, i.e. the shipped one — a tools/call is OpWrite, byte-identically to before this feature
// existed.
func TestReadFirstRuntime_NoClassifierLeavesTheConservativeDefault(t *testing.T) {
	p, ex, k := readFirstFixture(t, nil)
	if got := decidedClass(t, p, ex, k, toolsCallBody(2)); got != policy.OpWrite {
		t.Fatalf("with no classifier composed a tools/call must stay OpWrite, got %v", got)
	}
}

// Every NEGATIVE answer leaves OpWrite. The promotion is affirmative-only: it is not "anything but
// write", not "anything the classifier could speak for", and not "anything not explicitly denied".
//
// The (OpRead, false) row is the sharp one. It is the shape a careless caller produces — a class
// computed but not vouched for — and a classifier consumer that ignored the boolean would read it
// as a read. The runtime's own predicate requires BOTH halves.
func TestReadFirstRuntime_NonAffirmativeAnswersStayWrite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class policy.OperationClass
		ok    bool
	}{
		{"unset and unvouched", policy.OpUnset, false},
		{"unset but vouched", policy.OpUnset, true},
		{"write", policy.OpWrite, true},
		{"destructive", policy.OpDestructive, true},
		{"discovery", policy.OpDiscovery, true},
		{"control", policy.OpControl, true},
		{"read but NOT vouched for", policy.OpRead, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cls := &recordingClassifier{class: tc.class, ok: tc.ok}
			p, ex, k := readFirstFixture(t, cls)
			if got := decidedClass(t, p, ex, k, toolsCallBody(2)); got != policy.OpWrite {
				t.Fatalf("SECURITY: a %s answer must leave the call at OpWrite, got %v", tc.name, got)
			}
		})
	}
}

// §7. tools/list stays OpDiscovery and the classifier is NEVER consulted for it. Blocker #4 is
// about making one exact reviewed INVOCATION crossable, and the cheapest wrong way to "close" it
// is to route listing through the same promotion so that something passes the gate. The classifier
// not being reached is the stronger statement: there is no answer it could give that would matter.
func TestReadFirstRuntime_DiscoveryNeverReachesTheClassifier(t *testing.T) {
	cls := &recordingClassifier{class: policy.OpRead, ok: true}
	p, ex, k := readFirstFixture(t, cls)
	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(2)), sid), fixedClock())
	got := ex.resolvedInputs()
	if len(got) != 1 {
		t.Fatalf("expected exactly one decision to reach the executor, got %d", len(got))
	}
	if got[0].Operation.Class != policy.OpDiscovery {
		t.Fatalf("tools/list must stay OpDiscovery, got %v", got[0].Operation.Class)
	}
	if calls := cls.seen(); len(calls) != 0 {
		t.Fatalf("SECURITY: tools/list must never be routed through the read-first classifier, got %+v", calls)
	}
}

// An UNKNOWN tool — no catalog record — is never classified. It is the last thing that should be
// called read-only, and the runtime declines to ask rather than relying on the root's own inventory
// read to come back empty. Both halves hold; this one is the one a refactor could remove.
func TestReadFirstRuntime_UnknownToolIsNeverClassified(t *testing.T) {
	cls := &recordingClassifier{class: policy.OpRead, ok: true}
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	// Deliberately NOT ingesting tool "x": the catalog cannot identify what the request names.
	ex := &recordOnlyExec{}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	deps.CanaryOperationClass = cls.fn
	p := newGatewayPipeline(t, deps)

	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())
	if calls := cls.seen(); len(calls) != 0 {
		t.Fatalf("SECURITY: an unidentifiable tool must never be routed through the classifier, got %+v", calls)
	}
	for _, in := range ex.resolvedInputs() {
		if in.Operation.Class == policy.OpRead {
			t.Fatal("SECURITY: an unknown tool was classified read-first")
		}
	}
}

// §6 STRUCTURAL. The classifier seam's signature is (capability, serverID, toolName) →
// (class, ok). Nothing else can travel through it: not the request, not its arguments, not a
// fingerprint, not a catalog annotation, not a server-supplied hint.
//
// This is asserted on the TYPE rather than on behaviour because behaviour cannot prove a negative
// here — a test can only show that today's implementation ignores an input it is given, whereas the
// type shows there is no input to give. Widening the seam to carry an argument would fail this gate
// at compile-adjacent granularity, in a diff a reviewer reads.
func TestReadFirstWall_ClassifierTakesNoServerSuppliedInput(t *testing.T) {
	f, ok := reflect.TypeOf(Deps{}).FieldByName("CanaryOperationClass")
	if !ok {
		t.Fatal("Deps.CanaryOperationClass has been renamed or removed")
	}
	ft := f.Type
	if ft.Kind() != reflect.Func {
		t.Fatalf("the classifier seam must be a function, got %v", ft.Kind())
	}
	if ft.NumIn() != 3 {
		t.Fatalf("SECURITY: the classifier seam must take exactly (capability, serverID, toolName); "+
			"it now takes %d parameters, so something new can reach the classification decision", ft.NumIn())
	}
	for i := 0; i < ft.NumIn(); i++ {
		if ft.In(i).Kind() != reflect.String {
			t.Fatalf("SECURITY: classifier parameter %d is %v, not a plain identifier string — a "+
				"structured value is how a hint, an argument or a catalog record arrives", i, ft.In(i))
		}
	}
	if ft.NumOut() != 2 || ft.Out(0) != reflect.TypeOf(policy.OpUnset) || ft.Out(1).Kind() != reflect.Bool {
		t.Fatal("the classifier seam must answer (policy.OperationClass, bool) — the bool is what " +
			"makes 'could not speak for it' distinguishable from 'said unset'")
	}
}

// §8 STRUCTURAL PARITY, half one: there is exactly ONE site in this package that may write
// Operation.Class for a tool call, and it is classifyReadFirstToolCall.
//
// policyOperation sets the DEFAULTS (OpDiscovery for tools/list, OpWrite for tools/call) and is
// allowed; any THIRD writer would be a second classification, which is the divergence this gate
// exists to make impossible. The check is an AST walk rather than a grep so a renamed receiver, a
// different assignment spelling, or a write buried in a helper is still caught.
func TestReadFirstWall_OperationClassHasExactlyOneClassificationSite(t *testing.T) {
	writes := classFieldWrites(t)
	// Fields named Class that are NOT the policy operation class. Listed by their exact target
	// expression so that a rename, a move, or a NEW unrelated Class field has to be re-declared
	// here by a human rather than silently inheriting the exemption.
	notOperationClass := map[string]bool{
		"in.Destination.Class": true, // inspection destination class
		"rb.rec.Class":         true, // the telemetry record's message class
	}
	// The two sites permitted to decide a tool call's operation class: the DEFAULTS, and the ONE
	// authoritative promotion.
	allowed := map[string]bool{"policyOperation": true, "classifyReadFirstToolCall": true}
	seen := map[string]int{}
	for _, w := range writes {
		if notOperationClass[w.target] {
			continue
		}
		if !allowed[w.fn] {
			t.Fatalf("SECURITY: %s writes %s. Classification must happen at exactly one site so the "+
				"policy engine, the activation gate and the live side-effect gate read one value; a "+
				"second writer is how they come to disagree. If %s is not the policy operation "+
				"class, declare it in notOperationClass with a reason.", w.fn, w.target, w.target)
		}
		seen[w.fn]++
	}
	// The CONTROLS: if the selector stopped matching anything, the loop above would pass forever.
	if seen["classifyReadFirstToolCall"] == 0 {
		t.Fatal("the classification site was not found — this gate is no longer checking anything")
	}
	if seen["policyOperation"] == 0 {
		t.Fatal("the default-class site was not found — this gate is no longer checking anything")
	}
}

// classWrite is one assignment to a field named Class, with the function it sits in and the exact
// target expression it assigns to.
type classWrite struct{ fn, target string }

// classFieldWrites collects EVERY write to a field named Class in this package's non-test sources.
// Collecting all of them and classifying afterwards is deliberate: a scan that only looked for
// `op.Class` would miss a second classification written through any other spelling, which is the
// thing being prevented.
func classFieldWrites(t *testing.T) []classWrite {
	t.Helper()
	fset := token.NewFileSet()
	// "." is the package directory: `go test` runs with the package as its working directory,
	// which is the same convention the sibling AST gate in canary_reviewed_target_test.go uses.
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	var writes []classWrite
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			writes = append(writes, classWritesInFile(t, fset, file)...)
		}
	}
	return writes
}

// classWritesInFile walks one file, tracking the enclosing function so each write is attributable.
func classWritesInFile(t *testing.T, fset *token.FileSet, file *ast.File) []classWrite {
	t.Helper()
	var out []classWrite
	var fn string
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			fn = v.Name.Name
		case *ast.AssignStmt:
			for _, lhs := range v.Lhs {
				sel, isSel := lhs.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "Class" {
					continue
				}
				var b bytes.Buffer
				if err := printer.Fprint(&b, fset, lhs); err != nil {
					t.Fatalf("render assignment target: %v", err)
				}
				out = append(out, classWrite{fn: fn, target: b.String()})
			}
		}
		return true
	})
	return out
}

// §8 STRUCTURAL PARITY, half two: the class the executor acts on is the SAME VALUE the policy
// engine decided, carried by assignment rather than recomputed. buildExecInput must pass the
// DecisionInput straight through.
func TestReadFirstWall_ExecInputCarriesTheDecidedInputVerbatim(t *testing.T) {
	cls := &recordingClassifier{class: policy.OpRead, ok: true}
	p, ex, k := readFirstFixture(t, cls)
	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())
	got := ex.resolvedInputs()
	if len(got) != 1 {
		t.Fatalf("expected exactly one decision to reach the executor, got %d", len(got))
	}
	// The executor's copy carries the promoted class AND the tool identity it was promoted for.
	// Both together are the parity claim: the same tuple, not merely the same class.
	if got[0].Operation.Class != policy.OpRead {
		t.Fatalf("the executor must receive the classified class, got %v", got[0].Operation.Class)
	}
	if got[0].Tool == nil || got[0].Tool.Name != "x" || got[0].Tool.ServerID != testServerID {
		t.Fatalf("the executor must receive the tool the class was decided for, got %+v", got[0].Tool)
	}
	if got[0].Operation.Operand != "x" {
		t.Fatalf("the decided operand must name the classified tool, got %q", got[0].Operation.Operand)
	}
}
