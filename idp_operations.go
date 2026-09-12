package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// idp_operations.go — durable, operation-identified IdP write intents
// (FE-6A.0 correction, Blocker 9).
//
// THE DEFECT IT CLOSES: a legacy-LDAP cutover is a once-ever authority
// transition that the ENABLING registry write carries. A client whose
// response was lost (proxy timeout, closed tab, network blip) could only
// re-send — and a re-send was a SECOND create with a SECOND minted profile
// id, so the same operator intent could land twice, or the operator could
// not tell whether the first ever landed. The cutover record carried an
// operationId the SERVER minted after the fact, which is not something a
// client can hold across a lost response.
//
// THE MODEL: the client supplies a UUID `operationId` (`?operationId=`)
// BEFORE dispatch. It is REQUIRED for a cutover-bearing write (428
// operation_id_required) and honoured for every other create. Before the
// first irreversible write the registry persists a NON-SECRET intent bound
// to the actor, the action, the candidate profile's pre-minted identity and
// a digest of its public spec, and the registry document revision the
// caller fenced on. The intent moves pending → committed | aborted |
// outcome_unknown with the terminal result recorded, so:
//
//   - a duplicate operationId REPLAYS the recorded result (never a second
//     create, never a second cutover) — the same candidate spec is required
//     (a different spec under a reused id is 409 operation_mismatch);
//   - GET /api/idp/operations/{operationId} is the authoritative lookup;
//   - a process that dies mid-operation leaves a durable `pending` intent
//     that boot RECONCILES against the registry file (the profile is there
//     ⇒ committed; it is not ⇒ aborted) — the truth is derived from the
//     durable state, never guessed.
//
// The store is a bounded ring (idpOperationsMax) written atomically as a
// SIBLING of the registry file, so it shares the registry's durability
// posture and a test/operator that relocates the registry relocates its
// intents with it. Secrets NEVER enter it: the spec digest is over the
// public projection, and the recorded result is the response the client
// received (itself secret-free).

const (
	idpOperationsFile = "idp_operations.json"
	idpOperationsMax  = 256

	idpOpPending        = "pending"
	idpOpCommitted      = "committed"
	idpOpAborted        = "aborted"
	idpOpOutcomeUnknown = "outcome_unknown"
)

// idpOperationIDPattern accepts RFC 4122 UUIDs (any version, any variant
// nibble the spec allows), case-insensitive.
var idpOperationIDPattern = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validIdPOperationID reports whether s is an acceptable client operationId.
func validIdPOperationID(s string) bool { return idpOperationIDPattern.MatchString(s) }

// idpOperation is one durable intent record. Every field is non-secret.
type idpOperation struct {
	OperationID      string          `json:"operationId"`
	State            string          `json:"state"`
	Action           string          `json:"action"` // idp.create
	Actor            string          `json:"actor"`
	ProfileID        string          `json:"profileId"`
	SpecDigest       string          `json:"specDigest"`
	RegistryRevision string          `json:"registryRevision"` // the document revision the caller fenced on
	Cutover          bool            `json:"cutover"`          // the write carried the legacy-LDAP cutover
	StartedAt        string          `json:"startedAt"`
	FinishedAt       string          `json:"finishedAt,omitempty"`
	Code             string          `json:"code,omitempty"`   // refusal code of an aborted/unknown outcome
	Result           json.RawMessage `json:"result,omitempty"` // the recorded success response (replayed verbatim)
	// CommittedRevision is the registry document revision AFTER the commit
	// (what a lookup reports as the operation's registry binding).
	CommittedRevision string `json:"committedRevision,omitempty"`
}

// idpOperationStore is the bounded, atomically-written intent ring.
type idpOperationStore struct {
	mu   sync.Mutex
	path string // "" = in-memory (a non-persisted registry)
	ops  []*idpOperation
}

// errIdPOperationPersist: the durable intent could not be written, so the
// write was never attempted (500 persist_failed). The replay/mismatch/
// in-progress/aborted verdicts are refusals written by the handler from the
// recorded state and need no sentinel.
var errIdPOperationPersist = errors.New("idp: operation intent could not be persisted; nothing was changed")

// idpSpecDigest is the non-secret identity of a candidate profile spec: the
// public projection with the server-owned id/revision zeroed.
func idpSpecDigest(p *IdPProfile) string {
	pub := publicIdPProfile(p)
	if pub == nil {
		return ""
	}
	pub.ID, pub.Revision = "", 0
	b, _ := json.Marshal(pub)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newIdPOperationStore binds the store beside the registry file (or keeps
// it in memory when the registry itself is not persisted) and loads it.
func newIdPOperationStore(registryPath string) *idpOperationStore {
	s := &idpOperationStore{}
	if registryPath == "" {
		return s
	}
	s.path = filepath.Join(filepath.Dir(registryPath), idpOperationsFile)
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Printf("IdP: operations file unreadable (%s); starting with an empty intent ring", sanitizeLog(filepath.Base(s.path)))
		}
		return s
	}
	var ops []*idpOperation
	if err := json.Unmarshal(data, &ops); err != nil {
		// A corrupt intent ring must not block the registry: quarantine
		// beside the store (CHAOS-05 convention) and start empty.
		quarantineCorruptStateFile("idp_operations", s.path, err)
		return s
	}
	s.ops = ops
	return s
}

// persistLocked writes the ring atomically. Caller holds s.mu.
func (s *idpOperationStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if len(s.ops) > idpOperationsMax {
		s.ops = append([]*idpOperation(nil), s.ops[len(s.ops)-idpOperationsMax:]...)
	}
	data, err := json.MarshalIndent(s.ops, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path, data, 0o600)
}

func (s *idpOperationStore) findLocked(id string) *idpOperation {
	for _, op := range s.ops {
		if op != nil && op.OperationID == id {
			return op
		}
	}
	return nil
}

// Get returns a copy of the recorded operation, or nil.
func (s *idpOperationStore) Get(id string) *idpOperation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op := s.findLocked(id); op != nil {
		cp := *op
		return &cp
	}
	return nil
}

// Begin records intent BEFORE the first irreversible write. When the id is
// already known it returns the recorded operation and created=false — the
// caller replays or refuses, never writes. A new intent is persisted as
// pending before Begin returns (a persist failure is errIdPOperationPersist
// and nothing is recorded in memory either).
func (s *idpOperationStore) Begin(op idpOperation) (existing *idpOperation, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev := s.findLocked(op.OperationID); prev != nil {
		cp := *prev
		return &cp, false, nil
	}
	op.State = idpOpPending
	op.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	rec := op
	s.ops = append(s.ops, &rec)
	if err := s.persistLocked(); err != nil {
		s.ops = s.ops[:len(s.ops)-1]
		return nil, false, fmt.Errorf("%w: %v", errIdPOperationPersist, err)
	}
	return nil, true, nil
}

// Finish records the terminal outcome. The result is stored only for a
// committed operation. A persist failure here is logged, never returned:
// the registry outcome is already decided and reported truthfully; the
// next boot reconciles a stale pending record from the registry file.
func (s *idpOperationStore) Finish(id, state, code, committedRevision string, result any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op := s.findLocked(id)
	if op == nil {
		return
	}
	op.State = state
	op.Code = code
	op.CommittedRevision = committedRevision
	op.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if state == idpOpCommitted && result != nil {
		if b, err := json.Marshal(result); err == nil {
			op.Result = b
		}
	}
	if err := s.persistLocked(); err != nil {
		logger.Printf("IdP: operation %s outcome (%s) could not be persisted: the registry outcome stands; boot reconciles from the registry file", sanitizeLog(id), sanitizeLog(state))
	}
}

// Reconcile settles every non-terminal record against the durable registry
// content (boot / registry (re)load): the pre-minted profile is present ⇒
// committed; absent ⇒ aborted. present(id) answers from the loaded profiles.
func (s *idpOperationStore) Reconcile(present func(profileID string) bool, docRevision string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, op := range s.ops {
		if op == nil || (op.State != idpOpPending && op.State != idpOpOutcomeUnknown) {
			continue
		}
		if present(op.ProfileID) {
			op.State, op.CommittedRevision = idpOpCommitted, docRevision
			op.Code = "reconciled_committed"
		} else {
			op.State, op.Code = idpOpAborted, "reconciled_absent"
		}
		op.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		n++
	}
	if n > 0 {
		if err := s.persistLocked(); err != nil {
			logger.Printf("IdP: %d reconciled operation record(s) could not be persisted", n)
		}
	}
	return n
}

// lookupReadModel is the GET /api/idp/operations/{id} projection.
func (op *idpOperation) lookupReadModel() map[string]any {
	out := map[string]any{
		"operationId":      op.OperationID,
		"state":            op.State,
		"action":           op.Action,
		"actor":            op.Actor,
		"profileId":        op.ProfileID,
		"registryRevision": op.RegistryRevision,
		"cutover":          op.Cutover,
		"startedAt":        op.StartedAt,
	}
	if op.FinishedAt != "" {
		out["finishedAt"] = op.FinishedAt
	}
	if op.Code != "" {
		out["code"] = op.Code
	}
	if op.CommittedRevision != "" {
		out["committedRevision"] = op.CommittedRevision
	}
	if len(op.Result) > 0 {
		out["result"] = op.Result
	}
	return out
}
