package upstreamclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// CallOptions.PreSend is the executor's last look at rollout authority before request bytes exist,
// and it exists because the wait it sits after is UNBOUNDED: pool.acquire blocks on a per-server
// semaphore until a slot frees or the context is done. These pin the client's half of that
// contract — that the hook runs at all, that it runs AFTER the pool slot is held, that it runs on
// EVERY leg, and that a refusal reaches the caller as provably-never-sent on the first one
// (Codex P1, PR #1370, round 4).

// preSendsPerLeg is how many times the caller's predicate is re-asked for ONE physical leg: once
// at the pool boundary in Call, and once in roundTrip after DNS resolution and immediately before
// the transport. Pinned as an exact count so removing either site fails a test rather than being
// absorbed by the other — the guarded-twice trap this PR has hit five times already.
const preSendsPerLeg = 2

// A PreSend refusal stops the call before ANY request reaches the server, and the caller learns
// that no bytes were ever sent — the evidence the executor needs to record definitely_not_sent
// rather than sending a provably-undelivered attempt to witness reconciliation.
func TestPreSend_RefusalStopsTheCallWithNothingSent(t *testing.T) {
	var hits int
	c, target, _, stop := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"call-1","result":{}}`)
	})
	defer stop()

	refusal := errors.New("authority withdrawn")
	_, err := c.Call(context.Background(), target, "tools/list", nil, CallOptions{
		Idempotent: true, WireID: "call-1",
		PreSend: func() error { return refusal },
	})

	if !errors.Is(err, refusal) {
		t.Fatalf("the caller must receive its own refusal verbatim, got %v", err)
	}
	if hits != 0 {
		t.Fatalf("SECURITY: a pre-send refusal must stop the call before any request bytes exist, server saw %d", hits)
	}
	if !SendNeverStarted(err) {
		t.Fatal("a first-leg pre-send refusal is provably never-sent; without that evidence the " +
			"executor records may_have_been_sent for an invocation that never happened")
	}
}

// The mandatory control: a PreSend that permits the send does not interfere.
func TestPreSend_PermittingHookDoesNotInterfere(t *testing.T) {
	var hits int
	c, target, _, stop := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"call-1","result":{"tools":[]}}`)
	})
	defer stop()

	calls := 0
	resp, err := c.Call(context.Background(), target, "tools/list", nil, CallOptions{
		Idempotent: true, WireID: "call-1",
		PreSend: func() error { calls++; return nil },
	})
	if err != nil {
		t.Fatalf("CONTROL: a permitting hook must not block the call: %v", err)
	}
	// TWO re-asks per leg, and the exactness is deliberate: one at the pool boundary (after the
	// unbounded wait for a slot) and one after DNS resolution, immediately before the transport
	// takes over. Deleting EITHER site drops this to one and fails here, which is what keeps both
	// independently pinned — a looser "at least one" would let either be removed silently.
	if resp == nil || calls != preSendsPerLeg || hits != 1 {
		t.Fatalf("CONTROL: expected %d hook calls and one request, hook=%d server=%d", preSendsPerLeg, calls, hits)
	}
}

// THE HOOK RUNS AFTER THE POOL SLOT IS HELD, which is the whole reason it exists: the executor's
// own boundary guards run before Call, and the wait for a slot sits between them and the send.
//
// Deterministic, not timing-based: every slot is held by a request parked in the handler, and the
// test waits for exactly that many handler entries before launching the queued call. While the
// pool is saturated the queued call cannot have reached its hook; once the parked requests are
// released it must.
func TestPreSend_RunsAfterThePoolSlotIsAcquired(t *testing.T) {
	lim := DefaultLimits().MaxInFlight()
	if lim < 1 {
		t.Fatalf("premise: the per-server in-flight limit must be at least 1, got %d", lim)
	}

	entered := make(chan struct{}, lim)
	release := make(chan struct{})
	c, target, _, stop := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"x","result":{}}`)
	})
	defer stop()

	var wg sync.WaitGroup
	for i := 0; i < lim; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, _ = c.Call(context.Background(), target, "tools/list", nil, CallOptions{
				Idempotent: true, WireID: fmt.Sprintf("hold-%d", n),
			})
		}(i)
	}
	for i := 0; i < lim; i++ {
		<-entered // every slot is now held by a request parked in the handler
	}

	var hookRan atomic.Bool
	queued := make(chan struct{})
	go func() {
		defer close(queued)
		_, _ = c.Call(context.Background(), target, "tools/list", nil, CallOptions{
			Idempotent: true, WireID: "queued",
			PreSend: func() error { hookRan.Store(true); return nil },
		})
	}()

	// The pool is saturated, so the queued call is parked in acquire. Its hook must not have run:
	// a hook that runs BEFORE the slot is held would be asking about authority and then waiting an
	// unbounded time before acting on the answer, which is the defect it exists to close.
	if hookRan.Load() {
		t.Fatal("SECURITY: PreSend ran before the pool slot was held — the re-ask would then be " +
			"separated from the send by the very wait it exists to cover")
	}

	close(release)
	wg.Wait()
	<-queued
	if !hookRan.Load() {
		t.Fatal("the queued call reached the send without its PreSend ever running")
	}
}

// AND ON EVERY LEG. A retry is a second physical send; re-sending on the strength of a check made
// before the first leg is the same defect one loop iteration over.
func TestPreSend_RunsOnEveryRetryLeg(t *testing.T) {
	var hits atomic.Int64
	c, target, _, stop := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			// Fail the first leg WITHOUT a response, so an idempotent read is retryable.
			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"retry","result":{}}`)
	})
	defer stop()

	var hooks atomic.Int64
	_, err := c.Call(context.Background(), target, "tools/list", nil, CallOptions{
		Idempotent: true, WireID: "retry",
		PreSend: func() error { hooks.Add(1); return nil },
	})
	if err != nil {
		t.Fatalf("premise: the retried read should succeed on its second leg: %v", err)
	}
	if got := hits.Load(); got < 2 {
		t.Skipf("premise: the client did not retry in this run (%d leg(s)); nothing to prove", got)
	}
	if want := hits.Load() * preSendsPerLeg; hooks.Load() != want {
		t.Fatalf("SECURITY: %d physical leg(s) should carry %d pre-send re-ask(s), got %d — a retry "+
			"sent on the strength of a check made before an earlier leg", hits.Load(), want, hooks.Load())
	}
}
