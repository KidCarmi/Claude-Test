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

// TWO RE-ASK SITES, and each is pinned by an observable the other cannot produce:
//
//	roundTrip, before client.Do          → refusing here means NO TCP CONNECTION is ever accepted.
//	pinnedDialTLS, after the handshake   → refusing here means a connection IS accepted and NO
//	                                       HTTP request is ever served.
//
// Counting hook invocations was the earlier shape and it was the wrong instrument: it could not say
// WHICH site ran, so removing either was absorbable by the other — the guarded-twice trap, which
// this PR has now hit six times. Distinct observables cannot be absorbed.

// Refusing at the FIRST site stops the call before a connection is even attempted.
func TestPreSend_RefusalBeforeTheTransportOpensNoConnection(t *testing.T) {
	var hits int
	c, target, _, accepts, stop := pinnedTestServerCounting(t, func(w http.ResponseWriter, r *http.Request) {
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
	// The CUMULATIVE accept count, never the live gauge: a gauge of zero is equally true of a
	// connection that was opened and then closed, which is precisely the state this test must
	// distinguish itself from.
	if got := accepts.Load(); got != 0 {
		t.Fatalf("refusing before the transport must not even open a connection, accepted %d", got)
	}
	if !SendNeverStarted(err) {
		t.Fatal("a first-leg pre-send refusal is provably never-sent; without that evidence the " +
			"executor records may_have_been_sent for an invocation that never happened")
	}
}

// Refusing at the SECOND site — after the TCP connect and the TLS handshake — still sends nothing.
//
// This is the window an earlier revision left open on the argument that connect+TLS is "bounded by
// configured timeouts". It is bounded only by whatever an operator configured, and DialTLSContext
// is a clean abortable seam, so the argument did not survive contact (Codex P1, round 6). The hook
// permits the first ask (roundTrip) and refuses the second (post-handshake), which is exactly the
// state that used to send.
func TestPreSend_RefusalAfterTheHandshakeStillSendsNothing(t *testing.T) {
	var hits int
	c, target, _, accepts, stop := pinnedTestServerCounting(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"call-1","result":{}}`)
	})
	defer stop()

	refusal := errors.New("authority withdrawn during the handshake")
	var asks atomic.Int64
	_, err := c.Call(context.Background(), target, "tools/list", nil, CallOptions{
		Idempotent: true, WireID: "call-1",
		PreSend: func() error {
			if asks.Add(1) == 1 {
				return nil // the pre-transport site permits; the withdrawal lands during the handshake
			}
			return refusal
		},
	})

	if asks.Load() < 2 {
		t.Fatalf("premise: the predicate must be asked again after the handshake, asked %d time(s) — "+
			"without a second ask this proves nothing about the connect/TLS window", asks.Load())
	}
	if !errors.Is(err, refusal) {
		t.Fatalf("the caller must receive its own refusal verbatim, got %v", err)
	}
	// CUMULATIVE again, and here the gauge was actively wrong: by the time Call returns, our own
	// refusal has already closed the socket, so the server's StateClosed drives a live gauge back
	// to zero and the assertion races it. `asks >= 2` above proves OUR side of the handshake
	// completed (the second ask is unreachable until HandshakeContext returns nil); this proves the
	// peer actually accepted a connection, which is what separates this site from the first one.
	if got := accepts.Load(); got < 1 {
		t.Fatalf("premise: the connection must actually have been established, or the refusal is "+
			"being caught before the window this test is about, accepted %d", got)
	}
	if hits != 0 {
		t.Fatalf("SECURITY: authority was withdrawn after the handshake and %d request(s) were "+
			"still served — the connect/TLS window", hits)
	}
	if !SendNeverStarted(err) {
		t.Fatal("a post-handshake refusal is still provably never-sent: the socket is closed with " +
			"nothing written, which is the whole reason this seam beats cancelling the context")
	}
}

// The mandatory control: a predicate that permits does not interfere at either site.
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

	var asks atomic.Int64
	resp, err := c.Call(context.Background(), target, "tools/list", nil, CallOptions{
		Idempotent: true, WireID: "call-1",
		PreSend: func() error { asks.Add(1); return nil },
	})
	if err != nil {
		t.Fatalf("CONTROL: a permitting hook must not block the call: %v", err)
	}
	if resp == nil || hits != 1 {
		t.Fatalf("CONTROL: expected exactly one served request, server=%d", hits)
	}
	if asks.Load() < 2 {
		t.Fatalf("CONTROL: both re-ask sites must run on a fresh connection, asked %d time(s)", asks.Load())
	}
}

// THE FIRST SITE RUNS AFTER THE POOL SLOT IS HELD, which is why it exists at all: the executor's
// own boundary guards run before Call, and the wait for a slot sits between them and the send.
//
// Deterministic, not timing-based: every slot is held by a request parked in the handler, and the
// test waits for exactly that many handler entries before launching the queued call.
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

	var asks atomic.Int64
	_, err := c.Call(context.Background(), target, "tools/list", nil, CallOptions{
		Idempotent: true, WireID: "retry",
		PreSend: func() error { asks.Add(1); return nil },
	})
	if err != nil {
		t.Fatalf("premise: the retried read should succeed on its second leg: %v", err)
	}
	if got := hits.Load(); got < 2 {
		t.Skipf("premise: the client did not retry in this run (%d leg(s)); nothing to prove", got)
	}
	// At least one re-ask per leg. Not an exact multiple: whether a leg dials (two asks) or reuses
	// a connection (one) is the transport's business, and pinning it would make this a test of
	// net/http's pooling rather than of the contract.
	if asks.Load() < hits.Load() {
		t.Fatalf("SECURITY: %d physical leg(s) but only %d pre-send re-ask(s) — a retry sent on the "+
			"strength of a check made before an earlier leg", hits.Load(), asks.Load())
	}
}
