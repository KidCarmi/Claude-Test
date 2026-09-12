package fileutil

import "sync/atomic"

// syncObserver is a TEST-ONLY observability seam for durability
// synchronisation: every fsync this package performs on a file or a
// directory reports (kind, path) here, so a test can prove that a "durable"
// acknowledgement was preceded by the synchronisation it claims. It carries
// no behaviour of its own — nil means nobody is listening.
var syncObserver atomic.Pointer[func(kind, path string)]

// SetSyncObserverForTest installs fn as the synchronisation observer and
// returns a restore func. kind is "file" or "dir".
func SetSyncObserverForTest(fn func(kind, path string)) (restore func()) {
	var old *func(kind, path string)
	if fn == nil {
		old = syncObserver.Swap(nil)
	} else {
		old = syncObserver.Swap(&fn)
	}
	return func() { syncObserver.Store(old) }
}

// noteSync reports one completed synchronisation to the observer.
func noteSync(kind, path string) {
	if p := syncObserver.Load(); p != nil {
		(*p)(kind, path)
	}
}
