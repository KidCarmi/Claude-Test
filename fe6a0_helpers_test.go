package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
)

// fencedIdPPath builds the fenced /api/idp/{id} path for a PUT/DELETE in
// tests: the entry's CURRENT server-minted revision is echoed as the
// `revision` query parameter (FE-6A.0 C2), plus any extra query terms.
func fencedIdPPath(id string, extra ...string) string {
	rev := int64(1)
	if p := idpRegistry.Get(id); p != nil {
		rev = idpEntryRevision(p)
	}
	q := []string{"revision=" + strconv.FormatInt(rev, 10)}
	q = append(q, extra...)
	return "/api/idp/" + id + "?" + strings.Join(q, "&")
}

// fencedUsersPath builds the fenced /api/auth/users path carrying the
// current roster revision (plus extra query terms, e.g. username=…).
func fencedUsersPath(extra ...string) string {
	q := []string{"revision=" + strconv.FormatInt(cfg.RosterRevision(), 10)}
	q = append(q, extra...)
	return "/api/auth/users?" + strings.Join(q, "&")
}

// fencedDeleteReq builds an admin DELETE request against a fenced path.
func fencedDeleteReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, path, http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	return adminCtx(r)
}
