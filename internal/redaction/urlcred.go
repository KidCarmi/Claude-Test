package redaction

// urlcred.go — fail-CLOSED removal of URL userinfo (`scheme://user:pass@host`).
//
// An operator may configure a service URL that carries embedded credentials
// (a scan sidecar, a mirror, a presigned origin). Those URLs reach viewer-role
// read surfaces and the process log, so the credential must be stripped before
// they do.
//
// The rule that makes this correct is that the redactor must NEVER hand back
// input it failed to understand. url.Parse is strict about characters that are
// perfectly ordinary inside a password — a bare '%' ("pw%zz" is an invalid
// escape), a raw control character, a space in the authority — so "parse
// failed" and "carries no credential" are entirely different statements. A
// redactor that conflates them leaks exactly the passwords that contain the
// awkward characters. The parse failure is therefore the trigger for a
// LEXICAL strip, never for a passthrough.

import (
	"net/url"
	"strings"
)

// URLUserinfo returns raw with any URL userinfo removed.
//
// url.Parse is the canonical path, used only when it actually RECOGNISES
// userinfo. Every other input — the ones that fail to parse, and the ones that
// parse into an opaque form where net/url sees no userinfo at all
// ("http:user:pw@host", "u:pw@host:8484") — goes through the lexical strip,
// which locates the authority and drops everything up to and including its
// last '@'. The lexical strip is a no-op on an authority carrying no '@', so
// credential-free input is returned unchanged.
//
// The two-branch shape is deliberate: "url.Parse found no userinfo" and "this
// string carries no credential" are different statements, and treating the
// first as the second is how the awkward inputs leak.
func URLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err == nil {
		if u.User != nil {
			u.User = nil
			return u.String()
		}
		// net/url parsed the whole string and found no userinfo. Its verdict is
		// authoritative for every hierarchical URL, so an '@' in the path,
		// query or fragment is left alone. The one place a credential can still
		// hide is the OPAQUE form ("http:u:pw@host", "u:pw@host:8484"), which
		// net/url does not read as an authority at all.
		if u.Opaque == "" || !strings.ContainsRune(u.Opaque, '@') {
			return raw
		}
		return stripThroughLastAt(raw)
	}
	// PARSE FAILED. Nothing about this string's structure is established: the
	// '/', '?' and '#' that delimit an authority in a WELL-FORMED URL prove
	// nothing here, and a password may contain any of them
	// ("http://user:pw?part@host" parses as neither an authority nor a query).
	// Bounding the search by those delimiters is what let the first version of
	// this helper hand such a password back verbatim, so the search runs to the
	// LAST '@' in the string instead.
	//
	// The cost is over-redaction on malformed input that carries an unrelated
	// '@' later on — a mangled diagnostic string. That is the correct trade:
	// this branch only ever sees input net/url already rejected, and returning
	// a credential is not recoverable while a mangled URL is.
	return stripThroughLastAt(raw)
}

// stripThroughLastAt removes everything from the start of the authority through
// the LAST '@' in the string. Input carrying no '@' cannot hold userinfo and is
// returned unchanged.
func stripThroughLastAt(raw string) string {
	start := authorityStart(raw)
	if start < 0 {
		return raw
	}
	at := strings.LastIndexByte(raw[start:], '@')
	if at < 0 {
		return raw
	}
	return raw[:start] + raw[start+at+1:]
}

// authorityStart returns the index at which the authority begins, or -1 when
// the input has no authority component. "scheme://" and a scheme-relative
// "//" both introduce one; a bare "host:port/path" is treated as an authority
// so a schemeless `user:pass@host` cannot slip through.
func authorityStart(raw string) int {
	if i := strings.Index(raw, "://"); i >= 0 {
		return i + 3
	}
	if strings.HasPrefix(raw, "//") {
		return 2
	}
	if strings.ContainsAny(raw, "@") {
		return 0
	}
	return -1
}
