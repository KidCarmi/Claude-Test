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
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		u.User = nil
		return u.String()
	}
	return stripAuthorityUserinfo(raw)
}

// stripAuthorityUserinfo removes `userinfo@` from the authority of a URL-shaped
// string that url.Parse rejected. It deliberately reasons about the authority
// only: an '@' in a path, query or fragment is not userinfo and is left alone.
func stripAuthorityUserinfo(raw string) string {
	start := authorityStart(raw)
	if start < 0 {
		return raw
	}
	end := start + authorityLen(raw[start:])
	at := strings.LastIndexByte(raw[start:end], '@')
	if at < 0 {
		return raw
	}
	return raw[:start] + raw[start+at+1:end] + raw[end:]
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

// authorityLen returns the length of the authority at the head of s — up to
// the first path, query or fragment delimiter, which are the only three
// characters that can terminate an authority.
func authorityLen(s string) int {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return i
	}
	return len(s)
}
