package main

import (
	"path/filepath"
	"testing"
)

// PR-C1: the persisted-state root is overridable ONLY through an absolute,
// non-root path; blank keeps the /data default byte-identical.
func TestResolveDataDir(t *testing.T) {
	cases := []struct {
		name, raw, want string
		wantErr         bool
	}{
		{name: "unset keeps the default", raw: "", want: defaultDataDir},
		{name: "blank keeps the default", raw: "   \t", want: defaultDataDir},
		{name: "absolute path is honored", raw: "/srv/culvert-data", want: "/srv/culvert-data"},
		{name: "trailing separator is cleaned", raw: "/srv/culvert-data/", want: "/srv/culvert-data"},
		{name: "surrounding whitespace is trimmed", raw: "  /srv/culvert-data  ", want: "/srv/culvert-data"},
		{name: "dot segments are cleaned", raw: "/srv/x/../culvert-data", want: "/srv/culvert-data"},
		{name: "relative path is refused", raw: "data", wantErr: true},
		{name: "dot-relative path is refused", raw: "./data", wantErr: true},
		{name: "filesystem root is refused", raw: "/", wantErr: true},
		{name: "root spelled with dots is refused", raw: "/./", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveDataDir(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveDataDir(%q) = %q, want an error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveDataDir(%q): %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("resolveDataDir(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if !filepath.IsAbs(got) {
				t.Fatalf("resolved root %q is not absolute", got)
			}
		})
	}
}

// The default is the historical constant every deployment (compose,
// installer, operator docs) relies on.
func TestResolveDataDir_DefaultIsSlashData(t *testing.T) {
	if defaultDataDir != "/data" {
		t.Fatalf("defaultDataDir = %q, want /data", defaultDataDir)
	}
}
