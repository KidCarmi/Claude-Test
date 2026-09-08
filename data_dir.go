package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// dataDirEnv is the startup-scoped override of the persisted-state root
// (dataDir, default /data). It is read ONCE, before flag parsing and before
// any one-shot command, so every consumer of dataDir — the admin settings
// file, the object stores, PAC profiles, CDR state, the config-version
// store, the audit/log stores, backup/restore/prepare-downgrade — sees one
// value for the life of the process.
//
// The default is unchanged: unset (or blank) ⇒ /data, byte-identical to a
// build without the override. The override exists for non-container runs
// and for test harnesses that must NOT share (or be able to write) the
// host's /data: the real-binary browser smoke used to depend on a
// world-writable /data, which a CI runner does not have, and every
// /data-backed mutation then failed persist (2F correction, PR-C1).
//
// Startup-scoped and env-only: a recorded GUI-parity deferral of the same
// class as the HA-lease endpoints — the persisted-state root cannot be
// moved by the process that is persisting into it.
const (
	dataDirEnv     = "CULVERT_DATA_DIR"
	defaultDataDir = "/data"
)

// resolveDataDir returns the effective persisted-state root for the raw
// environment value: blank ⇒ the default; otherwise an ABSOLUTE, cleaned
// path that is not the filesystem root. A relative path is refused (it
// would silently bind the appliance's state to the process's cwd), and so
// is "/" (a restore commit renames siblings of dataDir).
func resolveDataDir(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return defaultDataDir, nil
	}
	if !filepath.IsAbs(v) {
		return "", fmt.Errorf("%s must be an absolute path, got %q", dataDirEnv, raw)
	}
	c := filepath.Clean(v)
	if c == string(filepath.Separator) {
		return "", fmt.Errorf("%s must not be the filesystem root", dataDirEnv)
	}
	return c, nil
}

// applyDataDirFromEnv installs the resolved root into dataDir. An invalid
// value is FATAL: booting against the default while the operator asked for
// another root would persist state where nobody looks for it.
func applyDataDirFromEnv() {
	d, err := resolveDataDir(os.Getenv(dataDirEnv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	dataDir = d
}

// dataDirOverridden reports whether the effective root differs from the
// default, for the one startup log line that records the override.
func dataDirOverridden() bool { return dataDir != defaultDataDir }
