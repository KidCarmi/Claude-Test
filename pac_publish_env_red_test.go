package main

// pac_publish_env_red_test.go — PR-C1c RED proof.
//
// The PAC lifecycle API tests (pac_publish_api_test.go) publish through the
// real handler, and a publish is complete only once its post-commit effects
// land — one of them a config-version capture. Their environment helper
// isolated every PAC store but left the config-version store on the
// process default, `<dataDir>/config_versions` = `/data/config_versions`.
// A root-run qualification never noticed; the CI runner's unprivileged user
// has no `/data`, so every capture failed, the first publish stayed
// `pending_reconciliation`, and the next one answered
// `409 operation_pending` (the "Gate · go test -race + coverage floors"
// failure on the frozen head). This gate pins the invariant directly: the
// PAC publish test environment must never depend on the process data root.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPACPublishEnv_ConfigVersionStoreIsIsolatedFromDataRoot(t *testing.T) {
	resetPACPublishGlobals(t)
	dir := configVersions.Dir()
	if dir == "" {
		t.Fatal("the config-version store must have a directory")
	}
	root := filepath.Clean(defaultDataDir) + string(filepath.Separator)
	if dir == filepath.Clean(defaultDataDir) || strings.HasPrefix(dir, root) {
		t.Fatalf("the PAC publish test environment leaves the config-version store on the process data root %q; a runner without a writable %s cannot capture a version, so the lifecycle journeys refuse the next publish with operation_pending", dir, defaultDataDir)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("the isolated config-version directory must be creatable: %v", err)
	}
	probe := filepath.Join(dir, ".probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatalf("the isolated config-version directory must be writable: %v", err)
	}
	_ = os.Remove(probe)
}
