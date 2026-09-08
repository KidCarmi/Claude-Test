package main

// data_dir_paths_red_test.go — PR-C1b: the persisted-state root override
// (CULVERT_DATA_DIR) must bind EVERY /data-rooted default, not only the
// stores that read dataDir at their own startup. The browser smoke under an
// empty read-only /data (the CI premise) still failed every PAC lifecycle
// journey after PR-C1: a publish's post-commit config-version effect wrote
// to the package-level config-version store, constructed at init time
// against a literal "/data/config_versions", so the operation stayed
// "pending reconciliation" (409 operation_pending) and every later
// lifecycle action was refused. The other literal /data roots (registry
// settings, the CDR certs root and runtime-enabled marker, the alert retry
// queue, the CDR store defaults, the reset-password roster default) have
// the same shape. RED on the tree at this commit's parent.

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDataDirOverride_RebindsHardcodedDefaults(t *testing.T) {
	root := t.TempDir()
	prevDataDir, prevVersions, prevMarker := dataDir, configVersions, cdrRuntimeEnabledPath
	t.Cleanup(func() {
		dataDir, configVersions, cdrRuntimeEnabledPath = prevDataDir, prevVersions, prevMarker
	})
	t.Setenv(dataDirEnv, root)
	applyDataDirFromEnv()
	if dataDir != root {
		t.Fatalf("dataDir = %q, want %q", dataDir, root)
	}
	inside := root + string(filepath.Separator)
	checks := map[string]string{
		"config-version store":       configVersions.Dir(),
		"registry settings file":     registrySettingsFile,
		"CDR certs root":             cdrCertsRoot,
		"CDR runtime-enabled marker": cdrRuntimeEnabledPath,
	}
	for name, p := range checks {
		if !strings.HasPrefix(p, inside) {
			t.Errorf("%s persists at %q — outside the overridden root %q", name, p, root)
		}
	}
}
