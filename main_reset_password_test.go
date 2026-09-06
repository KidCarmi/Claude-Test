package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestRunResetPasswordCommand_UnreadableRosterIsNotOverwritten reproduces a
// realistic deployment edge case for --reset-password (the documented admin
// lockout recovery path, run e.g. via `docker compose --profile cli run
// --rm cli --reset-password admin:newpassword` against the shared
// proxy-data volume): the roster file exists and holds real accounts, but
// for some reason (a UID mismatch after an image upgrade — the container
// runs as the non-root "proxy" user per the Dockerfile — a bind-mount
// source that resolved to the wrong file type, a transient read fault, ...)
// it cannot be READ back. That is neither the legitimate first-run case
// (file missing) nor the CHAOS-05 corrupt-JSON case (which quarantines the
// bad file by moving it aside before returning an error).
//
// --reset-password used to ignore the LoadUIUsersFile error entirely
// (`_ = cfg.LoadUIUsersFile()`) and press on with SetUIUser+SaveUIUsersFile
// against an EMPTY in-memory roster, silently replacing the intact,
// merely-unreadable file with a single fresh admin account — destroying
// every other admin/operator/viewer account and TOTP enrollment with no
// error, no quarantine copy, and no way back.
func TestRunResetPasswordCommand_UnreadableRosterIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")

	// Seed a real, valid, multi-user roster the way the running proxy would
	// have built it up over time.
	seed := &Config{}
	seed.SetUIUsersFile(path)
	if err := seed.SetUIUser("original-admin", "OriginalPass1", RoleAdmin); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := seed.SetUIUser("original-viewer", "ViewerPass1", RoleViewer); err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if err := seed.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	// Replace the regular file with a unix-domain socket bound to the same
	// path. This is a deterministic, privilege-independent way to produce a
	// real, non-missing os.ReadFile failure: os.Stat/Lstat report the path
	// as present, but reading it fails with "no such device or address"
	// (ENXIO) — neither os.IsNotExist nor a JSON parse error, so it is NOT
	// the quarantine path. It also proves the destructive half of the bug:
	// fileutil.AtomicWrite's rename-into-place CAN replace a socket special
	// file just like a regular one, so if the buggy code presses on to
	// Save(), the overwrite silently "succeeds".
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove seeded file: %v", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("bind unix socket at roster path: %v", err)
	}
	defer ln.Close()

	if _, err := os.ReadFile(path); err == nil || os.IsNotExist(err) {
		t.Fatalf("test setup invalid: expected a non-missing read failure, got err=%v", err)
	}

	newCreds := "attacker:BrandNewPass1"
	uiUsersFile := path
	s := &startupState{
		resetPwUser: &newCreds,
		uiUsersFile: &uiUsersFile,
	}

	runErr := runResetPasswordCommand(s)

	if runErr == nil {
		// The bug: the command reported success. Confirm the destruction to
		// make the failure message unambiguous.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("runResetPasswordCommand reported success (nil error) but the roster path is still unreadable: %v", readErr)
		}
		var env uiUsersFileEnvelope
		_ = json.Unmarshal(data, &env)
		t.Fatalf("runResetPasswordCommand silently overwrote an unreadable-but-intact roster with a fresh one (users now: %v) instead of refusing — original-admin/original-viewer are gone for good", env.Users)
	}

	// Fixed behavior: refuse, and leave the on-disk state exactly as it was
	// (still the socket, never replaced by a freshly written roster file).
	fi, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatalf("roster path vanished entirely: %v", statErr)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("roster path was replaced (mode=%v) even though runResetPasswordCommand returned an error", fi.Mode())
	}
}

// TestRunResetPasswordCommand_LstatItselfFailingIsNotProofOfAbsence pins the
// Codex review finding on the first fix: the guard must treat an inability
// to prove "usersPath is gone" as a reason to abort, not just usersPath
// visibly existing. The original guard checked `statErr == nil` — so if
// os.Lstat itself failed for its OWN reason (a transient I/O fault, or here
// an ENOTDIR from a path component that resolved to a regular file instead
// of a directory) it fell through as if the roster were confirmed absent,
// and would still have overwritten an intact-but-momentarily-unprobable
// roster once storage recovered. Only an affirmative os.IsNotExist result
// may be trusted as "safe to create fresh".
func TestRunResetPasswordCommand_LstatItselfFailingIsNotProofOfAbsence(t *testing.T) {
	dir := t.TempDir()
	// A regular file standing where a directory component is expected turns
	// any Lstat/ReadFile under it into ENOTDIR — never ENOENT — regardless
	// of privilege, so this is deterministic and root-safe like the socket
	// case above.
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	path := filepath.Join(blocker, "ui_users.json")

	if _, err := os.Lstat(path); err == nil || os.IsNotExist(err) {
		t.Fatalf("test setup invalid: expected a non-missing Lstat failure (ENOTDIR), got err=%v", err)
	}

	newCreds := "attacker:BrandNewPass1"
	uiUsersFile := path
	s := &startupState{
		resetPwUser: &newCreds,
		uiUsersFile: &uiUsersFile,
	}

	if err := runResetPasswordCommand(s); err == nil {
		t.Fatal("expected runResetPasswordCommand to refuse when Lstat cannot confirm the roster is absent, got nil error")
	}

	// Nothing should have been created at or under the blocked path.
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("runResetPasswordCommand created a roster file despite the unresolved Lstat failure")
	}
}
