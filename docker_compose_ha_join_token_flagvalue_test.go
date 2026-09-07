package main

// docker_compose_ha_join_token_flagvalue_test.go — deployment-artifact
// contract for docker-compose.ha.yml's proxy `command:` shell script.
//
// Step 4 of the file's own header comment instructs an operator standing up
// the HA standby node to "set HA_JOIN + HA_TOKEN env vars, then:
// docker compose -f docker-compose.ha.yml up -d". The embedded shell script
// builds the culvert argv as a single ARGS string and hands it to the binary
// via an UNQUOTED `exec ./culvert $$ARGS` — word-splitting is what turns that
// string back into separate argv tokens. That is fine as long as every
// variable substituted into ARGS is non-empty, but `--ha-token $$HA_TOKEN`
// is appended unconditionally inside the `if [ -n "$$HA_JOIN" ]` guard, which
// checks HA_JOIN, never HA_TOKEN. If an operator sets HA_JOIN but leaves
// HA_TOKEN empty/unset (a plausible copy-paste slip, since the GUI's deploy
// command names both but nothing stops setting just one), the shell's
// word-splitting drops the empty $$HA_TOKEN expansion ENTIRELY rather than
// emitting an empty argv token — leaving a dangling `--ha-token` flag with no
// value as the last word handed to the binary. Go's flag package rejects
// that outright ("flag needs an argument: -ha-token") and, because main.go
// calls the top-level flag.Parse() (ExitOnError), the process os.Exit(2)s
// before ever reaching the proxy listener — the standby node crash-loops
// under restart: unless-stopped instead of joining the cluster.
import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestDockerComposeHA_JoinWithoutTokenYieldsValidArgv extracts the proxy
// service's real `command: >` shell script from docker-compose.ha.yml, runs
// it under `sh` exactly as Compose would present it to the container
// (mirroring the file's own `$$` → `$` escaping), and asserts that setting
// only HA_JOIN (HA_TOKEN left empty, as an operator might by mistake) still
// produces a well-formed argv — no dangling flag with a missing value.
func TestDockerComposeHA_JoinWithoutTokenYieldsValidArgv(t *testing.T) {
	data, err := os.ReadFile("docker-compose.ha.yml")
	if err != nil {
		t.Fatalf("read docker-compose.ha.yml: %v", err)
	}
	s := string(data)

	// Isolate the proxy service's `command: >` folded shell script — from
	// just after the "command: >" line to the next same-indent "healthcheck:"
	// key that terminates it.
	cmdRE := regexp.MustCompile(`(?s)\n {4}command: >\n(.*?)\n {4}healthcheck:`)
	m := cmdRE.FindStringSubmatch(s)
	if m == nil {
		t.Fatal("docker-compose.ha.yml: could not isolate the proxy service's `command: >` script — update this test if the file's shape changed")
	}
	script := m[1]

	// Compose escapes "$$" to a literal "$" before the string ever reaches
	// the container's shell; mirror that so the extracted script behaves
	// exactly as it would inside the container.
	script = strings.ReplaceAll(script, "$$", "$")

	// Replace the terminal `exec ./culvert $ARGS` with a diagnostic that
	// prints the ACTUAL argv the shell would hand to the binary, one token
	// per line — via `set --`, the same unquoted-word-splitting mechanism
	// the real `exec` line relies on.
	execRE := regexp.MustCompile(`exec \./culvert \$ARGS`)
	if !execRE.MatchString(script) {
		t.Fatal("docker-compose.ha.yml: could not find the terminal `exec ./culvert $ARGS` line in the proxy command script — update this test if the file's shape changed")
	}
	script = execRE.ReplaceAllLiteralString(script, `set -- $ARGS; for a in "$@"; do printf "%s\n" "$a"; done`)

	// The documented step-4 scenario: HA_JOIN is set, HA_TOKEN is not
	// (everything else — enterprise TLS — left at its documented default of
	// unset/empty).
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(),
		"HA_JOIN=server-a.internal:50051", "HA_TOKEN=",
		"CP_CERT=", "CP_KEY=", "CP_CA=")
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		t.Fatalf("running the extracted proxy command script failed: %v\noutput:\n%s", runErr, out)
	}
	argv := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(argv) == 0 || argv[len(argv)-1] == "" {
		t.Fatalf("extracted no argv tokens from the command script; raw output:\n%s", out)
	}

	// A flag token is well-formed here either because it isn't the LAST word
	// (something follows it as its value) or because it carries its value
	// inline via `=`. A flag-looking token that is BOTH last AND has no `=`
	// is a dangling flag with nothing for flag.Parse to consume as its value.
	last := argv[len(argv)-1]
	if strings.HasPrefix(last, "-") && !strings.Contains(last, "=") {
		t.Fatalf("docker-compose.ha.yml: with HA_JOIN set and HA_TOKEN unset, the generated argv ends "+
			"with a dangling flag %q that has no value (word-splitting drops the empty $HA_TOKEN "+
			"expansion entirely instead of emitting an empty token) — `./culvert` would fail to start "+
			"with \"flag needs an argument: -ha-token\" and flag.Parse's ExitOnError would exit the "+
			"process before the standby ever joins the cluster. full argv: %v", last, argv)
	}
}
