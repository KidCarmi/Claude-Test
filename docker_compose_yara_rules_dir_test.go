package main

// docker_compose_yara_rules_dir_test.go — deployment-artifact contract for
// the proxy service's YARA rules directory in docker-compose.yml.
//
// The top-of-file comment documents a specific operator workflow:
//
//	# YARA rules (/app/yara in the proxy container):
//	#   Starter rules are bundled in the image (yara/sample_rules.yar).
//	#   Override: mount a host directory over /app/yara, then reload at runtime via
//	#   POST /api/security-scan/yara/reload
//
// and the proxy service's commented-out volume example follows suit:
//
//	# - ./yara:/app/yara:ro
//
// But the proxy service's actual command line passes:
//
//	"-yara-rules-dir", "/data/yara",
//
// `globalYARA.LoadDir` (scanning_startup.go) remembers exactly that
// directory as `globalYARA.Dir()`, and `POST /api/security-scan/yara/reload`
// (ui_security.go) reloads from `globalYARA.Dir()` — never from /app/yara.
// seedYARARules (main.go) copies the bundled /app/yara starter rules into
// /data/yara only once, on first boot while /data/yara is still empty.
//
// So an operator who follows the documented workflow on an EXISTING
// deployment — mount a host directory over /app/yara, restart, then POST the
// reload endpoint, exactly as instructed — silently gets no effect: the
// persistent /data/yara directory already has content from the first-boot
// seed, so it is never re-seeded from /app/yara, and the reload endpoint
// never reads /app/yara in the first place. No error is returned anywhere in
// this path. The documented override mechanism does not work against the
// documented runtime flag.
//
// This test pins the two to agree: the directory named in the top-of-file
// YARA comment (and its commented-out volume example) must match the
// -yara-rules-dir value actually passed to the proxy service.

import (
	"os"
	"regexp"
	"testing"
)

func TestDockerComposeYARADocsMatchRulesDirFlag(t *testing.T) {
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	s := string(compose)

	flagMatch := regexp.MustCompile(`"-yara-rules-dir",\s*"([^"]+)"`).FindStringSubmatch(s)
	if flagMatch == nil {
		t.Fatal("docker-compose.yml: proxy service command has no `-yara-rules-dir` flag")
	}
	effectiveDir := flagMatch[1]

	commentMatch := regexp.MustCompile(`YARA rules \(([^ ]+) in the proxy container\)`).FindStringSubmatch(s)
	if commentMatch == nil {
		t.Fatal("docker-compose.yml: no top-of-file `YARA rules (<dir> in the proxy container)` comment found")
	}
	documentedDir := commentMatch[1]
	if documentedDir != effectiveDir {
		t.Errorf("docker-compose.yml documents the YARA rules directory as %q but the proxy service's "+
			"actual `-yara-rules-dir` flag is %q — an operator who mounts a host directory over %q and "+
			"reloads via POST /api/security-scan/yara/reload (exactly as the comment instructs) gets no "+
			"effect: globalYARA.Dir()/reload always reads %q, and seedYARARules only ever copies INTO "+
			"%q once, on first boot while it is still empty.",
			documentedDir, effectiveDir, documentedDir, effectiveDir, effectiveDir)
	}

	overrideMatch := regexp.MustCompile(`Override: mount a host directory over (\S+),`).FindStringSubmatch(s)
	if overrideMatch == nil {
		t.Fatal("docker-compose.yml: no `Override: mount a host directory over <dir>,` comment found")
	}
	if overrideMatch[1] != effectiveDir {
		t.Errorf("docker-compose.yml's YARA override instruction names %q but the proxy service's "+
			"actual `-yara-rules-dir` flag is %q — mounting over %q has no effect on the running rule set.",
			overrideMatch[1], effectiveDir, overrideMatch[1])
	}

	volExampleMatch := regexp.MustCompile(`# - \./yara:(\S+):ro`).FindStringSubmatch(s)
	if volExampleMatch == nil {
		t.Fatal("docker-compose.yml: no commented-out `# - ./yara:<dir>:ro` volume example found")
	}
	if volExampleMatch[1] != effectiveDir {
		t.Errorf("docker-compose.yml's commented-out YARA volume example mounts over %q but the proxy "+
			"service's actual `-yara-rules-dir` flag is %q — uncommenting this example as instructed "+
			"would not affect the loaded rule set.",
			volExampleMatch[1], effectiveDir)
	}
}
