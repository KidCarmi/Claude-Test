package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// TestADRNumberingNoCollisions is the CI-enforced half of the reservation-convention
// recommendation raised by the Language & Terminology Governance routine after the
// identical "two documents claim the same ADR-NNNN number" defect recurred four times
// (T-16, T-46, T-47, and the ADR-0034 collision fixed alongside this test — see
// docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-08.md). Every prior occurrence
// was caught only by a human/AI review pass grepping the tree after the fact; this test
// makes the same check a merge-blocking part of the existing root `go test ./...` run
// (already required by pr-fast-gate.yml), so a PR that reintroduces a duplicate header
// fails BEFORE merge instead of days later.
//
// Two directories carry `# ADR-NNNN: ...` headers: docs/adr/ (adopted architecture
// decisions) and docs/support/rfc/ (proposed, not-yet-adopted RFC-track documents that
// happen to self-title themselves "ADR-NNNN" — see docs/support/rfc/0019 through 0022
// and 0036). Both share ONE numbering space: a bare "ADR-0018" citation elsewhere in the
// repo is ambiguous unless the number maps to exactly one document, regardless of which
// of the two directories holds it.
//
// This test does NOT allocate or reserve numbers for future PRs — it only rejects two
// EXISTING files claiming the same number at merge time, which is the cheapest point to
// catch it (before either branch's number choice has propagated into cross-references,
// GUI copy, or other ADRs' "Relates to" lines).
func TestADRNumberingNoCollisions(t *testing.T) {
	headerRe := regexp.MustCompile(`^#\s*ADR-(\d+)\b`)

	type owner struct {
		file   string
		number string
	}
	byNumber := map[string][]owner{}

	dirs := []string{
		filepath.Join("docs", "adr"),
		filepath.Join("docs", "support", "rfc"),
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path) // #nosec G304 -- fixed, repo-relative doc directories only
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			num := ""
			for _, line := range splitLinesForADRTest(data) {
				if m := headerRe.FindStringSubmatch(line); m != nil {
					num = m[1]
					break
				}
				// Only the first non-empty line and the first Markdown heading are
				// candidates; an RFC's leading "> STATUS: ..." blockquote line is
				// skipped implicitly because it never matches headerRe, and we keep
				// scanning until we find the real "# ADR-NNNN" heading or exhaust a
				// generous prefix of the file.
			}
			if num == "" {
				continue // not every docs/adr file self-titles "ADR-NNNN" in its header (e.g. ADR-FE-*)
			}
			byNumber[num] = append(byNumber[num], owner{file: path, number: num})
		}
	}

	var collidingNumbers []string
	for num, owners := range byNumber {
		if len(owners) > 1 {
			collidingNumbers = append(collidingNumbers, num)
		}
	}
	sort.Strings(collidingNumbers)

	for _, num := range collidingNumbers {
		owners := byNumber[num]
		files := make([]string, len(owners))
		for i, o := range owners {
			files[i] = o.file
		}
		sort.Strings(files)
		t.Errorf("ADR-%s is claimed by %d documents (must be exactly 1): %v — renumber the newer/less-established "+
			"one to the next number confirmed clean against every '# ADR-NNNN' header in docs/adr/ and "+
			"docs/support/rfc/, and update its downstream citations", num, len(owners), files)
	}
}

// splitLinesForADRTest scans only the first few lines of a doc — the header always
// appears near the top (RFC-track files carry one leading status blockquote line first).
func splitLinesForADRTest(data []byte) []string {
	const maxLines = 8
	lines := make([]string, 0, maxLines)
	start := 0
	for i := 0; i < len(data) && len(lines) < maxLines; i++ {
		if data[i] == '\n' {
			lines = append(lines, string(data[start:i]))
			start = i + 1
		}
	}
	if len(lines) < maxLines && start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}
