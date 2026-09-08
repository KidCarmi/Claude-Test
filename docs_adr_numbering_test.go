package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
			// The document's title is its first Markdown heading line, wherever it
			// falls — an RFC's leading "> STATUS: ..." blockquote (and any blank
			// lines around it) is skipped implicitly because it never starts with
			// "#". Stopping at the FIRST heading (rather than scanning the whole
			// file for any ADR-NNNN-shaped line) avoids a false match on a "Relates
			// to: ADR-0016" body line further down; not capping the scan at a fixed
			// line count (a prior version capped at 8 and a Codex review on the PR
			// that introduced this test caught that a longer front-matter block
			// would push the real heading past the cap and make the gate silently
			// skip the file) means front matter of any length is still followed
			// through to the real title.
			if line := firstMarkdownHeading(data); line != "" {
				if m := headerRe.FindStringSubmatch(line); m != nil {
					num = m[1]
				}
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

// TestFirstMarkdownHeading_NoLineCountCap pins the fix for a Codex review finding on
// the PR that introduced this file: an earlier version capped its scan at the first 8
// physical lines, so a document with 8+ lines of front matter before its real heading
// was silently treated as unnumbered and dropped out of the collision check entirely —
// exactly the kind of gap that would let a fifth ADR-numbering collision (see T-16,
// T-46, T-47, T-48) slip past a gate built specifically to catch it.
func TestFirstMarkdownHeading_NoLineCountCap(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString("> front matter line that is not a heading\n")
	}
	sb.WriteString("# ADR-0099: heading pushed past any small fixed line cap\n")
	sb.WriteString("\nbody text\n")

	got := firstMarkdownHeading([]byte(sb.String()))
	want := "# ADR-0099: heading pushed past any small fixed line cap"
	if got != want {
		t.Fatalf("firstMarkdownHeading with 21 lines of front matter = %q, want %q", got, want)
	}
}

// firstMarkdownHeading returns the first line of data (trimmed) that starts with
// "#", scanning the WHOLE file — no line-count cap, so front matter of any length
// before the real title is followed through rather than silently truncated past.
func firstMarkdownHeading(data []byte) string {
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			line := strings.TrimSpace(string(data[start:i]))
			if strings.HasPrefix(line, "#") {
				return line
			}
			start = i + 1
		}
	}
	return ""
}
