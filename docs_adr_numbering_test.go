package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// TestADRNumberingIsUnique guards a defect class the terminology-governance
// routine has now fixed four separate times (docs/engineering/
// TERMINOLOGY-GOVERNANCE-REVIEW-2026-07-24.md, -08-06.md, -08-25.md,
// -09-07.md): two independent PR streams each compute "the next free ADR
// number" by grepping the tree at merge time, with no reservation
// mechanism, and land the same number. A duplicate `# ADR-NNNN` header
// across docs/adr/ (accepted decisions) and docs/support/rfc/ (proposed,
// self-titled as ADR-NNNN pending adoption) makes a bare "ADR-0034"
// citation ambiguous between two unrelated decisions with no way to
// disambiguate from the number alone. This is a build-breaking check, not
// a style nit — the fourth recurrence is the point the governance review
// records as where fixing it each time stops being cheaper than
// preventing it.
func TestADRNumberingIsUnique(t *testing.T) {
	headerRe := regexp.MustCompile(`^#\s*ADR-(\d+)\b`)
	claimedBy := map[string][]string{}

	for _, dir := range []string{"docs/adr", "docs/support/rfc"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".md" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("opening %s: %v", path, err)
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				if m := headerRe.FindStringSubmatch(scanner.Text()); m != nil {
					claimedBy[m[1]] = append(claimedBy[m[1]], path)
					break
				}
			}
			closeErr := f.Close()
			if err := scanner.Err(); err != nil {
				t.Fatalf("scanning %s: %v", path, err)
			}
			if closeErr != nil {
				t.Fatalf("closing %s: %v", path, closeErr)
			}
		}
	}

	numbers := make([]string, 0, len(claimedBy))
	for num := range claimedBy {
		numbers = append(numbers, num)
	}
	sort.Strings(numbers)

	for _, num := range numbers {
		files := claimedBy[num]
		if len(files) > 1 {
			t.Errorf("ADR-%s is claimed by %d files, want exactly 1: %v", num, len(files), files)
		}
	}
}
