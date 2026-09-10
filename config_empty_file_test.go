package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Nightly QA (edge case): an empty or comment-only config.yaml must NOT
// crash the boot.
//
// docker-compose.yml documents "-config.yaml" as an optional bind mount
// ("Uncomment to use a custom config file"), and config.yaml itself ships
// with every field commented out as a starting template
// (docs/operator + repo root config.yaml.example-shaped files). An operator
// who reserves the path with `touch config.yaml` before filling it in, or
// who copies the shipped template and leaves every line commented out,
// produces a YAML document that decodes to nothing at all.
//
// goccy/go-yaml's Decoder.Decode reports that as io.EOF, and loadFileConfig
// (config.go) treated every decode error — io.EOF included — as fatal:
// `main()` calls log.Fatalf("Cannot load config file: %v", err) and the
// proxy never starts. An empty document is not malformed YAML; it is the
// same as "no overrides", exactly like omitting -config entirely, and must
// resolve to the same all-defaults FileConfig rather than refusing to boot.
func TestLoadFileConfig_EmptyFileDoesNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty config: %v", err)
	}

	fc, err := loadFileConfig(path)
	if err != nil {
		t.Fatalf("loadFileConfig(empty file) = %v, want nil error (an empty config.yaml must behave like no config.yaml)", err)
	}
	if fc == nil {
		t.Fatalf("loadFileConfig(empty file) returned a nil *FileConfig with a nil error")
	}
	if fc.Proxy.Port != 0 || fc.Proxy.UIPort != 0 {
		t.Fatalf("loadFileConfig(empty file) = %+v, want all-zero defaults", fc)
	}
}

// Same defect, reached through the shape an operator actually produces:
// copying the shipped template and leaving every setting commented out.
func TestLoadFileConfig_CommentOnlyFileDoesNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "# proxy:\n#   port: 8080\n# auth:\n#   user: admin\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write comment-only config: %v", err)
	}

	fc, err := loadFileConfig(path)
	if err != nil {
		t.Fatalf("loadFileConfig(comment-only file) = %v, want nil error", err)
	}
	if fc == nil {
		t.Fatalf("loadFileConfig(comment-only file) returned a nil *FileConfig with a nil error")
	}
}

// Whitespace-only is the same document shape a text editor's "save" can
// leave behind (e.g. a template with all content deleted but a trailing
// blank line kept).
func TestLoadFileConfig_WhitespaceOnlyFileDoesNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("   \n\n\t\n"), 0o600); err != nil {
		t.Fatalf("write whitespace-only config: %v", err)
	}

	if _, err := loadFileConfig(path); err != nil {
		t.Fatalf("loadFileConfig(whitespace-only file) = %v, want nil error", err)
	}
}

// A genuinely malformed document must still fail loudly — the fix must not
// widen into "swallow all decode errors".
func TestLoadFileConfig_MalformedYAMLStillErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Unterminated flow mapping — a real syntax error, not an empty document.
	if err := os.WriteFile(path, []byte("proxy: [1, 2\n"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	if _, err := loadFileConfig(path); err == nil {
		t.Fatalf("loadFileConfig(malformed YAML) = nil error, want a parse error")
	}
}

// An unknown top-level field must still fail loudly too (DisallowUnknownField
// stays enforced) — the fix targets ONLY the empty-document shape.
func TestLoadFileConfig_UnknownFieldStillErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("not_a_real_field: true\n"), 0o600); err != nil {
		t.Fatalf("write config with unknown field: %v", err)
	}

	if _, err := loadFileConfig(path); err == nil {
		t.Fatalf("loadFileConfig(unknown field) = nil error, want an unknown-field error")
	}
}
