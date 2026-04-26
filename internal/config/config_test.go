// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoad_Valid(t *testing.T) {
	t.Parallel()

	const yml = `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO:
              value: bar
            BAZ:
              file: ../baz.txt
            QUX:
              env: QUX_VAR
          secrets:
            S1:
              value: shh
            S2:
              env: S2_VAR
          dependabot:
            D1:
              value: dep
            D2:
              env: D2_VAR
        ignored:
          vars:
            - SKIP_VAR
          secrets:
            - SKIP_SECRET
          dependabot:
            - SKIP_DEP
other.tool:
  ignored: true
`
	cfg, err := LoadBytes([]byte(yml), "/some/dir/secrets.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	org, ok := cfg.Org("example")
	if !ok {
		t.Fatalf("org example missing")
	}
	repo, ok := org.PerRepo["acme"]
	if !ok {
		t.Fatalf("repo acme missing")
	}
	if got := repo.Managed.Vars["FOO"].Value; got != "bar" {
		t.Errorf("FOO value: got %q want %q", got, "bar")
	}
	if got := repo.Managed.Vars["BAZ"].File; got != "../baz.txt" {
		t.Errorf("BAZ file: got %q", got)
	}
	if got := repo.Managed.Vars["BAZ"].FileAbs; got != filepath.Clean("/some/baz.txt") {
		t.Errorf("BAZ resolved file: got %q", got)
	}
	if !contains(repo.Ignored.Vars, "SKIP_VAR") {
		t.Errorf("ignored vars missing SKIP_VAR: %v", repo.Ignored.Vars)
	}
	if !contains(repo.Ignored.Secrets, "SKIP_SECRET") {
		t.Errorf("ignored secrets missing SKIP_SECRET")
	}
	if !contains(repo.Ignored.Dependabot, "SKIP_DEP") {
		t.Errorf("ignored dependabot missing SKIP_DEP")
	}
	if got := repo.Managed.Vars["QUX"].Env; got != "QUX_VAR" {
		t.Errorf("QUX env: got %q want %q", got, "QUX_VAR")
	}
	if repo.Managed.Vars["QUX"].HasValue {
		t.Errorf("QUX should not have an explicit value")
	}
	if got := repo.Managed.Secrets["S2"].Env; got != "S2_VAR" {
		t.Errorf("S2 env: got %q", got)
	}
	if got := repo.Managed.Dependabot["D2"].Env; got != "D2_VAR" {
		t.Errorf("D2 env: got %q", got)
	}
	if got := repo.Managed.Vars["QUX"].Name; got != "QUX" {
		t.Errorf("QUX name: got %q want %q", got, "QUX")
	}
}

func TestLoad_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		yml       string
		errSubstr string
	}{
		{
			name: "multi source value+file",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO:
              value: bar
              file: x
`,
			errSubstr: "exactly one of",
		},
		{
			name: "multi source value+env",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          secrets:
            FOO:
              value: bar
              env: BAR_VAR
`,
			errSubstr: "exactly one of",
		},
		{
			name: "multi source env+file",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          secrets:
            FOO:
              env: BAR_VAR
              file: x
`,
			errSubstr: "exactly one of",
		},
		{
			name: "no source",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO: {}
`,
			errSubstr: "exactly one of",
		},
		{
			name: "scalar shorthand",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO: bar
`,
			errSubstr: "object form",
		},
		{
			name: "unknown key in managed",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO:
              value: bar
              bogus: 1
`,
			errSubstr: "unknown",
		},
		{
			name: "unknown key in scope",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO:
              value: bar
        bogus: {}
`,
			errSubstr: "unknown",
		},
		{
			name:      "not a mapping at top",
			yml:       `42`,
			errSubstr: "must be a mapping",
		},
		{
			name: "github.com not a mapping",
			yml: `
github.com: 42
`,
			errSubstr: "github.com",
		},
		{
			name: "wrong type for ignored list",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        ignored:
          vars: not-a-list
`,
			errSubstr: "list of strings",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadBytes([]byte(tc.yml), "/cfg/secrets.yml")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

func TestLoad_NoSection(t *testing.T) {
	t.Parallel()
	cfg, err := LoadBytes([]byte("other:\n  k: v\n"), "/c/x.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.Org("example"); ok {
		t.Fatalf("expected no orgs")
	}
}

func TestLoadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yml")
	if err := writeFile(path, []byte("github.com:\n  example:\n    per-repo: {}\n")); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned %v", err)
	}
	if _, ok := cfg.Org("example"); !ok {
		t.Fatalf("expected example org")
	}
}

func TestLoadFile_Missing(t *testing.T) {
	t.Parallel()
	_, err := Load(filepath.Join(t.TempDir(), "no-such.yml"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func contains(ss []string, s string) bool {
	return slices.Contains(ss, s)
}
