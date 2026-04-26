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
		{
			name: "managed and ignored conflict: vars",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            DUP:
              value: x
        ignored:
          vars:
            - DUP
`,
			errSubstr: "DUP",
		},
		{
			name: "managed and ignored conflict: secrets",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          secrets:
            DUP:
              value: x
        ignored:
          secrets:
            - DUP
`,
			errSubstr: "DUP",
		},
		{
			name: "managed and ignored conflict: dependabot",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          dependabot:
            DUP:
              value: x
        ignored:
          dependabot:
            - DUP
`,
			errSubstr: "DUP",
		},
		{
			name: "unknown key in ignored",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        ignored:
          bogus:
            - X
`,
			errSubstr: "unknown",
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

func TestLoad_AllRepos(t *testing.T) {
	t.Parallel()

	const yml = `
github.com:
  example:
    all-repos:
      managed:
        vars:
          ALL_VAR:
            value: shared
        secrets:
          ALL_SEC:
            value: s
        dependabot:
          ALL_DEP:
            value: d
      ignored:
        vars:
          - ALL_IG_VAR
        secrets:
          - ALL_IG_SEC
        dependabot:
          - ALL_IG_DEP
    per-repo:
      acme:
        managed:
          vars:
            REPO_VAR:
              value: r
`
	cfg, err := LoadBytes([]byte(yml), "/c/secrets.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	org, ok := cfg.Org("example")
	if !ok {
		t.Fatalf("org example missing")
	}
	if org.AllRepos == nil {
		t.Fatalf("AllRepos missing")
	}
	if org.AllRepos.Managed.Vars["ALL_VAR"].Value != "shared" {
		t.Errorf("ALL_VAR value: %+v", org.AllRepos.Managed.Vars["ALL_VAR"])
	}
	if !contains(org.AllRepos.Ignored.Vars, "ALL_IG_VAR") {
		t.Errorf("ALL_IG_VAR not in ignored: %v", org.AllRepos.Ignored.Vars)
	}
	if org.PerRepo["acme"].Managed.Vars["REPO_VAR"].Value != "r" {
		t.Errorf("REPO_VAR not parsed")
	}
}

func TestLoad_AllReposManagedIgnoredConflict(t *testing.T) {
	t.Parallel()
	const yml = `
github.com:
  example:
    all-repos:
      managed:
        vars:
          DUP:
            value: x
      ignored:
        vars:
          - DUP
`
	if _, err := LoadBytes([]byte(yml), "/c/secrets.yml"); err == nil {
		t.Fatal("expected conflict error")
	} else if !strings.Contains(err.Error(), "DUP") {
		t.Errorf("error should mention DUP: %v", err)
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

func TestLoad_OrgScope_Valid(t *testing.T) {
	t.Parallel()

	const yml = `
github.com:
  example:
    org:
      managed:
        vars:
          ORG_VAR_ALL:
            value: v
          ORG_VAR_SEL:
            value: w
            scope: selected
            repos:
              - r1
              - r2
        secrets:
          ORG_SEC:
            value: s
            scope: private
        dependabot:
          ORG_DEP:
            env: ORG_DEP_VAR
      ignored:
        vars:
          - IGNORED_ORG_VAR
        secrets:
          - IGNORED_ORG_SEC
        dependabot:
          - IGNORED_ORG_DEP
`
	cfg, err := LoadBytes([]byte(yml), "/c/secrets.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	org, ok := cfg.Org("example")
	if !ok {
		t.Fatalf("org example missing")
	}
	if org.OrgScope == nil {
		t.Fatalf("OrgScope missing")
	}
	if got := org.OrgScope.Managed.Vars["ORG_VAR_ALL"]; got == nil {
		t.Fatalf("ORG_VAR_ALL missing")
	} else {
		if got.Visibility != "all" {
			t.Errorf("ORG_VAR_ALL visibility default: got %q want all", got.Visibility)
		}
		if got.Entry.Value != "v" {
			t.Errorf("ORG_VAR_ALL value: got %q", got.Entry.Value)
		}
	}
	sel := org.OrgScope.Managed.Vars["ORG_VAR_SEL"]
	if sel == nil {
		t.Fatalf("ORG_VAR_SEL missing")
	}
	if sel.Visibility != "selected" {
		t.Errorf("ORG_VAR_SEL visibility: got %q", sel.Visibility)
	}
	if !equalStrings(sel.Repos, []string{"r1", "r2"}) {
		t.Errorf("ORG_VAR_SEL repos: got %v", sel.Repos)
	}
	if v := org.OrgScope.Managed.Secrets["ORG_SEC"].Visibility; v != "private" {
		t.Errorf("ORG_SEC visibility: got %q", v)
	}
	if v := org.OrgScope.Managed.Dependabot["ORG_DEP"].Entry.Env; v != "ORG_DEP_VAR" {
		t.Errorf("ORG_DEP env: got %q", v)
	}
	if !contains(org.OrgScope.Ignored.Vars, "IGNORED_ORG_VAR") {
		t.Errorf("ignored vars missing IGNORED_ORG_VAR: %v", org.OrgScope.Ignored.Vars)
	}
	if !contains(org.OrgScope.Ignored.Secrets, "IGNORED_ORG_SEC") {
		t.Errorf("ignored secrets missing IGNORED_ORG_SEC")
	}
	if !contains(org.OrgScope.Ignored.Dependabot, "IGNORED_ORG_DEP") {
		t.Errorf("ignored dependabot missing IGNORED_ORG_DEP")
	}
}

func TestLoad_OrgScope_Invalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		yml       string
		errSubstr string
	}{
		{
			name: "selected without repos",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V:
            value: x
            scope: selected
`,
			errSubstr: "selected",
		},
		{
			name: "selected with empty repos",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V:
            value: x
            scope: selected
            repos: []
`,
			errSubstr: "selected",
		},
		{
			name: "repos without selected",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V:
            value: x
            scope: all
            repos:
              - r1
`,
			errSubstr: "repos",
		},
		{
			name: "repos at default scope",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V:
            value: x
            repos:
              - r1
`,
			errSubstr: "repos",
		},
		{
			name: "invalid scope value",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V:
            value: x
            scope: bogus
`,
			errSubstr: "scope",
		},
		{
			name: "unknown key in org entry",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V:
            value: x
            bogus: 1
`,
			errSubstr: "unknown",
		},
		{
			name: "unknown key in org block",
			yml: `
github.com:
  example:
    org:
      bogus: {}
`,
			errSubstr: "unknown",
		},
		{
			name: "scope on per-repo entry rejected",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: x
              scope: all
`,
			errSubstr: "unknown",
		},
		{
			name: "managed/ignored conflict in org",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          DUP:
            value: x
      ignored:
        vars:
          - DUP
`,
			errSubstr: "DUP",
		},
		{
			name: "scalar shorthand in org",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          V: bar
`,
			errSubstr: "object form",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadBytes([]byte(tc.yml), "/c/secrets.yml")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

func TestLoad_SiblingTopLevelKeysIgnored(t *testing.T) {
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

gitlab.com:
  groups:
    - name: platform
      projects:
        - foo
        - bar
  variables:
    DUMMY: not-an-object
    OTHER: 42

safe-settings:
  organization:
    repositories:
      - foo
      - bar
    teams:
      - admins
  branch_protection:
    enforce_admins: true

random-tool: hello
another:
  - 1
  - 2
  - 3
`
	cfg, err := LoadBytes([]byte(yml), "/c/secrets.yml")
	if err != nil {
		t.Fatalf("unexpected error loading mixed-namespace YAML: %v", err)
	}
	org, ok := cfg.Org("example")
	if !ok {
		t.Fatalf("github.com.example was not parsed")
	}
	repo := org.PerRepo["acme"]
	if repo == nil {
		t.Fatalf("github.com.example.per-repo.acme missing")
	}
	if got := repo.Managed.Vars["FOO"].Value; got != "bar" {
		t.Errorf("FOO value: got %q want %q", got, "bar")
	}
	if _, ok := cfg.Org("gitlab.com"); ok {
		t.Errorf("gitlab.com leaked into orgs map")
	}
	if _, ok := cfg.Org("safe-settings"); ok {
		t.Errorf("safe-settings leaked into orgs map")
	}
	if _, ok := cfg.Org("random-tool"); ok {
		t.Errorf("random-tool leaked into orgs map")
	}
	if _, ok := cfg.Org("another"); ok {
		t.Errorf("another leaked into orgs map")
	}
	if got := len(cfg.Orgs); got != 1 {
		t.Errorf("orgs count: got %d want 1; orgs=%v", got, cfg.Orgs)
	}
}

func TestLoad_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		yml      string
		mustHave []string
	}{
		{
			name: "unknown key under per-repo entry",
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
			mustHave: []string{"managed.vars.FOO", "bogus"},
		},
		{
			name: "unknown key under per-repo managed",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          oddball:
            X:
              value: y
`,
			mustHave: []string{"managed", "oddball"},
		},
		{
			name: "unknown key under per-repo block",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        whatzit: {}
`,
			mustHave: []string{"acme", "whatzit"},
		},
		{
			name: "unknown key under all-repos entry",
			yml: `
github.com:
  example:
    all-repos:
      managed:
        vars:
          FOO:
            value: bar
            bogus: 1
`,
			mustHave: []string{"managed.vars.FOO", "bogus"},
		},
		{
			name: "unknown key under org scope entry",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          FOO:
            value: bar
            bogus: 1
`,
			mustHave: []string{"org.managed.vars.FOO", "bogus"},
		},
		{
			name: "unknown key under org scope block",
			yml: `
github.com:
  example:
    org:
      bogus: {}
`,
			mustHave: []string{"example", "bogus"},
		},
		{
			name: "unknown key under per-repo ignored",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        ignored:
          bogus:
            - X
`,
			mustHave: []string{"ignored", "bogus"},
		},
		{
			name: "wrong type for ignored.vars list",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        ignored:
          vars: not-a-list
`,
			mustHave: []string{"ignored.vars", "list of strings"},
		},
		{
			name: "wrong type for managed block",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed: not-a-mapping
`,
			mustHave: []string{"managed", "mapping"},
		},
		{
			name: "wrong type for org-scope managed block",
			yml: `
github.com:
  example:
    org:
      managed: 42
`,
			mustHave: []string{"org.managed", "mapping"},
		},
		{
			name: "wrong type for org-entry repos list",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          FOO:
            value: x
            scope: selected
            repos: nope
`,
			mustHave: []string{"repos", "list of strings"},
		},
		{
			name:     "wrong type for top-level document",
			yml:      "42\n",
			mustHave: []string{"top-level", "mapping"},
		},
		{
			name: "wrong type for github.com",
			yml: `
github.com: 42
`,
			mustHave: []string{"github.com", "mapping"},
		},
		{
			name: "wrong type for org node",
			yml: `
github.com:
  example: 42
`,
			mustHave: []string{"example", "mapping"},
		},
		{
			name: "wrong type for per-repo block",
			yml: `
github.com:
  example:
    per-repo: not-a-map
`,
			mustHave: []string{"per-repo", "mapping"},
		},
		{
			name: "scalar shorthand under per-repo entry",
			yml: `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            FOO: bar
`,
			mustHave: []string{"managed.vars.FOO", "object form"},
		},
		{
			name: "scalar shorthand under org-scope entry",
			yml: `
github.com:
  example:
    org:
      managed:
        vars:
          FOO: bar
`,
			mustHave: []string{"org.managed.vars.FOO", "object form"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := LoadBytes([]byte(tc.yml), "/c/secrets.yml")
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			for _, sub := range tc.mustHave {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q does not contain %q", err.Error(), sub)
				}
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
