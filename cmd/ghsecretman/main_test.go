// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gh "github.com/schmidtw/ghsecretman/internal/github"
)

func swapBuildVars(t *testing.T, c, d string) {
	t.Helper()
	prevC, prevD := commit, date
	commit, date = c, d
	t.Cleanup(func() { commit, date = prevC, prevD })
}

func TestRun_VersionSubcommand(t *testing.T) {
	swapBuildVars(t, "abcdef1", "2026-04-26T00:00:00Z")
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "version"}, "1.2.3", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
	}
	want := "ghsecretman 1.2.3\ncommit abcdef1\nbuilt 2026-04-26T00:00:00Z\n"
	if got := stdout.String(); got != want {
		t.Fatalf("stdout: got %q, want %q", got, want)
	}
}

func TestRun_VersionSubcommand_Defaults(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "version"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"ghsecretman dev", "commit ", "built "} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q: %q", want, out)
		}
	}
}

func TestRun_Version(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		version string
		want    string
		code    int
	}{
		{
			name:    "long flag with default version",
			args:    []string{"ghsecretman", "--version"},
			version: "dev",
			want:    "ghsecretman dev\n",
			code:    0,
		},
		{
			name:    "long flag with injected version",
			args:    []string{"ghsecretman", "--version"},
			version: "1.2.3",
			want:    "ghsecretman 1.2.3\n",
			code:    0,
		},
		{
			name:    "short flag",
			args:    []string{"ghsecretman", "-version"},
			version: "dev",
			want:    "ghsecretman dev\n",
			code:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, tc.version, &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit code: got %d, want %d (stderr=%q)", code, tc.code, stderr.String())
			}
			if got := stdout.String(); got != tc.want {
				t.Fatalf("stdout: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRun_NoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman"}, "dev", &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit when no command given")
	}
	if !strings.Contains(stderr.String(), "usage") {
		t.Fatalf("stderr should contain usage hint: %q", stderr.String())
	}
}

type fakeBackend struct {
	orgRepos []string

	vars       map[string]string
	secrets    []string
	dependabot []string

	mu            sync.Mutex
	setVars       []string
	setSecrets    []string
	setDependabot []string

	delVars       []string
	delSecrets    []string
	delDependabot []string

	orgVars       map[string]string
	orgSecrets    []string
	orgDependabot []string

	setOrgVars       []string
	setOrgSecrets    []string
	setOrgDependabot []string

	delOrgVars       []string
	delOrgSecrets    []string
	delOrgDependabot []string

	repoIDs map[string]int64
}

func (f *fakeBackend) ListOrgRepos(_ context.Context, _ string) ([]string, error) {
	return f.orgRepos, nil
}

func (f *fakeBackend) ListRepoVariables(_ context.Context, _, _ string) (map[string]string, error) {
	return f.vars, nil
}
func (f *fakeBackend) ListRepoSecrets(_ context.Context, _, _ string) ([]string, error) {
	return f.secrets, nil
}
func (f *fakeBackend) ListRepoDependabotSecrets(_ context.Context, _, _ string) ([]string, error) {
	return f.dependabot, nil
}

func (f *fakeBackend) GetRepoPublicKey(_ context.Context, _, _ string) (*gh.PublicKey, error) {
	return &gh.PublicKey{KeyID: "kid", Key: "AAAA"}, nil
}

func (f *fakeBackend) GetRepoDependabotPublicKey(_ context.Context, _, _ string) (*gh.PublicKey, error) {
	return &gh.PublicKey{KeyID: "kid-dep", Key: "BBBB"}, nil
}

func (f *fakeBackend) SetRepoVariable(_ context.Context, _, _, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setVars = append(f.setVars, name)
	return nil
}

func (f *fakeBackend) SetRepoSecret(_ context.Context, _, _, name string, _ *gh.PublicKey, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setSecrets = append(f.setSecrets, name)
	return nil
}

func (f *fakeBackend) SetRepoDependabotSecret(_ context.Context, _, _, name string, _ *gh.PublicKey, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setDependabot = append(f.setDependabot, name)
	return nil
}

func (f *fakeBackend) DeleteRepoVariable(_ context.Context, _, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delVars = append(f.delVars, name)
	return nil
}

func (f *fakeBackend) DeleteRepoSecret(_ context.Context, _, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delSecrets = append(f.delSecrets, name)
	return nil
}

func (f *fakeBackend) DeleteRepoDependabotSecret(_ context.Context, _, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delDependabot = append(f.delDependabot, name)
	return nil
}

func (f *fakeBackend) ListOrgVariables(_ context.Context, _ string) (map[string]string, error) {
	return f.orgVars, nil
}
func (f *fakeBackend) ListOrgSecrets(_ context.Context, _ string) ([]string, error) {
	return f.orgSecrets, nil
}
func (f *fakeBackend) ListOrgDependabotSecrets(_ context.Context, _ string) ([]string, error) {
	return f.orgDependabot, nil
}
func (f *fakeBackend) GetOrgPublicKey(_ context.Context, _ string) (*gh.PublicKey, error) {
	return &gh.PublicKey{KeyID: "org-actions-kid", Key: "AAAA"}, nil
}
func (f *fakeBackend) GetOrgDependabotPublicKey(_ context.Context, _ string) (*gh.PublicKey, error) {
	return &gh.PublicKey{KeyID: "org-dep-kid", Key: "BBBB"}, nil
}
func (f *fakeBackend) SetOrgVariable(_ context.Context, _, name, _, _ string, _ []int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setOrgVars = append(f.setOrgVars, name)
	return nil
}
func (f *fakeBackend) SetOrgSecret(_ context.Context, _, name string, _ *gh.PublicKey, _, _ string, _ []int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setOrgSecrets = append(f.setOrgSecrets, name)
	return nil
}
func (f *fakeBackend) SetOrgDependabotSecret(_ context.Context, _, name string, _ *gh.PublicKey, _, _ string, _ []int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setOrgDependabot = append(f.setOrgDependabot, name)
	return nil
}
func (f *fakeBackend) DeleteOrgVariable(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delOrgVars = append(f.delOrgVars, name)
	return nil
}
func (f *fakeBackend) DeleteOrgSecret(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delOrgSecrets = append(f.delOrgSecrets, name)
	return nil
}
func (f *fakeBackend) DeleteOrgDependabotSecret(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delOrgDependabot = append(f.delOrgDependabot, name)
	return nil
}
func (f *fakeBackend) GetRepoID(_ context.Context, _, repo string) (int64, error) {
	if id, ok := f.repoIDs[repo]; ok {
		return id, nil
	}
	return 0, nil
}

func writeCfg(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "secrets.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func swapBackend(t *testing.T, be gh.Backend, beErr error) {
	t.Helper()
	prev := backendFactory
	backendFactory = func() (gh.Backend, error) {
		if beErr != nil {
			return nil, beErr
		}
		return be, nil
	}
	t.Cleanup(func() { backendFactory = prev })
}

func TestRun_AuditClean(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)
	swapBackend(t, &fakeBackend{vars: map[string]string{"V": "ok"}}, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "repo: acme") {
		t.Fatalf("stdout missing stanza header: %q", stdout.String())
	}
}

func TestRun_AuditDriftReturnsOne(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: yaml
`)
	swapBackend(t, &fakeBackend{vars: map[string]string{"V": "live"}}, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit: got %d want 1", code)
	}
}

func TestRun_AuditMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
	if !strings.Contains(stderr.String(), "required") {
		t.Fatalf("stderr should mention required: %q", stderr.String())
	}
}

func TestRun_AuditBadConfig(t *testing.T) {
	swapBackend(t, &fakeBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", "/no/such/file.yml", "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_AuditBackendError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)
	swapBackend(t, nil, errors.New("no token"))
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_AuditUnknownRepo(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo: {}
`)
	swapBackend(t, &fakeBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example", "--repo", "nope"}, "dev", &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit: got %d want 1", code)
	}
}

func TestRun_AuditBadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--bogus"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_ApplySuccess(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
          secrets:
            S:
              value: secret
          dependabot:
            D:
              value: dep
`)
	be := &fakeBackend{}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", cfgPath, "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if len(be.setVars) != 1 || be.setVars[0] != "V" {
		t.Errorf("setVars: %v", be.setVars)
	}
	if len(be.setSecrets) != 1 || be.setSecrets[0] != "S" {
		t.Errorf("setSecrets: %v", be.setSecrets)
	}
	if len(be.setDependabot) != 1 || be.setDependabot[0] != "D" {
		t.Errorf("setDependabot: %v", be.setDependabot)
	}
	if !strings.Contains(stdout.String(), "vars/V: ok") {
		t.Errorf("stdout missing per-entry ok line: %q", stdout.String())
	}
}

func TestRun_ApplyMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
	if !strings.Contains(stderr.String(), "required") {
		t.Fatalf("stderr should mention required: %q", stderr.String())
	}
}

func TestRun_ApplyBadConfig(t *testing.T) {
	swapBackend(t, &fakeBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", "/no/such/file.yml", "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_ApplyBackendError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)
	swapBackend(t, nil, errors.New("no token"))
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", cfgPath, "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_ApplyBadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--bogus"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_ApplyUnknownRepo(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo: {}
`)
	swapBackend(t, &fakeBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", cfgPath, "--org", "example", "--repo", "nope"}, "dev", &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit: got %d want 1", code)
	}
}

func TestRun_EnforceDryRun_NoWrites(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)
	be := &fakeBackend{vars: map[string]string{"V_EXTRA": "x"}}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme", "--dry-run"},
		"dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
	}
	if len(be.setVars)+len(be.delVars) != 0 {
		t.Errorf("dry-run made writes: setVars=%v delVars=%v", be.setVars, be.delVars)
	}
	if !strings.Contains(stdout.String(), "would-delete") {
		t.Errorf("expected would-delete in dry-run output: %q", stdout.String())
	}
}

func TestRun_Enforce_DeletesExtras(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)
	be := &fakeBackend{vars: map[string]string{"V_EXTRA": "x"}}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme"},
		"dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if len(be.delVars) != 1 || be.delVars[0] != "V_EXTRA" {
		t.Errorf("expected V_EXTRA deleted; got %v", be.delVars)
	}
	if len(be.setVars) != 1 || be.setVars[0] != "V" {
		t.Errorf("expected V set; got %v", be.setVars)
	}
}

func TestRun_EnforceMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
	if !strings.Contains(stderr.String(), "required") {
		t.Fatalf("stderr should mention required: %q", stderr.String())
	}
}

func TestRun_EnforceBadConfig(t *testing.T) {
	swapBackend(t, &fakeBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", "/no/such/file.yml", "--org", "example", "--repo", "acme"},
		"dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_EnforceBackendError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)
	swapBackend(t, nil, errors.New("no token"))
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme"},
		"dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_EnforceBadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--bogus"}, "dev", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit: got %d want 2", code)
	}
}

func TestRun_EnforceUnknownRepo(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo: {}
`)
	swapBackend(t, &fakeBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "nope"},
		"dev", &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit: got %d want 1", code)
	}
}

func TestRun_AuditOrgWide_NoRepoFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)
	be := &fakeBackend{
		orgRepos: []string{"a", "b"},
		vars:     map[string]string{"V": "ok"},
	}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q\nstdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"repo: a", "repo: b", "summary: ok=2"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout missing %q\n--\n%s", want, stdout.String())
		}
	}
}

func TestRun_ApplyOrgWide_NoRepoFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)
	be := &fakeBackend{orgRepos: []string{"a", "b"}}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", cfgPath, "--org", "example"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q\nstdout=%q", code, stderr.String(), stdout.String())
	}
	if len(be.setVars) != 2 {
		t.Errorf("expected V set on each of 2 repos; got %v", be.setVars)
	}
}

func TestRun_EnforceOrgWide_DryRun_NoRepoFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)
	be := &fakeBackend{orgRepos: []string{"a", "b"}, vars: map[string]string{"EXTRA": "x"}}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--dry-run"},
		"dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
	}
	if len(be.setVars)+len(be.delVars) != 0 {
		t.Errorf("dry-run made writes")
	}
	for _, want := range []string{"would-set", "would-delete", "summary: ok=2"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout missing %q\n--\n%s", want, stdout.String())
		}
	}
}

func TestRun_AuditOrgWide_DriftReturnsOne(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: yaml
`)
	be := &fakeBackend{orgRepos: []string{"a"}, vars: map[string]string{"V": "live"}}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example"}, "dev", &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit: got %d want 1", code)
	}
}

type failVarBackend struct {
	fakeBackend
}

func (f *failVarBackend) SetRepoVariable(_ context.Context, _, _, _, _ string) error {
	return errors.New("rate limit")
}

func TestRun_ApplyEntryFailureReturnsOne(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)
	swapBackend(t, &failVarBackend{}, nil)
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", cfgPath, "--org", "example", "--repo", "acme"}, "dev", &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit: got %d want 1; stdout=%q", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "vars/V: FAILED") {
		t.Errorf("stdout missing FAILED line: %q", stdout.String())
	}
}

func TestRun_AuditOrgWide_IncludesOrgScope(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    org:
      managed:
        vars:
          ORG_VAR:
            value: x
    per-repo:
      acme:
        managed:
          vars:
            REPO_VAR:
              value: y
`)
	be := &fakeBackend{
		orgRepos: []string{"acme"},
		vars:     map[string]string{"REPO_VAR": "y"},
		orgVars:  map[string]string{"ORG_VAR": "x"},
	}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "audit", "--config", cfgPath, "--org", "example"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q\nstdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"scope: org", "repo: acme", "summary: ok=1"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout missing %q\n--\n%s", want, stdout.String())
		}
	}
}

func TestRun_ApplyOrgWide_WritesOrgScope_Selected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    org:
      managed:
        vars:
          ORG_VAR:
            value: x
            scope: selected
            repos:
              - acme
    per-repo:
      acme:
        managed:
          vars:
            REPO_VAR:
              value: y
`)
	be := &fakeBackend{
		orgRepos: []string{"acme"},
		repoIDs:  map[string]int64{"acme": 42},
	}
	swapBackend(t, be, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "apply", "--config", cfgPath, "--org", "example"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q\nstdout=%q", code, stderr.String(), stdout.String())
	}
	if len(be.setOrgVars) != 1 || be.setOrgVars[0] != "ORG_VAR" {
		t.Errorf("expected one ORG_VAR set; got %v", be.setOrgVars)
	}
	if len(be.setVars) != 1 {
		t.Errorf("expected one repo var set; got %v", be.setVars)
	}
}

func TestRun_Help_PrintsCommandList(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{"ghsecretman", arg}, "dev", &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, "commands:") {
				t.Fatalf("stdout missing commands section: %q", out)
			}
			for _, sub := range []string{"audit", "apply", "enforce", "example", "version"} {
				if !strings.Contains(out, sub) {
					t.Errorf("stdout missing subcommand %q", sub)
				}
			}
		})
	}
}

func TestRun_Example_Stdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "example"}, "dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
	}
	for _, marker := range []string{"github.com:", "managed:", "ignored:", "per-repo:", "all-repos:"} {
		if !strings.Contains(stdout.String(), marker) {
			t.Errorf("stdout missing schema marker %q", marker)
		}
	}
}

func TestRun_Example_OutputFile(t *testing.T) {
	for _, flag := range []string{"-o", "--output"} {
		t.Run(flag, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			var stdout, stderr bytes.Buffer
			code := run([]string{"ghsecretman", "example", flag, path}, "dev", &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "github.com:") {
				t.Fatalf("file missing expected content: %q", data)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout should be empty when writing to file: %q", stdout.String())
			}
		})
	}
}

func TestRun_Example_RefuseOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "example", "-o", path}, "dev", &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit when refusing to overwrite")
	}
	if !strings.Contains(stderr.String(), "exists") {
		t.Errorf("stderr should explain the refusal: %q", stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatalf("file should not have been modified: %q", data)
	}
}

func TestRun_Example_ForceOverwrite(t *testing.T) {
	for _, flag := range []string{"-f", "--force"} {
		t.Run(flag, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{"ghsecretman", "example", "-o", path, flag}, "dev", &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit: got %d want 0; stderr=%q", code, stderr.String())
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "github.com:") {
				t.Fatalf("file not overwritten with example: %q", data)
			}
		})
	}
}
