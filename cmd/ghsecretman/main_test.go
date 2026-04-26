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
	"testing"

	gh "github.com/schmidtw/ghsecretman/internal/github"
)

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

	setVars       []string
	setSecrets    []string
	setDependabot []string

	delVars       []string
	delSecrets    []string
	delDependabot []string
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
	f.setVars = append(f.setVars, name)
	return nil
}

func (f *fakeBackend) SetRepoSecret(_ context.Context, _, _, name string, _ *gh.PublicKey, _ string) error {
	f.setSecrets = append(f.setSecrets, name)
	return nil
}

func (f *fakeBackend) SetRepoDependabotSecret(_ context.Context, _, _, name string, _ *gh.PublicKey, _ string) error {
	f.setDependabot = append(f.setDependabot, name)
	return nil
}

func (f *fakeBackend) DeleteRepoVariable(_ context.Context, _, _, name string) error {
	f.delVars = append(f.delVars, name)
	return nil
}

func (f *fakeBackend) DeleteRepoSecret(_ context.Context, _, _, name string) error {
	f.delSecrets = append(f.delSecrets, name)
	return nil
}

func (f *fakeBackend) DeleteRepoDependabotSecret(_ context.Context, _, _, name string) error {
	f.delDependabot = append(f.delDependabot, name)
	return nil
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

func swapTTY(t *testing.T, val bool) {
	t.Helper()
	prev := isTTY
	isTTY = func() bool { return val }
	t.Cleanup(func() { isTTY = prev })
}

func swapStdin(t *testing.T, input string) {
	t.Helper()
	prev := stdin
	stdin = strings.NewReader(input)
	t.Cleanup(func() { stdin = prev })
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

func TestRun_EnforceWithYes_DeletesExtras(t *testing.T) {
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
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme", "--yes"},
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

func TestRun_EnforceWithoutYes_NonTTY_Refuses(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)
	be := &fakeBackend{}
	swapBackend(t, be, nil)
	swapTTY(t, false)

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme"},
		"dev", &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit when no --yes and stdin is non-TTY")
	}
	if !strings.Contains(stderr.String(), "--yes") {
		t.Errorf("stderr should mention --yes requirement: %q", stderr.String())
	}
	if len(be.delVars)+len(be.setVars) != 0 {
		t.Errorf("no writes should have happened: setVars=%v delVars=%v", be.setVars, be.delVars)
	}
}

func TestRun_EnforceTTYPromptYes_Proceeds(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)
	be := &fakeBackend{vars: map[string]string{"V_EXTRA": "x"}}
	swapBackend(t, be, nil)
	swapTTY(t, true)
	swapStdin(t, "y\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme"},
		"dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if len(be.delVars) != 1 || be.delVars[0] != "V_EXTRA" {
		t.Errorf("expected V_EXTRA deleted; got %v", be.delVars)
	}
	if !strings.Contains(stdout.String(), "V_EXTRA") {
		t.Errorf("expected prompt to mention V_EXTRA: %q", stdout.String())
	}
}

func TestRun_EnforceTTYPromptNo_AbortsWithoutWrites(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCfg(t, dir, `
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)
	be := &fakeBackend{vars: map[string]string{"V_EXTRA": "x"}}
	swapBackend(t, be, nil)
	swapTTY(t, true)
	swapStdin(t, "n\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme"},
		"dev", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit: got %d want 0", code)
	}
	if len(be.delVars)+len(be.setVars) != 0 {
		t.Errorf("declining at the prompt must skip all writes: setVars=%v delVars=%v",
			be.setVars, be.delVars)
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
	code := run([]string{"ghsecretman", "enforce", "--config", "/no/such/file.yml", "--org", "example", "--repo", "acme", "--yes"},
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
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "acme", "--yes"},
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
	code := run([]string{"ghsecretman", "enforce", "--config", cfgPath, "--org", "example", "--repo", "nope", "--yes"},
		"dev", &stdout, &stderr)
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
