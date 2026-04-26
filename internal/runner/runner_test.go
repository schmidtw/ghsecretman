// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/schmidtw/ghsecretman/internal/config"
	gh "github.com/schmidtw/ghsecretman/internal/github"
)

type fakeBackend struct {
	orgRepos    []string
	orgReposErr error

	vars       map[string]string
	secrets    []string
	dependabot []string
	err        error

	actionsKey    *gh.PublicKey
	dependabotKey *gh.PublicKey

	actionsKeyErr    error
	dependabotKeyErr error

	mu          sync.Mutex
	setVarCalls []setVarCall
	setSecCalls []setSecretCall
	setDepCalls []setSecretCall

	delVarCalls []string
	delSecCalls []string
	delDepCalls []string

	// keyFetchCount tracks how many times each key fetch endpoint was called.
	actionsKeyFetches    int
	dependabotKeyFetches int

	// setErr injects errors for specific (kind, name) pairs.
	setErr map[string]error
	// delErr injects errors for specific (kind, name) pairs on delete.
	delErr map[string]error
}

type setVarCall struct {
	owner, repo, name, value string
}

type setSecretCall struct {
	owner, repo, name, plaintext string
	keyID                        string
}

func (f *fakeBackend) ListOrgRepos(_ context.Context, _ string) ([]string, error) {
	return f.orgRepos, f.orgReposErr
}

func (f *fakeBackend) ListRepoVariables(_ context.Context, _, _ string) (map[string]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.vars, nil
}
func (f *fakeBackend) ListRepoSecrets(_ context.Context, _, _ string) ([]string, error) {
	return f.secrets, f.err
}
func (f *fakeBackend) ListRepoDependabotSecrets(_ context.Context, _, _ string) ([]string, error) {
	return f.dependabot, f.err
}

func (f *fakeBackend) GetRepoPublicKey(_ context.Context, _, _ string) (*gh.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actionsKeyFetches++
	if f.actionsKeyErr != nil {
		return nil, f.actionsKeyErr
	}
	if f.actionsKey == nil {
		return &gh.PublicKey{KeyID: "key-actions", Key: "AAAA"}, nil
	}
	return f.actionsKey, nil
}

func (f *fakeBackend) GetRepoDependabotPublicKey(_ context.Context, _, _ string) (*gh.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dependabotKeyFetches++
	if f.dependabotKeyErr != nil {
		return nil, f.dependabotKeyErr
	}
	if f.dependabotKey == nil {
		return &gh.PublicKey{KeyID: "key-dep", Key: "BBBB"}, nil
	}
	return f.dependabotKey, nil
}

func (f *fakeBackend) SetRepoVariable(_ context.Context, owner, repo, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.setErr["vars/"+name]; ok {
		return e
	}
	f.setVarCalls = append(f.setVarCalls, setVarCall{owner, repo, name, value})
	return nil
}

func (f *fakeBackend) SetRepoSecret(_ context.Context, owner, repo, name string, key *gh.PublicKey, plaintext string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.setErr["secrets/"+name]; ok {
		return e
	}
	keyID := ""
	if key != nil {
		keyID = key.KeyID
	}
	f.setSecCalls = append(f.setSecCalls, setSecretCall{owner, repo, name, plaintext, keyID})
	return nil
}

func (f *fakeBackend) SetRepoDependabotSecret(_ context.Context, owner, repo, name string, key *gh.PublicKey, plaintext string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.setErr["dependabot/"+name]; ok {
		return e
	}
	keyID := ""
	if key != nil {
		keyID = key.KeyID
	}
	f.setDepCalls = append(f.setDepCalls, setSecretCall{owner, repo, name, plaintext, keyID})
	return nil
}

func (f *fakeBackend) DeleteRepoVariable(_ context.Context, _, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.delErr["vars/"+name]; ok {
		return e
	}
	f.delVarCalls = append(f.delVarCalls, name)
	return nil
}

func (f *fakeBackend) DeleteRepoSecret(_ context.Context, _, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.delErr["secrets/"+name]; ok {
		return e
	}
	f.delSecCalls = append(f.delSecCalls, name)
	return nil
}

func (f *fakeBackend) DeleteRepoDependabotSecret(_ context.Context, _, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.delErr["dependabot/"+name]; ok {
		return e
	}
	f.delDepCalls = append(f.delDepCalls, name)
	return nil
}

func TestAuditRepo_Drift(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_OK:
              value: same
            V_BAD:
              value: yaml-side
            V_GONE:
              value: x
          secrets:
            S_HERE:
              value: x
            S_GONE:
              value: x
          dependabot:
            D_HERE:
              value: x
        ignored:
          vars:
            - IG_VAR
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		vars: map[string]string{
			"V_OK":      "same",
			"V_BAD":     "live-side",
			"EXTRA_VAR": "x",
			"IG_VAR":    "x",
		},
		secrets:    []string{"S_HERE", "EXTRA_SEC"},
		dependabot: []string{"D_HERE"},
	}

	var out bytes.Buffer
	res, err := AuditRepo(context.Background(), cfg, "example", "acme", be, &out, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Drift {
		t.Errorf("expected drift")
	}
	s := out.String()
	for _, want := range []string{
		"repo: acme",
		"V_OK", "match",
		"V_BAD", "mismatch",
		"V_GONE", "missing",
		"EXTRA_VAR", "extra",
		"S_HERE", "present",
		"S_GONE", "missing",
		"EXTRA_SEC", "extra",
		"D_HERE", "present",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n--\n%s", want, s)
		}
	}
	if strings.Contains(s, "IG_VAR") {
		t.Errorf("ignored entry should be silent by default; got:\n%s", s)
	}
}

func TestAuditRepo_NoDrift(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"V": "ok"}}
	var out bytes.Buffer
	res, err := AuditRepo(context.Background(), cfg, "example", "acme", be, &out, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Drift {
		t.Errorf("expected no drift; got output:\n%s", out.String())
	}
}

func TestAuditRepo_FileSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "v.txt"), []byte("from-file")); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              file: v.txt
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"V": "from-file"}}
	var out bytes.Buffer
	res, err := AuditRepo(context.Background(), cfg, "example", "acme", be, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Drift {
		t.Errorf("expected no drift; got:\n%s", out.String())
	}
}

func TestAuditRepo_UnknownOrgRepo(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{}}
	_, err := AuditRepo(context.Background(), cfg, "missing", "acme", &fakeBackend{}, &bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected error for unknown org")
	}

	cfg.Orgs["example"] = &config.Org{PerRepo: map[string]*config.Repo{}}
	_, err = AuditRepo(context.Background(), cfg, "example", "missing-repo", &fakeBackend{}, &bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected error for unknown repo")
	}
}

func TestAuditRepo_BackendError(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Orgs: map[string]*config.Org{
			"example": {PerRepo: map[string]*config.Repo{"acme": {}}},
		},
	}
	be := &fakeBackend{err: errors.New("boom")}
	_, err := AuditRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditRepo_ResolveError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              file: missing.txt
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"V": "x"}}
	_, err = AuditRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestApplyRepo_WritesAllSections(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "f.txt"), []byte("file-val")); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V1:
              value: v-one
            V2:
              file: f.txt
          secrets:
            S1:
              value: s-one
            S2:
              value: s-two
          dependabot:
            D1:
              value: d-one
        ignored:
          vars:
            - IG_VAR
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	var out bytes.Buffer
	res, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 0 {
		t.Errorf("expected zero failures, got %d", res.Failed)
	}

	if got := callNames(be.setVarCalls); !equalSorted(got, []string{"V1", "V2"}) {
		t.Errorf("vars set: got %v want [V1 V2]", got)
	}
	if got := secretCallNames(be.setSecCalls); !equalSorted(got, []string{"S1", "S2"}) {
		t.Errorf("secrets set: got %v want [S1 S2]", got)
	}
	if got := secretCallNames(be.setDepCalls); !equalSorted(got, []string{"D1"}) {
		t.Errorf("dependabot set: got %v want [D1]", got)
	}

	for _, c := range be.setVarCalls {
		switch c.name {
		case "V1":
			if c.value != "v-one" {
				t.Errorf("V1 value: %q", c.value)
			}
		case "V2":
			if c.value != "file-val" {
				t.Errorf("V2 value: %q", c.value)
			}
		}
	}
	for _, c := range be.setSecCalls {
		if c.keyID != "key-actions" {
			t.Errorf("secret %s: keyID=%q", c.name, c.keyID)
		}
	}
	for _, c := range be.setDepCalls {
		if c.keyID != "key-dep" {
			t.Errorf("dependabot %s: keyID=%q", c.name, c.keyID)
		}
	}

	if be.actionsKeyFetches != 1 {
		t.Errorf("actions key fetched %d times; expected exactly 1", be.actionsKeyFetches)
	}
	if be.dependabotKeyFetches != 1 {
		t.Errorf("dependabot key fetched %d times; expected exactly 1", be.dependabotKeyFetches)
	}

	s := out.String()
	for _, want := range []string{"repo: acme", "vars/V1: ok", "secrets/S1: ok", "dependabot/D1: ok"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n--\n%s", want, s)
		}
	}
	if strings.Contains(s, "FAILED") {
		t.Errorf("unexpected FAILED line:\n%s", s)
	}
	if strings.Contains(s, "summary:") {
		t.Errorf("no summary line should appear when nothing failed:\n%s", s)
	}
}

func TestApplyRepo_OnlyVars_NoKeyFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: x
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if be.actionsKeyFetches != 0 || be.dependabotKeyFetches != 0 {
		t.Errorf("no key should be fetched when only vars are managed; actions=%d dep=%d",
			be.actionsKeyFetches, be.dependabotKeyFetches)
	}
}

func TestApplyRepo_PerEntryFailureContinues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_GOOD:
              value: ok
            V_BAD:
              value: ok
          secrets:
            S_GOOD:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		setErr: map[string]error{"vars/V_BAD": errors.New("rate limit")},
	}
	var out bytes.Buffer
	res, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 1 {
		t.Errorf("expected 1 failure, got %d", res.Failed)
	}
	if got := callNames(be.setVarCalls); !equalSorted(got, []string{"V_GOOD"}) {
		t.Errorf("V_BAD should not appear in successful var calls: %v", got)
	}
	if len(be.setSecCalls) != 1 {
		t.Errorf("S_GOOD should still be applied after V_BAD failed: %+v", be.setSecCalls)
	}
	s := out.String()
	if !strings.Contains(s, "vars/V_BAD: FAILED: rate limit") {
		t.Errorf("output missing failure line:\n%s", s)
	}
	if !strings.Contains(s, "summary: 1 failed") {
		t.Errorf("output missing summary line:\n%s", s)
	}
}

func TestApplyRepo_KeyFetchFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          secrets:
            S:
              value: x
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{actionsKeyErr: errors.New("forbidden")}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error when public key fetch fails")
	}
}

func TestApplyRepo_DependabotKeyFetchFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          dependabot:
            D:
              value: x
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{dependabotKeyErr: errors.New("forbidden")}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error when dependabot public key fetch fails")
	}
}

func TestApplyRepo_ResolveError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              file: missing.txt
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", &fakeBackend{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestApplyRepo_UnknownOrgRepo(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{}}
	if _, err := ApplyRepo(context.Background(), cfg, "missing", "acme", &fakeBackend{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for unknown org")
	}
	cfg.Orgs["example"] = &config.Org{PerRepo: map[string]*config.Repo{}}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "missing", &fakeBackend{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for unknown repo")
	}
}

func callNames(cs []setVarCall) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}

func secretCallNames(cs []setSecretCall) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}

func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	slices.Sort(aa)
	slices.Sort(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

// TestApplyRepo_EnvSource_OtherRepoUnsetEnvDoesNotAbort asserts the lazy
// env-resolution contract: when --repo X targets a repo whose entries do
// not reference an env var FOO, FOO being unset does not abort the run
// even though some other repo in the same config references FOO.
func TestApplyRepo_EnvSource_OtherRepoUnsetEnvDoesNotAbort(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_ACME:
              env: GHSM_TEST_ACME_SET
      other:
        managed:
          vars:
            V_OTHER:
              env: GHSM_TEST_OTHER_NEVER_SET
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHSM_TEST_ACME_SET", "acme-value")
	// Note: GHSM_TEST_OTHER_NEVER_SET is intentionally never set.

	be := &fakeBackend{}
	var out bytes.Buffer
	res, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &out)
	if err != nil {
		t.Fatalf("targeting acme should not require env vars referenced only by another repo, got: %v", err)
	}
	if res.Failed != 0 {
		t.Errorf("expected zero failures, got %d", res.Failed)
	}
	if len(be.setVarCalls) != 1 || be.setVarCalls[0].name != "V_ACME" || be.setVarCalls[0].value != "acme-value" {
		t.Errorf("unexpected set calls: %+v", be.setVarCalls)
	}
}

func TestApplyRepo_EnvSource_TargetedUnsetEnvFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          secrets:
            S_NEEDED:
              env: GHSM_TEST_TARGETED_NEVER_SET
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ApplyRepo(context.Background(), cfg, "example", "acme", &fakeBackend{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when a targeted entry's env var is unset")
	}
	if !strings.Contains(err.Error(), "S_NEEDED") {
		t.Errorf("error should mention the entry name; got: %v", err)
	}
	if !strings.Contains(err.Error(), "GHSM_TEST_TARGETED_NEVER_SET") {
		t.Errorf("error should mention the env var name; got: %v", err)
	}
}

func TestAuditRepo_EnvSource(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              env: GHSM_TEST_AUDIT_ENV
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHSM_TEST_AUDIT_ENV", "live-side")

	be := &fakeBackend{vars: map[string]string{"V": "live-side"}}
	var out bytes.Buffer
	res, err := AuditRepo(context.Background(), cfg, "example", "acme", be, &out, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Drift {
		t.Errorf("expected no drift; got:\n%s", out.String())
	}
}

// TestApplyRepo_DoesNotWriteIgnored asserts that names listed in the
// per-repo `ignored` block are never set, even when no managed entry of
// the same name exists. The fake backend records every Set call, so any
// write to an ignored name would show up here.
func TestApplyRepo_DoesNotWriteIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_ON:
              value: ok
          secrets:
            S_ON:
              value: ok
          dependabot:
            D_ON:
              value: ok
        ignored:
          vars:
            - V_OFF
          secrets:
            - S_OFF
          dependabot:
            - D_OFF
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	var out bytes.Buffer
	res, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 0 {
		t.Errorf("expected zero failures, got %d", res.Failed)
	}
	for _, c := range be.setVarCalls {
		if c.name == "V_OFF" {
			t.Errorf("ignored var V_OFF must not be written; got %+v", c)
		}
	}
	for _, c := range be.setSecCalls {
		if c.name == "S_OFF" {
			t.Errorf("ignored secret S_OFF must not be written; got %+v", c)
		}
	}
	for _, c := range be.setDepCalls {
		if c.name == "D_OFF" {
			t.Errorf("ignored dependabot D_OFF must not be written; got %+v", c)
		}
	}
	s := out.String()
	for _, name := range []string{"V_OFF", "S_OFF", "D_OFF"} {
		if strings.Contains(s, name) {
			t.Errorf("apply output should not mention ignored name %q; got:\n%s", name, s)
		}
	}
}

func TestEnforceRepo_DeletesExtrasAndAppliesManaged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_KEEP:
              value: ok
          secrets:
            S_KEEP:
              value: ok
          dependabot:
            D_KEEP:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		vars:       map[string]string{"V_KEEP": "ok", "V_EXTRA1": "x", "V_EXTRA2": "y"},
		secrets:    []string{"S_KEEP", "S_EXTRA"},
		dependabot: []string{"D_KEEP", "D_EXTRA"},
	}
	var out bytes.Buffer
	res, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &out, EnforceOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 0 {
		t.Errorf("expected zero failures, got %d", res.Failed)
	}
	if !equalSorted(be.delVarCalls, []string{"V_EXTRA1", "V_EXTRA2"}) {
		t.Errorf("var deletes: got %v want [V_EXTRA1 V_EXTRA2]", be.delVarCalls)
	}
	if !equalSorted(be.delSecCalls, []string{"S_EXTRA"}) {
		t.Errorf("secret deletes: got %v want [S_EXTRA]", be.delSecCalls)
	}
	if !equalSorted(be.delDepCalls, []string{"D_EXTRA"}) {
		t.Errorf("dependabot deletes: got %v want [D_EXTRA]", be.delDepCalls)
	}
	if !equalSorted(callNames(be.setVarCalls), []string{"V_KEEP"}) {
		t.Errorf("var sets: got %v", callNames(be.setVarCalls))
	}
	if !equalSorted(secretCallNames(be.setSecCalls), []string{"S_KEEP"}) {
		t.Errorf("secret sets: got %v", secretCallNames(be.setSecCalls))
	}
	if !equalSorted(secretCallNames(be.setDepCalls), []string{"D_KEEP"}) {
		t.Errorf("dependabot sets: got %v", secretCallNames(be.setDepCalls))
	}

	s := out.String()
	for _, want := range []string{
		"repo: acme",
		"vars/V_KEEP: ok",
		"vars/V_EXTRA1: deleted",
		"secrets/S_EXTRA: deleted",
		"dependabot/D_EXTRA: deleted",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n--\n%s", want, s)
		}
	}
}

func TestEnforceRepo_IgnoredExtrasNotDeleted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_KEEP:
              value: ok
        ignored:
          vars:
            - V_LEAVE_ALONE
          secrets:
            - S_LEAVE_ALONE
          dependabot:
            - D_LEAVE_ALONE
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		vars:       map[string]string{"V_KEEP": "ok", "V_LEAVE_ALONE": "x", "V_EXTRA": "y"},
		secrets:    []string{"S_LEAVE_ALONE", "S_EXTRA"},
		dependabot: []string{"D_LEAVE_ALONE"},
	}
	var out bytes.Buffer
	if _, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &out, EnforceOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, n := range be.delVarCalls {
		if n == "V_LEAVE_ALONE" {
			t.Errorf("ignored var V_LEAVE_ALONE should not be deleted; got %v", be.delVarCalls)
		}
	}
	for _, n := range be.delSecCalls {
		if n == "S_LEAVE_ALONE" {
			t.Errorf("ignored secret S_LEAVE_ALONE should not be deleted; got %v", be.delSecCalls)
		}
	}
	for _, n := range be.delDepCalls {
		if n == "D_LEAVE_ALONE" {
			t.Errorf("ignored dependabot D_LEAVE_ALONE should not be deleted; got %v", be.delDepCalls)
		}
	}
	if !equalSorted(be.delVarCalls, []string{"V_EXTRA"}) {
		t.Errorf("var deletes: got %v want [V_EXTRA]", be.delVarCalls)
	}
	if !equalSorted(be.delSecCalls, []string{"S_EXTRA"}) {
		t.Errorf("secret deletes: got %v want [S_EXTRA]", be.delSecCalls)
	}
	if len(be.delDepCalls) != 0 {
		t.Errorf("dependabot deletes: got %v want []", be.delDepCalls)
	}
	s := out.String()
	for _, name := range []string{"V_LEAVE_ALONE", "S_LEAVE_ALONE", "D_LEAVE_ALONE"} {
		if strings.Contains(s, name) {
			t.Errorf("ignored name %q must not appear in enforce output:\n%s", name, s)
		}
	}
}

func TestEnforceRepo_DryRunSkipsAllWrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_KEEP:
              value: ok
          secrets:
            S_KEEP:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		vars:    map[string]string{"V_EXTRA": "x"},
		secrets: []string{"S_EXTRA"},
	}
	var out bytes.Buffer
	res, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &out, EnforceOptions{DryRun: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 0 {
		t.Errorf("expected zero failures, got %d", res.Failed)
	}
	if len(be.setVarCalls)+len(be.setSecCalls)+len(be.setDepCalls) != 0 {
		t.Errorf("dry-run made set calls: vars=%v secs=%v deps=%v",
			be.setVarCalls, be.setSecCalls, be.setDepCalls)
	}
	if len(be.delVarCalls)+len(be.delSecCalls)+len(be.delDepCalls) != 0 {
		t.Errorf("dry-run made delete calls: vars=%v secs=%v deps=%v",
			be.delVarCalls, be.delSecCalls, be.delDepCalls)
	}
	if be.actionsKeyFetches != 0 || be.dependabotKeyFetches != 0 {
		t.Errorf("dry-run should not fetch public keys; actions=%d dep=%d",
			be.actionsKeyFetches, be.dependabotKeyFetches)
	}
	s := out.String()
	for _, want := range []string{
		"vars/V_KEEP: would-set",
		"secrets/S_KEEP: would-set",
		"vars/V_EXTRA: would-delete",
		"secrets/S_EXTRA: would-delete",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dry-run output missing %q\n--\n%s", want, s)
		}
	}
}

func TestEnforceRepo_DryRunDoesNotResolve(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              env: GHSM_TEST_ENFORCE_DRYRUN_NEVER_SET
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	if _, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}, EnforceOptions{DryRun: true}); err != nil {
		t.Fatalf("dry-run should not require value resolution; got: %v", err)
	}
}

func TestEnforceRepo_DeleteFailureContinues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		vars:   map[string]string{"V_BAD": "x", "V_GOOD": "y"},
		delErr: map[string]error{"vars/V_BAD": errors.New("boom")},
	}
	var out bytes.Buffer
	res, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &out, EnforceOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 1 {
		t.Errorf("expected 1 failure, got %d", res.Failed)
	}
	if !equalSorted(be.delVarCalls, []string{"V_GOOD"}) {
		t.Errorf("V_GOOD should still be deleted after V_BAD failed: got %v", be.delVarCalls)
	}
	s := out.String()
	if !strings.Contains(s, "vars/V_BAD: FAILED: boom") {
		t.Errorf("output missing failure line:\n%s", s)
	}
	if !strings.Contains(s, "summary: 1 failed") {
		t.Errorf("output missing summary line:\n%s", s)
	}
}

func TestEnforceRepo_ConfirmCallbackReceivesExtras(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		vars:       map[string]string{"V_X": "x"},
		secrets:    []string{"S_X"},
		dependabot: []string{"D_X"},
	}
	var got []string
	confirm := func(extras []string) bool {
		got = append([]string(nil), extras...)
		return true
	}
	if _, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{},
		EnforceOptions{Confirm: confirm}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalSorted(got, []string{"vars/V_X", "secrets/S_X", "dependabot/D_X"}) {
		t.Errorf("Confirm got %v, want sorted-equal of [vars/V_X secrets/S_X dependabot/D_X]", got)
	}
	if len(be.delVarCalls) != 1 || len(be.delSecCalls) != 1 || len(be.delDepCalls) != 1 {
		t.Errorf("expected one delete per kind after confirm=true; got vars=%v secs=%v deps=%v",
			be.delVarCalls, be.delSecCalls, be.delDepCalls)
	}
}

func TestEnforceRepo_ConfirmFalseSkipsAllWrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V_KEEP:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"V_X": "x"}}
	confirm := func(_ []string) bool { return false }
	res, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{},
		EnforceOptions{Confirm: confirm})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Failed != 0 {
		t.Errorf("Failed should be 0 when confirm declined")
	}
	if len(be.setVarCalls)+len(be.delVarCalls) != 0 {
		t.Errorf("confirm=false must skip all writes; sets=%v dels=%v", be.setVarCalls, be.delVarCalls)
	}
	if be.actionsKeyFetches != 0 {
		t.Errorf("public key should not be fetched when confirm declines; got %d", be.actionsKeyFetches)
	}
}

func TestEnforceRepo_DryRunIgnoresConfirm(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed: {}
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"V_X": "x"}}
	called := false
	confirm := func(_ []string) bool {
		called = true
		return false
	}
	if _, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{},
		EnforceOptions{DryRun: true, Confirm: confirm}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Errorf("Confirm must not be invoked when DryRun is true")
	}
}

func TestEnforceRepo_UnknownOrgRepo(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{}}
	if _, err := EnforceRepo(context.Background(), cfg, "missing", "acme", &fakeBackend{}, &bytes.Buffer{}, EnforceOptions{}); err == nil {
		t.Fatal("expected error for unknown org")
	}
	cfg.Orgs["example"] = &config.Org{PerRepo: map[string]*config.Repo{}}
	if _, err := EnforceRepo(context.Background(), cfg, "example", "missing", &fakeBackend{}, &bytes.Buffer{}, EnforceOptions{}); err == nil {
		t.Fatal("expected error for unknown repo")
	}
}

func TestEnforceRepo_BackendListError(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Orgs: map[string]*config.Org{
			"example": {PerRepo: map[string]*config.Repo{"acme": {}}},
		},
	}
	be := &fakeBackend{err: errors.New("boom")}
	if _, err := EnforceRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}, EnforceOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnforceRepo_ResolveErrorWhenLive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              file: missing.txt
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnforceRepo(context.Background(), cfg, "example", "acme", &fakeBackend{}, &bytes.Buffer{}, EnforceOptions{}); err == nil {
		t.Fatal("expected resolve error in live enforce mode")
	}
}

func TestAudit_IteratesEveryOrgRepo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          ALL_VAR:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		orgRepos: []string{"acme", "beta"},
		vars:     map[string]string{"ALL_VAR": "ok"},
	}
	var out bytes.Buffer
	res, err := Audit(context.Background(), cfg, "example", be, &out, false, OrgOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Drift {
		t.Errorf("expected no drift; got:\n%s", out.String())
	}
	if res.OkRepos != 2 || res.FailedRepos != 0 {
		t.Errorf("repo counts: ok=%d failed=%d (want ok=2 failed=0)",
			res.OkRepos, res.FailedRepos)
	}
	s := out.String()
	for _, want := range []string{"repo: acme", "repo: beta", "summary: ok=2 skipped=0 failed=0"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n--\n%s", want, s)
		}
	}
}

func TestAudit_SkipsReposNotInConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		orgRepos: []string{"acme", "unrelated"},
		vars:     map[string]string{"V": "ok"},
	}
	var out bytes.Buffer
	res, err := Audit(context.Background(), cfg, "example", be, &out, false, OrgOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OkRepos != 1 {
		t.Errorf("ok repos: got %d want 1 (unrelated should be skipped)", res.OkRepos)
	}
	if strings.Contains(out.String(), "repo: unrelated") {
		t.Errorf("unrelated repo should not appear in output:\n%s", out.String())
	}
}

func TestAudit_PerRepoErrorContinues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Backend errors on repo list calls; every repo errors uniformly.
	be := &fakeBackend{
		orgRepos: []string{"a", "b"},
		err:      errors.New("boom"),
	}
	var out bytes.Buffer
	res, err := Audit(context.Background(), cfg, "example", be, &out, false, OrgOptions{})
	if err != nil {
		t.Fatalf("Audit should continue on per-repo error, not return one: %v", err)
	}
	if res.FailedRepos != 2 || res.OkRepos != 0 {
		t.Errorf("got ok=%d failed=%d; want ok=0 failed=2", res.OkRepos, res.FailedRepos)
	}
	s := out.String()
	if !strings.Contains(s, "ERROR: ") {
		t.Errorf("expected ERROR line in output:\n%s", s)
	}
	if !strings.Contains(s, "summary: ok=0 skipped=0 failed=2") {
		t.Errorf("expected summary line: %q", s)
	}
}

func TestAudit_ListOrgReposError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed: {}
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{orgReposErr: errors.New("forbidden")}
	if _, err := Audit(context.Background(), cfg, "example", be, &bytes.Buffer{}, false, OrgOptions{}); err == nil {
		t.Fatal("expected error when ListOrgRepos fails")
	}
}

func TestAudit_UnknownOrg(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{}}
	if _, err := Audit(context.Background(), cfg, "missing", &fakeBackend{}, &bytes.Buffer{}, false, OrgOptions{}); err == nil {
		t.Fatal("expected error for unknown org")
	}
}

func TestApply_IteratesAndAppliesCascade(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          ALL_VAR:
            value: shared
    per-repo:
      acme:
        managed:
          vars:
            ALL_VAR:
              value: acme-override
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{orgRepos: []string{"acme", "beta"}}
	var out bytes.Buffer
	res, err := Apply(context.Background(), cfg, "example", be, &out, OrgOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OkRepos != 2 {
		t.Errorf("ok repos: %d", res.OkRepos)
	}
	wantValues := map[string]string{
		"acme": "acme-override",
		"beta": "shared",
	}
	got := map[string]string{}
	for _, c := range be.setVarCalls {
		got[c.repo] = c.value
	}
	for r, v := range wantValues {
		if got[r] != v {
			t.Errorf("repo %s: got %q want %q (per-repo > all-repos)", r, got[r], v)
		}
	}
}

func TestApply_UnknownOrg(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{}}
	if _, err := Apply(context.Background(), cfg, "missing", &fakeBackend{}, &bytes.Buffer{}, OrgOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestApply_ListOrgReposError(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{
		"example": {AllRepos: &config.Repo{}},
	}}
	be := &fakeBackend{orgReposErr: errors.New("boom")}
	if _, err := Apply(context.Background(), cfg, "example", be, &bytes.Buffer{}, OrgOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnforce_IteratesDryRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          KEEP:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		orgRepos: []string{"acme", "beta"},
		vars:     map[string]string{"EXTRA": "x"},
	}
	var out bytes.Buffer
	if _, err := Enforce(context.Background(), cfg, "example", be, &out, EnforceOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if len(be.setVarCalls)+len(be.delVarCalls) != 0 {
		t.Errorf("dry-run made writes: sets=%v dels=%v", be.setVarCalls, be.delVarCalls)
	}
	s := out.String()
	for _, want := range []string{"repo: acme", "repo: beta", "would-set", "would-delete"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n--\n%s", want, s)
		}
	}
}

func TestEnforce_UnknownOrg(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{}}
	if _, err := Enforce(context.Background(), cfg, "missing", &fakeBackend{}, &bytes.Buffer{}, EnforceOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestEnforce_ListOrgReposError(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Orgs: map[string]*config.Org{
		"example": {AllRepos: &config.Repo{}},
	}}
	be := &fakeBackend{orgReposErr: errors.New("boom")}
	if _, err := Enforce(context.Background(), cfg, "example", be, &bytes.Buffer{}, EnforceOptions{}); err == nil {
		t.Fatal("expected error")
	}
}

// TestAuditRepo_AllReposOnly asserts that when a repo has no per-repo entry
// but the org defines all-repos, the per-repo audit still proceeds via
// cascade.
func TestAuditRepo_AllReposOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: shared
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"V": "shared"}}
	res, err := AuditRepo(context.Background(), cfg, "example", "any-repo", be, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("repo with no per-repo entry should still audit when all-repos exists: %v", err)
	}
	if res.Drift {
		t.Errorf("expected no drift")
	}
}

// TestApplyRepo_PerRepoOverridesAllRepos asserts that the cascade path
// honors per-repo > all-repos at the apply layer.
func TestApplyRepo_PerRepoOverridesAllRepos(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: shared
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: acme-only
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(be.setVarCalls) != 1 || be.setVarCalls[0].value != "acme-only" {
		t.Errorf("expected acme-only; got %+v", be.setVarCalls)
	}
}

// TestApplyRepo_AllReposShieldedByPerRepoIgnored asserts that per-repo's
// ignored list shields the repo from an all-repos.managed write.
func TestApplyRepo_AllReposShieldedByPerRepoIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: shared
    per-repo:
      acme:
        ignored:
          vars:
            - V
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(be.setVarCalls) != 0 {
		t.Errorf("per-repo.ignored must shield against all-repos.managed; got writes: %+v",
			be.setVarCalls)
	}
}

// TestApplyRepo_PerRepoManagedOverridesAllReposIgnored asserts that a
// per-repo.managed entry rescues a name from all-repos.ignored.
func TestApplyRepo_PerRepoManagedOverridesAllReposIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      ignored:
        vars:
          - V
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: acme-explicit
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{}
	if _, err := ApplyRepo(context.Background(), cfg, "example", "acme", be, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(be.setVarCalls) != 1 || be.setVarCalls[0].value != "acme-explicit" {
		t.Errorf("per-repo.managed must override all-repos.ignored; got %+v", be.setVarCalls)
	}
}

func TestAuditRepo_ShowIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        ignored:
          vars:
            - IG_VAR
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{vars: map[string]string{"IG_VAR": "x"}}
	var out bytes.Buffer
	res, err := AuditRepo(context.Background(), cfg, "example", "acme", be, &out, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Drift {
		t.Errorf("ignored should not count as drift")
	}
	if !strings.Contains(out.String(), "IG_VAR") {
		t.Errorf("expected IG_VAR in output with showIgnored=true; got:\n%s", out.String())
	}
}

// gatedBackend extends fakeBackend with a per-call gate. Every call to
// ListRepoVariables increments inFlight (then decrements on return) and
// observes maxInFlight, letting tests assert that no more than the
// configured concurrency runs at once.
type gatedBackend struct {
	fakeBackend
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	release     chan struct{}
}

func (g *gatedBackend) ListRepoVariables(_ context.Context, _, _ string) (map[string]string, error) {
	cur := g.inFlight.Add(1)
	for {
		hi := g.maxInFlight.Load()
		if cur <= hi || g.maxInFlight.CompareAndSwap(hi, cur) {
			break
		}
	}
	if g.release != nil {
		<-g.release
	}
	g.inFlight.Add(-1)
	return g.vars, g.err
}

func TestAudit_RespectsConcurrencyLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	repoNames := make([]string, 0, 32)
	for i := range 32 {
		repoNames = append(repoNames, "r-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	be := &gatedBackend{
		fakeBackend: fakeBackend{
			orgRepos: repoNames,
			vars:     map[string]string{"V": "ok"},
		},
		release: make(chan struct{}, len(repoNames)),
	}
	for range repoNames {
		be.release <- struct{}{}
	}

	var out bytes.Buffer
	limit := 4
	if _, err := Audit(context.Background(), cfg, "example", be, &out, false, OrgOptions{Concurrency: limit}); err != nil {
		t.Fatal(err)
	}
	if got := int(be.maxInFlight.Load()); got > limit {
		t.Errorf("max concurrent ListRepoVariables=%d exceeds limit=%d", got, limit)
	}
}

// TestAudit_AtomicPerRepoOutput asserts that per-repo stanzas never
// interleave even when many repos run in parallel. Each stanza begins with
// "repo: <name>"; once a stanza begins, all subsequent indented lines must
// belong to that same repo until the next "repo:" header.
func TestAudit_AtomicPerRepoOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          A:
            value: ok
          B:
            value: ok
          C:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	repoNames := make([]string, 0, n)
	for i := range n {
		repoNames = append(repoNames, "r"+string(rune('a'+i%26))+string(rune('A'+i/26)))
	}
	be := &fakeBackend{
		orgRepos: repoNames,
		vars:     map[string]string{"A": "ok", "B": "ok", "C": "ok"},
	}

	var out bytes.Buffer
	if _, err := Audit(context.Background(), cfg, "example", be, &out, false, OrgOptions{Concurrency: 8}); err != nil {
		t.Fatal(err)
	}

	scan := bufio.NewScanner(strings.NewReader(out.String()))
	currentRepo := ""
	seenRepos := map[string]bool{}
	for scan.Scan() {
		line := scan.Text()
		switch {
		case strings.HasPrefix(line, "repo: "):
			currentRepo = strings.TrimPrefix(line, "repo: ")
			if seenRepos[currentRepo] {
				t.Fatalf("repo %q stanza appears more than once (interleaved):\n%s",
					currentRepo, out.String())
			}
			seenRepos[currentRepo] = true
		case strings.HasPrefix(line, "  "):
			if currentRepo == "" {
				t.Fatalf("indented line before any repo header:\n%q\nfull output:\n%s", line, out.String())
			}
		default:
			currentRepo = ""
		}
	}
	if len(seenRepos) != n {
		t.Errorf("expected %d distinct repo stanzas, got %d", n, len(seenRepos))
	}
}

func TestAudit_DefaultConcurrencyWhenZero(t *testing.T) {
	t.Parallel()
	if got := resolveConcurrency(0); got != DefaultConcurrency {
		t.Errorf("resolveConcurrency(0)=%d; want %d", got, DefaultConcurrency)
	}
	if got := resolveConcurrency(-3); got != DefaultConcurrency {
		t.Errorf("resolveConcurrency(-3)=%d; want %d", got, DefaultConcurrency)
	}
	if got := resolveConcurrency(2); got != 2 {
		t.Errorf("resolveConcurrency(2)=%d; want 2", got)
	}
}

func TestAudit_SkippedCount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    per-repo:
      acme:
        managed:
          vars:
            V:
              value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		orgRepos: []string{"acme", "unrelated", "also-unrelated"},
		vars:     map[string]string{"V": "ok"},
	}
	var out bytes.Buffer
	res, err := Audit(context.Background(), cfg, "example", be, &out, false, OrgOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OkRepos != 1 {
		t.Errorf("ok=%d want 1", res.OkRepos)
	}
	if res.SkippedRepos != 2 {
		t.Errorf("skipped=%d want 2", res.SkippedRepos)
	}
	if !strings.Contains(out.String(), "summary: ok=1 skipped=2 failed=0") {
		t.Errorf("summary line missing; got:\n%s", out.String())
	}
}

// TestAudit_ExitCodeMatrix exercises the four cases the issue calls out:
// {clean, drift-only, failure-only, both}. Exit codes are derived in the
// CLI from (Drift, FailedRepos) — here we assert the OrgResult fields the
// CLI inspects.
func TestAudit_ExitCodeMatrix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		live        map[string]string
		listErr     error
		wantDrift   bool
		wantFailed  int
		wantOk      int
		wantNonzero bool
	}{
		{
			name:        "clean",
			live:        map[string]string{"V": "ok"},
			wantOk:      2,
			wantNonzero: false,
		},
		{
			name:        "drift-only",
			live:        map[string]string{"V": "different"},
			wantDrift:   true,
			wantOk:      2,
			wantNonzero: true,
		},
		{
			name:        "failure-only",
			listErr:     errors.New("boom"),
			wantFailed:  2,
			wantNonzero: true,
		},
		{
			name:        "both-drift-and-failure",
			live:        map[string]string{"V": "different"},
			listErr:     errors.New("boom"), // err short-circuits before drift, so failure dominates
			wantFailed:  2,
			wantNonzero: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			be := &fakeBackend{
				orgRepos: []string{"a", "b"},
				vars:     tc.live,
				err:      tc.listErr,
			}
			res, err := Audit(context.Background(), cfg, "example", be, &bytes.Buffer{}, false, OrgOptions{})
			if err != nil {
				t.Fatalf("Audit returned err: %v", err)
			}
			if res.Drift != tc.wantDrift {
				t.Errorf("Drift=%v want %v", res.Drift, tc.wantDrift)
			}
			if res.FailedRepos != tc.wantFailed {
				t.Errorf("FailedRepos=%d want %d", res.FailedRepos, tc.wantFailed)
			}
			if res.OkRepos != tc.wantOk {
				t.Errorf("OkRepos=%d want %d", res.OkRepos, tc.wantOk)
			}
			nonzero := res.Drift || res.FailedRepos > 0
			if nonzero != tc.wantNonzero {
				t.Errorf("derived nonzero exit=%v want %v", nonzero, tc.wantNonzero)
			}
		})
	}
}

func TestApply_PartialFailureContinues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		orgRepos: []string{"a", "b", "c"},
		setErr:   map[string]error{"vars/V": errors.New("rate limit")},
	}
	var out bytes.Buffer
	res, err := Apply(context.Background(), cfg, "example", be, &out, OrgOptions{Concurrency: 3})
	if err != nil {
		t.Fatalf("apply should not return an error on per-entry failures: %v", err)
	}
	if res.OkRepos != 3 {
		t.Errorf("OkRepos=%d want 3 (per-repo wrapper succeeds; failure is per-entry)", res.OkRepos)
	}
	if res.FailedEntries != 3 {
		t.Errorf("FailedEntries=%d want 3 (one per repo)", res.FailedEntries)
	}
	if !strings.Contains(out.String(), "summary: ok=3 skipped=0 failed=0") {
		t.Errorf("summary line missing or wrong; got:\n%s", out.String())
	}
}

func TestEnforce_AtomicOutputDryRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secrets.yml")
	if err := writeFile(cfgPath, []byte(`
github.com:
  example:
    all-repos:
      managed:
        vars:
          V:
            value: ok
`)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	be := &fakeBackend{
		orgRepos: []string{"a", "b", "c", "d"},
		vars:     map[string]string{"EXTRA": "x"},
	}
	var out bytes.Buffer
	res, err := Enforce(context.Background(), cfg, "example", be, &out, EnforceOptions{DryRun: true, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	if res.OkRepos != 4 {
		t.Errorf("OkRepos=%d want 4", res.OkRepos)
	}
	if !strings.Contains(out.String(), "summary: ok=4 skipped=0 failed=0") {
		t.Errorf("summary missing; got:\n%s", out.String())
	}
	scan := bufio.NewScanner(strings.NewReader(out.String()))
	seen := map[string]bool{}
	for scan.Scan() {
		line := scan.Text()
		name, ok := strings.CutPrefix(line, "repo: ")
		if !ok {
			continue
		}
		if seen[name] {
			t.Fatalf("repo %q stanza split (interleaved):\n%s", name, out.String())
		}
		seen[name] = true
	}
}
