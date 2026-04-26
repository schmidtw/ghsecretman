// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/schmidtw/ghsecretman/internal/config"
)

type fakeBackend struct {
	vars       map[string]string
	secrets    []string
	dependabot []string
	err        error
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
