// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package resolve

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/schmidtw/ghsecretman/internal/config"
)

func TestResolve(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	relFile := filepath.Join(dir, "rel.txt")
	if err := writeTestFile(relFile, "rel-value\n"); err != nil {
		t.Fatal(err)
	}
	absFile := filepath.Join(dir, "abs.txt")
	if err := writeTestFile(absFile, "abs-value"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		entry *config.Entry
		want  string
	}{
		{
			name:  "value verbatim",
			entry: &config.Entry{HasValue: true, Value: "literal"},
			want:  "literal",
		},
		{
			name:  "empty value is allowed",
			entry: &config.Entry{HasValue: true, Value: ""},
			want:  "",
		},
		{
			name:  "file with trailing newline preserved",
			entry: &config.Entry{File: "rel.txt", FileAbs: relFile},
			want:  "rel-value\n",
		},
		{
			name:  "absolute file",
			entry: &config.Entry{File: absFile, FileAbs: absFile},
			want:  "abs-value",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Resolve(tc.entry)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestResolve_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.txt")
	_, err := Resolve(&config.Entry{File: "missing.txt", FileAbs: missing})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	var fe *FileError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FileError, got %T", err)
	}
	if !strings.Contains(err.Error(), "missing.txt") {
		t.Fatalf("error should mention path: %v", err)
	}
}

func TestResolve_NoSource(t *testing.T) {
	t.Parallel()
	_, err := Resolve(&config.Entry{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolve_Env(t *testing.T) {
	tests := []struct {
		name    string
		setKey  string
		setVal  string
		entry   *config.Entry
		want    string
		wantErr bool
	}{
		{
			name:   "env set returns value",
			setKey: "GHSM_TEST_SET",
			setVal: "from-env",
			entry:  &config.Entry{Name: "MY_ENTRY", Env: "GHSM_TEST_SET"},
			want:   "from-env",
		},
		{
			name:   "env set to empty string returns empty",
			setKey: "GHSM_TEST_EMPTY",
			setVal: "",
			entry:  &config.Entry{Name: "MY_ENTRY", Env: "GHSM_TEST_EMPTY"},
			want:   "",
		},
		{
			name:    "env unset returns EnvError",
			entry:   &config.Entry{Name: "MY_ENTRY", Env: "GHSM_TEST_DEFINITELY_UNSET"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setKey != "" {
				t.Setenv(tc.setKey, tc.setVal)
			}
			got, err := Resolve(tc.entry)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestResolve_EnvError_TypedAndContainsBothNames(t *testing.T) {
	_, err := Resolve(&config.Entry{Name: "MY_SECRET", Env: "GHSM_TEST_DEFINITELY_UNSET"})
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
	var ee *EnvError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *EnvError, got %T: %v", err, err)
	}
	if ee.Name != "MY_SECRET" {
		t.Errorf("EnvError.Name: got %q want %q", ee.Name, "MY_SECRET")
	}
	if ee.Var != "GHSM_TEST_DEFINITELY_UNSET" {
		t.Errorf("EnvError.Var: got %q want %q", ee.Var, "GHSM_TEST_DEFINITELY_UNSET")
	}
	msg := err.Error()
	if !strings.Contains(msg, "MY_SECRET") || !strings.Contains(msg, "GHSM_TEST_DEFINITELY_UNSET") {
		t.Errorf("error message %q must include both entry name and env var name", msg)
	}
}

// TestResolve_EnvLazy proves that constructing an entry referencing an env
// var does not by itself trigger a lookup — the lookup happens at the moment
// Resolve is called. The entry is built up-front (as it would be at config
// load time), then the env var is set, then Resolve is called and observes
// the new value.
func TestResolve_EnvLazy(t *testing.T) {
	entry := &config.Entry{Name: "LAZY", Env: "GHSM_TEST_LAZY"}

	if _, err := Resolve(entry); err == nil {
		t.Fatal("expected error before env was set")
	}

	t.Setenv("GHSM_TEST_LAZY", "now-set")
	got, err := Resolve(entry)
	if err != nil {
		t.Fatalf("unexpected error after env was set: %v", err)
	}
	if got != "now-set" {
		t.Fatalf("got %q want %q", got, "now-set")
	}
}

func TestResolve_FileWithoutAbs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.txt")
	if err := writeTestFile(path, "abc"); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(&config.Entry{File: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestFileError_Unwrap(t *testing.T) {
	t.Parallel()
	inner := errors.New("boom")
	fe := &FileError{Path: "/x", Err: inner}
	if !errors.Is(fe, inner) {
		t.Fatal("expected errors.Is to match wrapped error")
	}
}

func writeTestFile(path, content string) error {
	return writeFile(path, []byte(content))
}
