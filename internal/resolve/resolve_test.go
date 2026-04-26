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
	t.Setenv("GHSM_TEST_VAR", "from-env")
	got, err := Resolve(&config.Entry{Env: "GHSM_TEST_VAR"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("got %q want %q", got, "from-env")
	}
}

func TestResolve_EnvMissing(t *testing.T) {
	_, err := Resolve(&config.Entry{Env: "GHSM_TEST_DEFINITELY_UNSET_VAR"})
	if err == nil {
		t.Fatal("expected error for missing env var")
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
