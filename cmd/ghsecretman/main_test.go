// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"strings"
	"testing"
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
