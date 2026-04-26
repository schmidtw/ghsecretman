// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"strings"
	"testing"
)

func TestExample_NotEmpty(t *testing.T) {
	t.Parallel()
	if Example == "" {
		t.Fatal("Example is empty; embed failed")
	}
}

func TestExample_HasSchemaMarkers(t *testing.T) {
	t.Parallel()
	for _, marker := range []string{
		"github.com:",
		"managed:",
		"ignored:",
		"per-repo:",
		"all-repos:",
	} {
		if !strings.Contains(Example, marker) {
			t.Errorf("Example missing schema marker %q", marker)
		}
	}
}
