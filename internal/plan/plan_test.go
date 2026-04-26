// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package plan

import (
	"sort"
	"testing"

	"github.com/schmidtw/ghsecretman/internal/config"
)

func TestForRepo(t *testing.T) {
	t.Parallel()
	repo := &config.Repo{
		Managed: config.Managed{
			Vars: map[string]*config.Entry{
				"V1": {HasValue: true, Value: "v1"},
				"V2": {File: "x", FileAbs: "/abs/x"},
			},
			Secrets: map[string]*config.Entry{
				"S1": {HasValue: true, Value: "s1"},
			},
			Dependabot: map[string]*config.Entry{
				"D1": {HasValue: true, Value: "d1"},
			},
		},
		Ignored: config.Ignored{
			Vars:       []string{"IGV"},
			Secrets:    []string{"IGS"},
			Dependabot: []string{"IGD"},
		},
	}
	intents := ForRepo("acme", repo)

	got := summarize(intents)
	want := []string{
		"acme/dependabot/D1/managed",
		"acme/secrets/S1/managed",
		"acme/vars/V1/managed",
		"acme/vars/V2/managed",
	}
	if !equal(got, want) {
		t.Fatalf("intents:\ngot  %v\nwant %v", got, want)
	}

	if !IsIgnored(repo, KindVar, "IGV") {
		t.Errorf("IGV should be ignored")
	}
	if !IsIgnored(repo, KindSecret, "IGS") {
		t.Errorf("IGS should be ignored")
	}
	if !IsIgnored(repo, KindDependabot, "IGD") {
		t.Errorf("IGD should be ignored")
	}
	if IsIgnored(repo, KindVar, "V1") {
		t.Errorf("V1 should not be ignored")
	}
}

func TestForRepo_EmptyRepo(t *testing.T) {
	t.Parallel()
	intents := ForRepo("acme", &config.Repo{})
	if len(intents) != 0 {
		t.Fatalf("expected no intents, got %d", len(intents))
	}
}

func summarize(in []Intent) []string {
	out := make([]string, 0, len(in))
	for _, i := range in {
		out = append(out, i.Repo+"/"+string(i.Kind)+"/"+i.Name+"/"+string(i.Action))
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
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
