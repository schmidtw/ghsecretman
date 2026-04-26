// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"sort"
	"testing"

	"github.com/schmidtw/ghsecretman/internal/config"
	"github.com/schmidtw/ghsecretman/internal/plan"
)

func TestCompute_VarsMatchAndMismatchAndMissingAndExtra(t *testing.T) {
	t.Parallel()
	intents := []plan.Intent{
		{Repo: "acme", Kind: plan.KindVar, Name: "MATCHED", Action: plan.ActionManaged},
		{Repo: "acme", Kind: plan.KindVar, Name: "MISMATCHED", Action: plan.ActionManaged},
		{Repo: "acme", Kind: plan.KindVar, Name: "NOT_ON_GH", Action: plan.ActionManaged},
	}
	desired := map[string]string{
		"MATCHED":    "same",
		"MISMATCHED": "yaml-value",
		"NOT_ON_GH":  "val",
	}
	live := Live{
		Vars: map[string]string{
			"MATCHED":    "same",
			"MISMATCHED": "gh-value",
			"EXTRA_VAR":  "v",
		},
	}
	ignored := config.Ignored{}

	got := Compute("acme", intents, desired, live, ignored)
	want := map[string]Status{
		"vars/MATCHED":    Match,
		"vars/MISMATCHED": Mismatch,
		"vars/NOT_ON_GH":  Missing,
		"vars/EXTRA_VAR":  Extra,
	}
	checkEntries(t, got, want)
}

func TestCompute_SecretsAndDependabot(t *testing.T) {
	t.Parallel()
	intents := []plan.Intent{
		{Repo: "acme", Kind: plan.KindSecret, Name: "PRESENT_SEC", Action: plan.ActionManaged},
		{Repo: "acme", Kind: plan.KindSecret, Name: "MISSING_SEC", Action: plan.ActionManaged},
		{Repo: "acme", Kind: plan.KindDependabot, Name: "PRESENT_DEP", Action: plan.ActionManaged},
		{Repo: "acme", Kind: plan.KindDependabot, Name: "MISSING_DEP", Action: plan.ActionManaged},
	}
	live := Live{
		Secrets:    []string{"PRESENT_SEC", "EXTRA_SEC"},
		Dependabot: []string{"PRESENT_DEP", "EXTRA_DEP"},
	}

	got := Compute("acme", intents, nil, live, config.Ignored{})
	want := map[string]Status{
		"secrets/PRESENT_SEC":    Present,
		"secrets/MISSING_SEC":    Missing,
		"secrets/EXTRA_SEC":      Extra,
		"dependabot/PRESENT_DEP": Present,
		"dependabot/MISSING_DEP": Missing,
		"dependabot/EXTRA_DEP":   Extra,
	}
	checkEntries(t, got, want)
}

func TestCompute_IgnoredSuppressesExtra(t *testing.T) {
	t.Parallel()
	live := Live{
		Vars:       map[string]string{"IG_VAR": "v"},
		Secrets:    []string{"IG_SEC"},
		Dependabot: []string{"IG_DEP"},
	}
	ig := config.Ignored{
		Vars:       []string{"IG_VAR"},
		Secrets:    []string{"IG_SEC"},
		Dependabot: []string{"IG_DEP"},
	}
	got := Compute("acme", nil, nil, live, ig)
	want := map[string]Status{
		"vars/IG_VAR":       Ignored,
		"secrets/IG_SEC":    Ignored,
		"dependabot/IG_DEP": Ignored,
	}
	checkEntries(t, got, want)
}

func TestHasDrift(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		entries []Entry
		want    bool
	}{
		{"empty", nil, false},
		{"only matches and ignored", []Entry{
			{Status: Match}, {Status: Present}, {Status: Ignored},
		}, false},
		{"mismatch", []Entry{{Status: Mismatch}}, true},
		{"missing", []Entry{{Status: Missing}}, true},
		{"extra", []Entry{{Status: Extra}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := HasDrift(tc.entries); got != tc.want {
				t.Fatalf("HasDrift: got %v want %v", got, tc.want)
			}
		})
	}
}

func checkEntries(t *testing.T, got []Entry, want map[string]Status) {
	t.Helper()
	gotMap := map[string]Status{}
	keys := make([]string, 0, len(got))
	for _, e := range got {
		k := string(e.Kind) + "/" + e.Name
		gotMap[k] = e.Status
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(gotMap) != len(want) {
		t.Errorf("entry count: got %d (%v) want %d (%v)", len(gotMap), keys, len(want), want)
	}
	for k, v := range want {
		if gv, ok := gotMap[k]; !ok || gv != v {
			t.Errorf("%s: got %q want %q", k, gv, v)
		}
	}
}
