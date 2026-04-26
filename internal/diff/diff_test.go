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

func TestCompute_SkipIntentsDoNotCountAsIntended(t *testing.T) {
	t.Parallel()
	// A skip-intent (Action=ActionIgnored) for IG_VAR must not make the
	// diff treat IG_VAR as an intended write: the live IG_VAR should be
	// reported as Ignored, not Match/Mismatch/Missing.
	intents := []plan.Intent{
		{Repo: "acme", Kind: plan.KindVar, Name: "IG_VAR", Action: plan.ActionIgnored},
		{Repo: "acme", Kind: plan.KindSecret, Name: "IG_SEC", Action: plan.ActionIgnored},
		{Repo: "acme", Kind: plan.KindDependabot, Name: "IG_DEP", Action: plan.ActionIgnored},
	}
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
	got := Compute("acme", intents, nil, live, ig)
	want := map[string]Status{
		"vars/IG_VAR":       Ignored,
		"secrets/IG_SEC":    Ignored,
		"dependabot/IG_DEP": Ignored,
	}
	checkEntries(t, got, want)
	if HasDrift(got) {
		t.Errorf("ignored entries should not register as drift")
	}
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

func TestCompute_OverrideManaged_AttachesToManagedEntries(t *testing.T) {
	t.Parallel()
	// A per-repo.managed entry that shadowed an all-repos.managed entry
	// produces an Intent with OverridesAllRepos=true. Compute must surface
	// that on the resulting diff Entry as Override=OverrideManaged so audit
	// can render an override row, regardless of match/mismatch/missing/present.
	intents := []plan.Intent{
		{Repo: "acme", Kind: plan.KindVar, Name: "MATCH_OVR", Action: plan.ActionManaged, OverridesAllRepos: true},
		{Repo: "acme", Kind: plan.KindVar, Name: "MISS_OVR", Action: plan.ActionManaged, OverridesAllRepos: true},
		{Repo: "acme", Kind: plan.KindSecret, Name: "SEC_OVR", Action: plan.ActionManaged, OverridesAllRepos: true},
		{Repo: "acme", Kind: plan.KindDependabot, Name: "DEP_OVR", Action: plan.ActionManaged, OverridesAllRepos: true},
		{Repo: "acme", Kind: plan.KindVar, Name: "PLAIN", Action: plan.ActionManaged},
	}
	desired := map[string]string{
		"MATCH_OVR": "v",
		"MISS_OVR":  "v",
		"PLAIN":     "p",
	}
	live := Live{
		Vars:       map[string]string{"MATCH_OVR": "v", "PLAIN": "p"},
		Secrets:    []string{"SEC_OVR"},
		Dependabot: []string{},
	}
	got := Compute("acme", intents, desired, live, config.Ignored{})
	overrideOf := map[string]Override{}
	statusOf := map[string]Status{}
	for _, e := range got {
		key := string(e.Kind) + "/" + e.Name
		overrideOf[key] = e.Override
		statusOf[key] = e.Status
	}
	wantOverride := map[string]Override{
		"vars/MATCH_OVR":     OverrideManaged,
		"vars/MISS_OVR":      OverrideManaged,
		"secrets/SEC_OVR":    OverrideManaged,
		"dependabot/DEP_OVR": OverrideManaged,
		"vars/PLAIN":         OverrideNone,
	}
	for k, want := range wantOverride {
		if overrideOf[k] != want {
			t.Errorf("%s override: got %q want %q", k, overrideOf[k], want)
		}
	}
	if statusOf["vars/MATCH_OVR"] != Match {
		t.Errorf("MATCH_OVR status: got %q want match", statusOf["vars/MATCH_OVR"])
	}
	if statusOf["vars/MISS_OVR"] != Missing {
		t.Errorf("MISS_OVR status: got %q want missing", statusOf["vars/MISS_OVR"])
	}
	if statusOf["secrets/SEC_OVR"] != Present {
		t.Errorf("SEC_OVR status: got %q want present", statusOf["secrets/SEC_OVR"])
	}
	if statusOf["dependabot/DEP_OVR"] != Missing {
		t.Errorf("DEP_OVR status: got %q want missing", statusOf["dependabot/DEP_OVR"])
	}
}

func TestCompute_OverrideIgnored_ShieldsAllReposManaged(t *testing.T) {
	t.Parallel()
	// An ActionIgnored intent with ShieldsAllReposManaged=true is the
	// per-repo.ignored shadowing all-repos.managed case. The resulting
	// diff Entry must be Status=Ignored, Override=OverrideIgnored.
	// Behavior must hold both when the name is present on github (case A
	// here uses live=present) and when it's absent (case B below uses
	// live=absent — the row must still be emitted as a config-level fact).
	intents := []plan.Intent{
		{Repo: "acme", Kind: plan.KindVar, Name: "PRESENT_SHIELD", Action: plan.ActionIgnored, ShieldsAllReposManaged: true},
		{Repo: "acme", Kind: plan.KindVar, Name: "ABSENT_SHIELD", Action: plan.ActionIgnored, ShieldsAllReposManaged: true},
		{Repo: "acme", Kind: plan.KindSecret, Name: "SEC_SHIELD", Action: plan.ActionIgnored, ShieldsAllReposManaged: true},
		{Repo: "acme", Kind: plan.KindDependabot, Name: "DEP_SHIELD", Action: plan.ActionIgnored, ShieldsAllReposManaged: true},
		{Repo: "acme", Kind: plan.KindVar, Name: "PLAIN_IG", Action: plan.ActionIgnored},
	}
	live := Live{
		Vars:    map[string]string{"PRESENT_SHIELD": "v", "PLAIN_IG": "p"},
		Secrets: []string{"SEC_SHIELD"},
	}
	ig := config.Ignored{
		Vars:       []string{"PRESENT_SHIELD", "ABSENT_SHIELD", "PLAIN_IG"},
		Secrets:    []string{"SEC_SHIELD"},
		Dependabot: []string{"DEP_SHIELD"},
	}
	got := Compute("acme", intents, nil, live, ig)
	overrideOf := map[string]Override{}
	statusOf := map[string]Status{}
	for _, e := range got {
		key := string(e.Kind) + "/" + e.Name
		overrideOf[key] = e.Override
		statusOf[key] = e.Status
	}
	for _, k := range []string{
		"vars/PRESENT_SHIELD",
		"vars/ABSENT_SHIELD",
		"secrets/SEC_SHIELD",
		"dependabot/DEP_SHIELD",
	} {
		if statusOf[k] != Ignored {
			t.Errorf("%s status: got %q want ignored", k, statusOf[k])
		}
		if overrideOf[k] != OverrideIgnored {
			t.Errorf("%s override: got %q want %q", k, overrideOf[k], OverrideIgnored)
		}
	}
	if overrideOf["vars/PLAIN_IG"] != OverrideNone {
		t.Errorf("PLAIN_IG override: got %q want none", overrideOf["vars/PLAIN_IG"])
	}
	if HasDrift(got) {
		t.Errorf("ignored entries (including overrides) must not register as drift")
	}
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
