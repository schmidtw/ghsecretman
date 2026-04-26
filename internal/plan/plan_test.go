// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package plan

import (
	"slices"
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
		"acme/dependabot/IGD/ignored",
		"acme/secrets/IGS/ignored",
		"acme/secrets/S1/managed",
		"acme/vars/IGV/ignored",
		"acme/vars/V1/managed",
		"acme/vars/V2/managed",
	}
	if !equal(got, want) {
		t.Fatalf("intents:\ngot  %v\nwant %v", got, want)
	}

	for _, in := range intents {
		if in.Action == ActionIgnored && in.Entry != nil {
			t.Errorf("ignored intent should have nil Entry; got %+v", in)
		}
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

func TestForRepoCascade_Matrix(t *testing.T) {
	t.Parallel()

	type want struct {
		action            Action
		fromAllRepos      bool // true → entry should equal all-repos's entry
		overridesAllRepos bool
	}

	tests := []struct {
		name      string
		allMan    []string
		allIg     []string
		repoMan   []string
		repoIg    []string
		wantNames map[string]want // Name -> expectation; absent means absent
	}{
		{
			name:      "only all-repos.managed",
			allMan:    []string{"X"},
			wantNames: map[string]want{"X": {action: ActionManaged, fromAllRepos: true}},
		},
		{
			name:      "only all-repos.ignored",
			allIg:     []string{"X"},
			wantNames: map[string]want{"X": {action: ActionIgnored}},
		},
		{
			name:      "only per-repo.managed",
			repoMan:   []string{"X"},
			wantNames: map[string]want{"X": {action: ActionManaged}},
		},
		{
			name:      "only per-repo.ignored",
			repoIg:    []string{"X"},
			wantNames: map[string]want{"X": {action: ActionIgnored}},
		},
		{
			name:    "per-repo.managed overrides all-repos.managed",
			allMan:  []string{"X"},
			repoMan: []string{"X"},
			wantNames: map[string]want{
				"X": {action: ActionManaged, overridesAllRepos: true},
			},
		},
		{
			name:      "per-repo.ignored shields all-repos.managed",
			allMan:    []string{"X"},
			repoIg:    []string{"X"},
			wantNames: map[string]want{"X": {action: ActionIgnored}},
		},
		{
			name:      "per-repo.managed overrides all-repos.ignored",
			allIg:     []string{"X"},
			repoMan:   []string{"X"},
			wantNames: map[string]want{"X": {action: ActionManaged}},
		},
		{
			name:      "per-repo.ignored absorbs all-repos.ignored",
			allIg:     []string{"X"},
			repoIg:    []string{"X"},
			wantNames: map[string]want{"X": {action: ActionIgnored}},
		},
		{
			name:    "disjoint names from each layer all surface",
			allMan:  []string{"A_M"},
			allIg:   []string{"A_I"},
			repoMan: []string{"R_M"},
			repoIg:  []string{"R_I"},
			wantNames: map[string]want{
				"A_M": {action: ActionManaged, fromAllRepos: true},
				"A_I": {action: ActionIgnored},
				"R_M": {action: ActionManaged},
				"R_I": {action: ActionIgnored},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			allRepos := buildRepo(tc.allMan, tc.allIg, "all")
			perRepo := buildRepo(tc.repoMan, tc.repoIg, "repo")

			intents := ForRepoCascade("acme", allRepos, perRepo)
			byName := map[string]Intent{}
			for _, in := range intents {
				if in.Kind != KindVar {
					continue
				}
				byName[in.Name] = in
			}
			if len(byName) != len(tc.wantNames) {
				t.Fatalf("intent count: got %d want %d (intents=%+v)",
					len(byName), len(tc.wantNames), intents)
			}
			for name, w := range tc.wantNames {
				got, ok := byName[name]
				if !ok {
					t.Fatalf("intent for %s missing; got=%+v", name, byName)
				}
				if got.Action != w.action {
					t.Errorf("%s action: got %s want %s", name, got.Action, w.action)
				}
				if got.OverridesAllRepos != w.overridesAllRepos {
					t.Errorf("%s overrides: got %v want %v",
						name, got.OverridesAllRepos, w.overridesAllRepos)
				}
				if w.action == ActionManaged {
					if got.Entry == nil {
						t.Errorf("%s: managed intent should have entry", name)
					} else {
						wantPrefix := "repo-"
						if w.fromAllRepos {
							wantPrefix = "all-"
						}
						wantVal := wantPrefix + name + "-val"
						if got.Entry.Value != wantVal {
							t.Errorf("%s: entry value got %q want %q",
								name, got.Entry.Value, wantVal)
						}
					}
				}
				if w.action == ActionIgnored && got.Entry != nil {
					t.Errorf("%s: ignored intent must have nil entry", name)
				}
			}
		})
	}
}

// TestForRepoCascade_PerKindIsolation asserts that the same name in different
// kinds doesn't interfere across kinds — the cascade is per (kind, name).
func TestForRepoCascade_PerKindIsolation(t *testing.T) {
	t.Parallel()
	allRepos := &config.Repo{
		Managed: config.Managed{
			Vars:    map[string]*config.Entry{"X": {HasValue: true, Value: "vars-all"}},
			Secrets: map[string]*config.Entry{"X": {HasValue: true, Value: "sec-all"}},
		},
	}
	perRepo := &config.Repo{
		Ignored: config.Ignored{Vars: []string{"X"}},
	}
	intents := ForRepoCascade("acme", allRepos, perRepo)
	var sawIgnoredVar, sawManagedSecret bool
	for _, in := range intents {
		if in.Kind == KindVar && in.Name == "X" && in.Action == ActionIgnored {
			sawIgnoredVar = true
		}
		if in.Kind == KindSecret && in.Name == "X" && in.Action == ActionManaged {
			sawManagedSecret = true
			if in.Entry == nil || in.Entry.Value != "sec-all" {
				t.Errorf("secret X should resolve to all-repos entry; got %+v", in.Entry)
			}
		}
	}
	if !sawIgnoredVar {
		t.Errorf("vars/X should be ignored (per-repo.Ignored shields all-repos.managed)")
	}
	if !sawManagedSecret {
		t.Errorf("secrets/X should be managed from all-repos (per-repo doesn't reference it)")
	}
}

func TestForRepoCascade_NilArguments(t *testing.T) {
	t.Parallel()
	if intents := ForRepoCascade("acme", nil, nil); len(intents) != 0 {
		t.Errorf("expected no intents from nil-nil; got %d", len(intents))
	}
}

func TestEffectiveIgnored(t *testing.T) {
	t.Parallel()
	allRepos := &config.Repo{
		Ignored: config.Ignored{
			Vars:       []string{"AV"},
			Secrets:    []string{"AS"},
			Dependabot: []string{"AD"},
		},
		Managed: config.Managed{
			Vars: map[string]*config.Entry{"OV": {HasValue: true, Value: "x"}},
		},
	}
	perRepo := &config.Repo{
		Ignored: config.Ignored{Vars: []string{"PV"}},
		Managed: config.Managed{
			// per-repo.managed must not appear as ignored even if all-repos says so.
			Vars: map[string]*config.Entry{"AV": {HasValue: true, Value: "y"}},
		},
	}
	got := EffectiveIgnored(allRepos, perRepo)
	if !sortedEqual(got.Vars, []string{"PV"}) {
		t.Errorf("vars ignored: got %v want [PV]", got.Vars)
	}
	if !sortedEqual(got.Secrets, []string{"AS"}) {
		t.Errorf("secrets ignored: got %v want [AS]", got.Secrets)
	}
	if !sortedEqual(got.Dependabot, []string{"AD"}) {
		t.Errorf("dependabot ignored: got %v want [AD]", got.Dependabot)
	}
}

func buildRepo(managed, ignored []string, suffix string) *config.Repo {
	if managed == nil && ignored == nil {
		return nil
	}
	r := &config.Repo{}
	if len(managed) > 0 {
		r.Managed.Vars = map[string]*config.Entry{}
		for _, n := range managed {
			r.Managed.Vars[n] = &config.Entry{HasValue: true, Value: suffix + "-" + n + "-val"}
		}
	}
	if len(ignored) > 0 {
		r.Ignored.Vars = append([]string(nil), ignored...)
	}
	return r
}

func sortedEqual(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	return equal(aa, bb)
}

func TestForOrg(t *testing.T) {
	t.Parallel()
	s := &config.OrgScope{
		Managed: config.OrgManaged{
			Vars: map[string]*config.OrgEntry{
				"V_ALL": {
					Entry:      &config.Entry{Name: "V_ALL", HasValue: true, Value: "vall"},
					Visibility: "all",
				},
				"V_SEL": {
					Entry:      &config.Entry{Name: "V_SEL", HasValue: true, Value: "vsel"},
					Visibility: "selected",
					Repos:      []string{"r1", "r2"},
				},
			},
			Secrets: map[string]*config.OrgEntry{
				"S_PRIV": {
					Entry:      &config.Entry{Name: "S_PRIV", HasValue: true, Value: "x"},
					Visibility: "private",
				},
			},
			Dependabot: map[string]*config.OrgEntry{
				"D1": {
					Entry:      &config.Entry{Name: "D1", HasValue: true, Value: "d"},
					Visibility: "all",
				},
			},
		},
		Ignored: config.Ignored{
			Vars:       []string{"IGV"},
			Secrets:    []string{"IGS"},
			Dependabot: []string{"IGD"},
		},
	}
	intents := ForOrg(s)

	// Org intents must be distinct from repo intents: IsOrg=true, Repo="".
	for _, in := range intents {
		if !in.IsOrg {
			t.Errorf("expected IsOrg=true on %+v", in)
		}
		if in.Repo != "" {
			t.Errorf("expected empty Repo on %+v", in)
		}
	}

	byName := map[string]Intent{}
	for _, in := range intents {
		byName[string(in.Kind)+"/"+in.Name] = in
	}
	if got := byName["vars/V_ALL"]; got.Visibility != "all" || got.Action != ActionManaged {
		t.Errorf("V_ALL intent: %+v", got)
	}
	sel := byName["vars/V_SEL"]
	if sel.Visibility != "selected" || !equal(sel.SelectedRepos, []string{"r1", "r2"}) {
		t.Errorf("V_SEL intent: %+v", sel)
	}
	if got := byName["secrets/S_PRIV"]; got.Visibility != "private" {
		t.Errorf("S_PRIV visibility: %q", got.Visibility)
	}
	if got := byName["vars/IGV"]; got.Action != ActionIgnored {
		t.Errorf("IGV should be ignored: %+v", got)
	}
	if got := byName["dependabot/D1"]; got.Entry == nil || got.Entry.Value != "d" {
		t.Errorf("D1 entry wrong: %+v", got)
	}
}

func TestForOrg_NilOrEmpty(t *testing.T) {
	t.Parallel()
	if intents := ForOrg(nil); len(intents) != 0 {
		t.Errorf("nil OrgScope: got %d intents", len(intents))
	}
	if intents := ForOrg(&config.OrgScope{}); len(intents) != 0 {
		t.Errorf("empty OrgScope: got %d intents", len(intents))
	}
}

func TestEffectiveOrgIgnored(t *testing.T) {
	t.Parallel()
	if got := EffectiveOrgIgnored(nil); len(got.Vars)+len(got.Secrets)+len(got.Dependabot) != 0 {
		t.Errorf("nil scope should produce empty ignored: %+v", got)
	}
	s := &config.OrgScope{Ignored: config.Ignored{
		Vars:       []string{"V"},
		Secrets:    []string{"S"},
		Dependabot: []string{"D"},
	}}
	got := EffectiveOrgIgnored(s)
	if !equal(got.Vars, []string{"V"}) || !equal(got.Secrets, []string{"S"}) || !equal(got.Dependabot, []string{"D"}) {
		t.Errorf("got %+v", got)
	}
}

func TestForOrg_DistinctFromRepoIntents(t *testing.T) {
	t.Parallel()
	// Same name X on org-level vars and on repo-level vars must produce two
	// intents that don't collide: one with IsOrg=true, one with IsOrg=false.
	s := &config.OrgScope{
		Managed: config.OrgManaged{
			Vars: map[string]*config.OrgEntry{"X": {
				Entry: &config.Entry{Name: "X", HasValue: true, Value: "org-x"}, Visibility: "all",
			}},
		},
	}
	repo := &config.Repo{
		Managed: config.Managed{
			Vars: map[string]*config.Entry{"X": {Name: "X", HasValue: true, Value: "repo-x"}},
		},
	}
	orgIntents := ForOrg(s)
	repoIntents := ForRepo("acme", repo)
	if len(orgIntents) != 1 || !orgIntents[0].IsOrg {
		t.Fatalf("org intents wrong: %+v", orgIntents)
	}
	if len(repoIntents) != 1 || repoIntents[0].IsOrg {
		t.Fatalf("repo intents wrong: %+v", repoIntents)
	}
	if orgIntents[0].Entry.Value == repoIntents[0].Entry.Value {
		t.Errorf("entries should be distinct; got same value %q", orgIntents[0].Entry.Value)
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
	return slices.Equal(a, b)
}
