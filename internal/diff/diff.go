// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package diff compares planned intents against observed live state.
package diff

import (
	"slices"
	"sort"

	"github.com/schmidtw/ghsecretman/internal/config"
	"github.com/schmidtw/ghsecretman/internal/plan"
)

// Status names a per-entry result.
type Status string

const (
	Match    Status = "match"    // vars: desired == live
	Mismatch Status = "mismatch" // vars: desired != live
	Present  Status = "present"  // secrets/dependabot: name exists on github
	Missing  Status = "missing"  // intent name absent on github
	Extra    Status = "extra"    // on github, not in YAML, not ignored
	Ignored  Status = "ignored"  // on github and explicitly ignored
)

// Override records that an entry's effective layer differs from the
// all-repos default — used by audit to surface layered drift.
type Override string

const (
	// OverrideNone is the zero value: no cascade override applies.
	OverrideNone Override = ""
	// OverrideManaged indicates a per-repo.managed entry shadowed an
	// all-repos.managed entry of the same name.
	OverrideManaged Override = "managed"
	// OverrideIgnored indicates a per-repo.ignored entry shielded an
	// all-repos.managed entry of the same name.
	OverrideIgnored Override = "ignored"
)

// Live captures observed state for a single repo.
//
// Vars is name → value because the GitHub API returns variable values.
// Secrets and Dependabot list names only — values are never exposed.
type Live struct {
	Vars       map[string]string
	Secrets    []string
	Dependabot []string
}

// Entry is one diff result row.
type Entry struct {
	Repo         string
	Kind         plan.Kind
	Name         string
	Status       Status
	DesiredValue string // populated for Mismatch on vars
	LiveValue    string // populated for Mismatch on vars

	// Override is non-empty when this entry resolved through a cross-layer
	// override:
	//   - OverrideManaged: per-repo.managed shadowed all-repos.managed.
	//   - OverrideIgnored: per-repo.ignored shielded all-repos.managed.
	// In both cases the implicit layer pair is per-repo over all-repos.
	Override Override
}

// Compute produces diff entries for a single repo.
//
// desiredVars maps variable name → resolved desired value. Pass nil if no
// vars are intended.
func Compute(repo string, intents []plan.Intent, desiredVars map[string]string, live Live, ignored config.Ignored) []Entry {
	vars := computeVars(repo, intents, desiredVars, live, ignored)
	secrets := computeNames(repo, plan.KindSecret, intents, live.Secrets, ignored.Secrets)
	deps := computeNames(repo, plan.KindDependabot, intents, live.Dependabot, ignored.Dependabot)
	out := make([]Entry, 0, len(vars)+len(secrets)+len(deps))
	out = append(out, vars...)
	out = append(out, secrets...)
	out = append(out, deps...)
	return out
}

func computeVars(repo string, intents []plan.Intent, desiredVars map[string]string, live Live, ignored config.Ignored) []Entry {
	intended := map[string]struct{}{}
	managedOverride := map[string]struct{}{}
	ignoredShield := map[string]struct{}{}
	out := make([]Entry, 0)
	intentNames := make([]string, 0)
	for _, in := range intents {
		if in.Kind != plan.KindVar {
			continue
		}
		switch in.Action {
		case plan.ActionManaged:
			intended[in.Name] = struct{}{}
			intentNames = append(intentNames, in.Name)
			if in.OverridesAllRepos {
				managedOverride[in.Name] = struct{}{}
			}
		case plan.ActionIgnored:
			if in.ShieldsAllReposManaged {
				ignoredShield[in.Name] = struct{}{}
			}
		}
	}
	sort.Strings(intentNames)

	for _, name := range intentNames {
		desired := desiredVars[name]
		e := Entry{Repo: repo, Kind: plan.KindVar, Name: name}
		if _, ok := managedOverride[name]; ok {
			e.Override = OverrideManaged
		}
		if liveVal, ok := live.Vars[name]; ok {
			e.Status = Match
			if liveVal != desired {
				e.Status = Mismatch
				e.DesiredValue = desired
				e.LiveValue = liveVal
			}
		} else {
			e.Status = Missing
		}
		out = append(out, e)
	}

	liveNames := make([]string, 0, len(live.Vars))
	for n := range live.Vars {
		liveNames = append(liveNames, n)
	}
	sort.Strings(liveNames)
	emittedShield := map[string]struct{}{}
	for _, name := range liveNames {
		if _, ok := intended[name]; ok {
			continue
		}
		e := Entry{Repo: repo, Kind: plan.KindVar, Name: name, Status: Extra}
		if slices.Contains(ignored.Vars, name) {
			e.Status = Ignored
			if _, shielded := ignoredShield[name]; shielded {
				e.Override = OverrideIgnored
				emittedShield[name] = struct{}{}
			}
		}
		out = append(out, e)
	}
	// Emit shield-override rows for names that were not on the live target.
	// The override is a configuration-level fact (per-repo.ignored shielded
	// all-repos.managed) and is meaningful regardless of live presence.
	shieldNames := make([]string, 0)
	for name := range ignoredShield {
		if _, ok := emittedShield[name]; ok {
			continue
		}
		shieldNames = append(shieldNames, name)
	}
	sort.Strings(shieldNames)
	for _, name := range shieldNames {
		out = append(out, Entry{
			Repo:     repo,
			Kind:     plan.KindVar,
			Name:     name,
			Status:   Ignored,
			Override: OverrideIgnored,
		})
	}
	return out
}

func computeNames(repo string, kind plan.Kind, intents []plan.Intent, liveNames []string, ignored []string) []Entry {
	intended := map[string]struct{}{}
	managedOverride := map[string]struct{}{}
	ignoredShield := map[string]struct{}{}
	out := make([]Entry, 0)
	intentNames := make([]string, 0)
	for _, in := range intents {
		if in.Kind != kind {
			continue
		}
		switch in.Action {
		case plan.ActionManaged:
			intended[in.Name] = struct{}{}
			intentNames = append(intentNames, in.Name)
			if in.OverridesAllRepos {
				managedOverride[in.Name] = struct{}{}
			}
		case plan.ActionIgnored:
			if in.ShieldsAllReposManaged {
				ignoredShield[in.Name] = struct{}{}
			}
		}
	}
	sort.Strings(intentNames)
	liveSet := map[string]struct{}{}
	for _, n := range liveNames {
		liveSet[n] = struct{}{}
	}

	for _, name := range intentNames {
		e := Entry{Repo: repo, Kind: kind, Name: name}
		if _, ok := managedOverride[name]; ok {
			e.Override = OverrideManaged
		}
		if _, ok := liveSet[name]; ok {
			e.Status = Present
		} else {
			e.Status = Missing
		}
		out = append(out, e)
	}
	sortedLive := append([]string(nil), liveNames...)
	sort.Strings(sortedLive)
	emittedShield := map[string]struct{}{}
	for _, name := range sortedLive {
		if _, ok := intended[name]; ok {
			continue
		}
		e := Entry{Repo: repo, Kind: kind, Name: name, Status: Extra}
		if slices.Contains(ignored, name) {
			e.Status = Ignored
			if _, shielded := ignoredShield[name]; shielded {
				e.Override = OverrideIgnored
				emittedShield[name] = struct{}{}
			}
		}
		out = append(out, e)
	}
	shieldNames := make([]string, 0)
	for name := range ignoredShield {
		if _, ok := emittedShield[name]; ok {
			continue
		}
		shieldNames = append(shieldNames, name)
	}
	sort.Strings(shieldNames)
	for _, name := range shieldNames {
		out = append(out, Entry{
			Repo:     repo,
			Kind:     kind,
			Name:     name,
			Status:   Ignored,
			Override: OverrideIgnored,
		})
	}
	return out
}

// HasDrift reports whether any entry represents a state needing action.
//
// Match, Present, and Ignored are clean; everything else is drift.
func HasDrift(entries []Entry) bool {
	for _, e := range entries {
		switch e.Status {
		case Match, Present, Ignored:
			continue
		default:
			return true
		}
	}
	return false
}
