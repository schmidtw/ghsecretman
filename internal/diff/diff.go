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

// intentSets summarizes managed and ignored intents for one kind into the
// lookup maps the diff loops need.
type intentSets struct {
	intended        map[string]struct{}
	intentNames     []string
	managedOverride map[string]struct{}
	ignoredShield   map[string]struct{}
}

func collectIntents(intents []plan.Intent, kind plan.Kind) intentSets {
	s := intentSets{
		intended:        map[string]struct{}{},
		managedOverride: map[string]struct{}{},
		ignoredShield:   map[string]struct{}{},
		intentNames:     make([]string, 0),
	}
	for _, in := range intents {
		if in.Kind != kind {
			continue
		}
		switch in.Action {
		case plan.ActionManaged:
			s.intended[in.Name] = struct{}{}
			s.intentNames = append(s.intentNames, in.Name)
			if in.OverridesAllRepos {
				s.managedOverride[in.Name] = struct{}{}
			}
		case plan.ActionIgnored:
			if in.ShieldsAllReposManaged {
				s.ignoredShield[in.Name] = struct{}{}
			}
		}
	}
	sort.Strings(s.intentNames)
	return s
}

// shieldOnlyNames returns ignored-shield names that have not yet been
// emitted via the live-state pass; these still need rows because the
// override is a configuration-level fact.
func shieldOnlyNames(shields, emitted map[string]struct{}) []string {
	out := make([]string, 0)
	for name := range shields {
		if _, ok := emitted[name]; ok {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func computeVars(repo string, intents []plan.Intent, desiredVars map[string]string, live Live, ignored config.Ignored) []Entry {
	s := collectIntents(intents, plan.KindVar)
	out := make([]Entry, 0)

	for _, name := range s.intentNames {
		out = append(out, varEntry(repo, name, desiredVars[name], live.Vars, s.managedOverride))
	}

	liveNames := sortedKeys(live.Vars)
	emittedShield := map[string]struct{}{}
	for _, name := range liveNames {
		if _, ok := s.intended[name]; ok {
			continue
		}
		out = append(out, extraVarEntry(repo, name, ignored.Vars, s.ignoredShield, emittedShield))
	}
	for _, name := range shieldOnlyNames(s.ignoredShield, emittedShield) {
		out = append(out, Entry{Repo: repo, Kind: plan.KindVar, Name: name, Status: Ignored, Override: OverrideIgnored})
	}
	return out
}

func varEntry(repo, name, desired string, liveVars map[string]string, managedOverride map[string]struct{}) Entry {
	e := Entry{Repo: repo, Kind: plan.KindVar, Name: name}
	if _, ok := managedOverride[name]; ok {
		e.Override = OverrideManaged
	}
	if liveVal, ok := liveVars[name]; ok {
		e.Status = Match
		if liveVal != desired {
			e.Status = Mismatch
			e.DesiredValue = desired
			e.LiveValue = liveVal
		}
	} else {
		e.Status = Missing
	}
	return e
}

func extraVarEntry(repo, name string, ignored []string, shield, emitted map[string]struct{}) Entry {
	e := Entry{Repo: repo, Kind: plan.KindVar, Name: name, Status: Extra}
	if !slices.Contains(ignored, name) {
		return e
	}
	e.Status = Ignored
	if _, shielded := shield[name]; shielded {
		e.Override = OverrideIgnored
		emitted[name] = struct{}{}
	}
	return e
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func computeNames(repo string, kind plan.Kind, intents []plan.Intent, liveNames []string, ignored []string) []Entry {
	s := collectIntents(intents, kind)
	out := make([]Entry, 0)
	liveSet := map[string]struct{}{}
	for _, n := range liveNames {
		liveSet[n] = struct{}{}
	}

	for _, name := range s.intentNames {
		out = append(out, nameEntry(repo, kind, name, liveSet, s.managedOverride))
	}
	sortedLive := append([]string(nil), liveNames...)
	sort.Strings(sortedLive)
	emittedShield := map[string]struct{}{}
	for _, name := range sortedLive {
		if _, ok := s.intended[name]; ok {
			continue
		}
		out = append(out, extraNameEntry(repo, kind, name, ignored, s.ignoredShield, emittedShield))
	}
	for _, name := range shieldOnlyNames(s.ignoredShield, emittedShield) {
		out = append(out, Entry{Repo: repo, Kind: kind, Name: name, Status: Ignored, Override: OverrideIgnored})
	}
	return out
}

func nameEntry(repo string, kind plan.Kind, name string, liveSet, managedOverride map[string]struct{}) Entry {
	e := Entry{Repo: repo, Kind: kind, Name: name}
	if _, ok := managedOverride[name]; ok {
		e.Override = OverrideManaged
	}
	if _, ok := liveSet[name]; ok {
		e.Status = Present
	} else {
		e.Status = Missing
	}
	return e
}

func extraNameEntry(repo string, kind plan.Kind, name string, ignored []string, shield, emitted map[string]struct{}) Entry {
	e := Entry{Repo: repo, Kind: kind, Name: name, Status: Extra}
	if !slices.Contains(ignored, name) {
		return e
	}
	e.Status = Ignored
	if _, shielded := shield[name]; shielded {
		e.Override = OverrideIgnored
		emitted[name] = struct{}{}
	}
	return e
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
