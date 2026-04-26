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
	out := make([]Entry, 0)
	intentNames := make([]string, 0)
	for _, in := range intents {
		if in.Kind != plan.KindVar {
			continue
		}
		intended[in.Name] = struct{}{}
		intentNames = append(intentNames, in.Name)
	}
	sort.Strings(intentNames)

	for _, name := range intentNames {
		desired := desiredVars[name]
		if liveVal, ok := live.Vars[name]; ok {
			status := Match
			e := Entry{Repo: repo, Kind: plan.KindVar, Name: name, Status: status}
			if liveVal != desired {
				e.Status = Mismatch
				e.DesiredValue = desired
				e.LiveValue = liveVal
			}
			out = append(out, e)
		} else {
			out = append(out, Entry{Repo: repo, Kind: plan.KindVar, Name: name, Status: Missing})
		}
	}

	liveNames := make([]string, 0, len(live.Vars))
	for n := range live.Vars {
		liveNames = append(liveNames, n)
	}
	sort.Strings(liveNames)
	for _, name := range liveNames {
		if _, ok := intended[name]; ok {
			continue
		}
		status := Extra
		if slices.Contains(ignored.Vars, name) {
			status = Ignored
		}
		out = append(out, Entry{Repo: repo, Kind: plan.KindVar, Name: name, Status: status})
	}
	return out
}

func computeNames(repo string, kind plan.Kind, intents []plan.Intent, liveNames []string, ignored []string) []Entry {
	intended := map[string]struct{}{}
	out := make([]Entry, 0)
	intentNames := make([]string, 0)
	for _, in := range intents {
		if in.Kind != kind {
			continue
		}
		intended[in.Name] = struct{}{}
		intentNames = append(intentNames, in.Name)
	}
	sort.Strings(intentNames)
	liveSet := map[string]struct{}{}
	for _, n := range liveNames {
		liveSet[n] = struct{}{}
	}

	for _, name := range intentNames {
		if _, ok := liveSet[name]; ok {
			out = append(out, Entry{Repo: repo, Kind: kind, Name: name, Status: Present})
		} else {
			out = append(out, Entry{Repo: repo, Kind: kind, Name: name, Status: Missing})
		}
	}
	sortedLive := append([]string(nil), liveNames...)
	sort.Strings(sortedLive)
	for _, name := range sortedLive {
		if _, ok := intended[name]; ok {
			continue
		}
		status := Extra
		if slices.Contains(ignored, name) {
			status = Ignored
		}
		out = append(out, Entry{Repo: repo, Kind: kind, Name: name, Status: status})
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
