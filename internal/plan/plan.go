// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package plan turns a config model into a flat list of intended actions
// per (target, kind, name).
package plan

import (
	"slices"
	"sort"

	"github.com/schmidtw/ghsecretman/internal/config"
)

// Kind names a GitHub object class.
type Kind string

const (
	KindVar        Kind = "vars"
	KindSecret     Kind = "secrets"
	KindDependabot Kind = "dependabot"
)

// Action describes what the runner intends to do with the entry.
type Action string

const (
	// ActionManaged means the entry is in the managed block — apply/audit
	// against it.
	ActionManaged Action = "managed"
	// ActionIgnored means the name appears in the ignored block at this
	// scope — skip it for both apply and audit-output.
	ActionIgnored Action = "ignored"
)

// Intent is one (target, kind, name) action with its source entry.
type Intent struct {
	Repo   string
	Kind   Kind
	Name   string
	Action Action
	Entry  *config.Entry

	// OverridesAllRepos is true when this intent's name was also present in
	// all-repos.managed and the per-repo entry took precedence. Reserved for
	// audit-side override reporting; runtime behavior is unaffected.
	OverridesAllRepos bool

	// IsOrg distinguishes an org-level intent (different GitHub object class)
	// from a repo-level intent. When true, Repo is empty and the entry is
	// targeted at the named organization.
	IsOrg bool

	// Visibility is the org-level secret/variable visibility envelope and is
	// only meaningful when IsOrg is true. One of "all", "private", "selected".
	Visibility string

	// SelectedRepos is the static list of repo names that may access the
	// entry; only populated when IsOrg && Visibility == "selected".
	SelectedRepos []string
}

// ForRepo returns intents for every managed entry on the repo plus a
// skip-intent for every name in the ignored block.
//
// Output order is stable: section order vars, secrets, dependabot;
// within each section, managed names sorted, then ignored names sorted.
func ForRepo(repo string, r *config.Repo) []Intent {
	if r == nil {
		return nil
	}
	out := make([]Intent, 0)
	out = appendKind(out, repo, KindVar, r.Managed.Vars, r.Ignored.Vars)
	out = appendKind(out, repo, KindSecret, r.Managed.Secrets, r.Ignored.Secrets)
	out = appendKind(out, repo, KindDependabot, r.Managed.Dependabot, r.Ignored.Dependabot)
	return out
}

func appendKind(out []Intent, repo string, kind Kind, m map[string]*config.Entry, ignored []string) []Intent {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, Intent{
			Repo:   repo,
			Kind:   kind,
			Name:   n,
			Action: ActionManaged,
			Entry:  m[n],
		})
	}
	ig := append([]string(nil), ignored...)
	sort.Strings(ig)
	for _, n := range ig {
		out = append(out, Intent{
			Repo:   repo,
			Kind:   kind,
			Name:   n,
			Action: ActionIgnored,
		})
	}
	return out
}

// ForRepoCascade returns intents for one repo after applying the
// per-repo > all-repos precedence rules.
//
// Rules (per kind, per name):
//   - In per-repo.managed → managed (per-repo entry).
//     Marked OverridesAllRepos when the same name was also in all-repos.managed.
//   - In per-repo.ignored → ignored.
//   - In all-repos.managed (and not above) → managed (all-repos entry).
//   - In all-repos.ignored (and not above) → ignored.
func ForRepoCascade(repoName string, allRepos, perRepo *config.Repo) []Intent {
	out := make([]Intent, 0)
	out = appendCascadeKind(out, repoName, KindVar, allRepos, perRepo)
	out = appendCascadeKind(out, repoName, KindSecret, allRepos, perRepo)
	out = appendCascadeKind(out, repoName, KindDependabot, allRepos, perRepo)
	return out
}

type cascadeWinner struct {
	action            Action
	entry             *config.Entry
	overridesAllRepos bool
}

func appendCascadeKind(out []Intent, repo string, kind Kind, allRepos, perRepo *config.Repo) []Intent {
	resolved := resolveCascade(allRepos, perRepo, kind)
	managedNames := make([]string, 0)
	ignoredNames := make([]string, 0)
	for n, w := range resolved {
		if w.action == ActionManaged {
			managedNames = append(managedNames, n)
		} else {
			ignoredNames = append(ignoredNames, n)
		}
	}
	sort.Strings(managedNames)
	sort.Strings(ignoredNames)

	for _, n := range managedNames {
		w := resolved[n]
		out = append(out, Intent{
			Repo: repo, Kind: kind, Name: n,
			Action:            ActionManaged,
			Entry:             w.entry,
			OverridesAllRepos: w.overridesAllRepos,
		})
	}
	for _, n := range ignoredNames {
		out = append(out, Intent{
			Repo: repo, Kind: kind, Name: n,
			Action: ActionIgnored,
		})
	}
	return out
}

func resolveCascade(allRepos, perRepo *config.Repo, kind Kind) map[string]cascadeWinner {
	prMan, prIg := managedFor(perRepo, kind), ignoredFor(perRepo, kind)
	arMan, arIg := managedFor(allRepos, kind), ignoredFor(allRepos, kind)
	prIgSet := stringSet(prIg)
	resolved := map[string]cascadeWinner{}

	for n, e := range prMan {
		w := cascadeWinner{action: ActionManaged, entry: e}
		if _, ok := arMan[n]; ok {
			w.overridesAllRepos = true
		}
		resolved[n] = w
	}
	for _, n := range prIg {
		if _, ok := resolved[n]; ok {
			continue
		}
		resolved[n] = cascadeWinner{action: ActionIgnored}
	}
	for n, e := range arMan {
		if _, ok := resolved[n]; ok {
			continue
		}
		if _, shielded := prIgSet[n]; shielded {
			continue
		}
		resolved[n] = cascadeWinner{action: ActionManaged, entry: e}
	}
	for _, n := range arIg {
		if _, ok := resolved[n]; ok {
			continue
		}
		resolved[n] = cascadeWinner{action: ActionIgnored}
	}
	return resolved
}

func managedFor(r *config.Repo, kind Kind) map[string]*config.Entry {
	if r == nil {
		return nil
	}
	switch kind {
	case KindVar:
		return r.Managed.Vars
	case KindSecret:
		return r.Managed.Secrets
	case KindDependabot:
		return r.Managed.Dependabot
	}
	return nil
}

func ignoredFor(r *config.Repo, kind Kind) []string {
	if r == nil {
		return nil
	}
	switch kind {
	case KindVar:
		return r.Ignored.Vars
	case KindSecret:
		return r.Ignored.Secrets
	case KindDependabot:
		return r.Ignored.Dependabot
	}
	return nil
}

func stringSet(ss []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		out[s] = struct{}{}
	}
	return out
}

// ForOrg returns intents for an org-level scope.
//
// Org intents are a different GitHub object class than repo intents (org
// secrets/vars/dependabot live on the organization, not on a repo) and are
// therefore returned with IsOrg=true and Repo="". The cascade rules between
// per-repo / all-repos / org operate on repo-level objects only — org-scope
// intents do not collide with repo-scope intents.
//
// Output order is stable: section order vars, secrets, dependabot;
// within each section, managed names sorted, then ignored names sorted.
func ForOrg(s *config.OrgScope) []Intent {
	if s == nil {
		return nil
	}
	out := make([]Intent, 0)
	out = appendOrgKind(out, KindVar, s.Managed.Vars, s.Ignored.Vars)
	out = appendOrgKind(out, KindSecret, s.Managed.Secrets, s.Ignored.Secrets)
	out = appendOrgKind(out, KindDependabot, s.Managed.Dependabot, s.Ignored.Dependabot)
	return out
}

func appendOrgKind(out []Intent, kind Kind, m map[string]*config.OrgEntry, ignored []string) []Intent {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		oe := m[n]
		out = append(out, Intent{
			Kind:          kind,
			Name:          n,
			Action:        ActionManaged,
			Entry:         oe.Entry,
			IsOrg:         true,
			Visibility:    oe.Visibility,
			SelectedRepos: append([]string(nil), oe.Repos...),
		})
	}
	ig := append([]string(nil), ignored...)
	sort.Strings(ig)
	for _, n := range ig {
		out = append(out, Intent{
			Kind:   kind,
			Name:   n,
			Action: ActionIgnored,
			IsOrg:  true,
		})
	}
	return out
}

// EffectiveOrgIgnored returns the org-level ignored list (no cascade).
//
// Useful for downstream code that needs an ignored set for marking extras at
// the org scope. Unlike repo-scope ignored, there is no cascade across scope
// classes; org.ignored applies only to the org-level GitHub object.
func EffectiveOrgIgnored(s *config.OrgScope) config.Ignored {
	if s == nil {
		return config.Ignored{}
	}
	return config.Ignored{
		Vars:       append([]string(nil), s.Ignored.Vars...),
		Secrets:    append([]string(nil), s.Ignored.Secrets...),
		Dependabot: append([]string(nil), s.Ignored.Dependabot...),
	}
}

// EffectiveIgnored returns the cascaded ignored list at a single repo.
//
// Useful for downstream code (diff) that needs an ignored set for marking
// extras. A name is effectively ignored when it ends up in an ActionIgnored
// intent under ForRepoCascade.
func EffectiveIgnored(allRepos, perRepo *config.Repo) config.Ignored {
	intents := ForRepoCascade("", allRepos, perRepo)
	var out config.Ignored
	for _, in := range intents {
		if in.Action != ActionIgnored {
			continue
		}
		switch in.Kind {
		case KindVar:
			out.Vars = append(out.Vars, in.Name)
		case KindSecret:
			out.Secrets = append(out.Secrets, in.Name)
		case KindDependabot:
			out.Dependabot = append(out.Dependabot, in.Name)
		}
	}
	return out
}

// IsIgnored reports whether name appears in the repo's ignored list for kind.
func IsIgnored(r *config.Repo, kind Kind, name string) bool {
	if r == nil {
		return false
	}
	var list []string
	switch kind {
	case KindVar:
		list = r.Ignored.Vars
	case KindSecret:
		list = r.Ignored.Secrets
	case KindDependabot:
		list = r.Ignored.Dependabot
	}
	return slices.Contains(list, name)
}
