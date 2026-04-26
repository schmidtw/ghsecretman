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
)

// Intent is one (target, kind, name) action with its source entry.
type Intent struct {
	Repo   string
	Kind   Kind
	Name   string
	Action Action
	Entry  *config.Entry
}

// ForRepo returns intents for every managed entry on the repo.
//
// Output order is stable: section order vars, secrets, dependabot;
// names sorted within each section.
func ForRepo(repo string, r *config.Repo) []Intent {
	if r == nil {
		return nil
	}
	out := make([]Intent, 0)
	out = appendKind(out, repo, KindVar, r.Managed.Vars)
	out = appendKind(out, repo, KindSecret, r.Managed.Secrets)
	out = appendKind(out, repo, KindDependabot, r.Managed.Dependabot)
	return out
}

func appendKind(out []Intent, repo string, kind Kind, m map[string]*config.Entry) []Intent {
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
