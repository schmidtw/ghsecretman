// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package runner orchestrates an audit pass against a single repo. It
// resolves desired values, fetches live state through the github backend,
// invokes the diff engine, and writes a structured per-repo stanza.
package runner

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/schmidtw/ghsecretman/internal/config"
	"github.com/schmidtw/ghsecretman/internal/diff"
	gh "github.com/schmidtw/ghsecretman/internal/github"
	"github.com/schmidtw/ghsecretman/internal/plan"
	"github.com/schmidtw/ghsecretman/internal/resolve"
)

// Result reports the outcome of a single-repo audit.
type Result struct {
	Drift bool
}

// AuditRepo runs an audit against a single repo and writes a labeled
// stanza to out. showIgnored controls whether ignored entries appear.
func AuditRepo(ctx context.Context, cfg *config.Config, org, repo string, backend gh.Backend, out io.Writer, showIgnored bool) (Result, error) {
	o, ok := cfg.Org(org)
	if !ok {
		return Result{}, fmt.Errorf("org %q not found in config", org)
	}
	r, ok := o.PerRepo[repo]
	if !ok {
		return Result{}, fmt.Errorf("repo %q not found under org %q", repo, org)
	}

	intents := plan.ForRepo(repo, r)

	desiredVars, err := resolveVars(intents)
	if err != nil {
		return Result{}, err
	}

	live, err := fetchLive(ctx, backend, org, repo)
	if err != nil {
		return Result{}, err
	}

	entries := diff.Compute(repo, intents, desiredVars, live, r.Ignored)
	writeStanza(out, org, repo, entries, showIgnored)

	return Result{Drift: diff.HasDrift(entries)}, nil
}

func resolveVars(intents []plan.Intent) (map[string]string, error) {
	out := map[string]string{}
	for _, in := range intents {
		if in.Kind != plan.KindVar {
			continue
		}
		v, err := resolve.Resolve(in.Entry)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", in.Name, err)
		}
		out[in.Name] = v
	}
	return out, nil
}

func fetchLive(ctx context.Context, backend gh.Backend, org, repo string) (diff.Live, error) {
	vars, err := backend.ListRepoVariables(ctx, org, repo)
	if err != nil {
		return diff.Live{}, err
	}
	secrets, err := backend.ListRepoSecrets(ctx, org, repo)
	if err != nil {
		return diff.Live{}, err
	}
	dependabot, err := backend.ListRepoDependabotSecrets(ctx, org, repo)
	if err != nil {
		return diff.Live{}, err
	}
	return diff.Live{Vars: vars, Secrets: secrets, Dependabot: dependabot}, nil
}

func writeStanza(out io.Writer, org, repo string, entries []diff.Entry, showIgnored bool) {
	fmt.Fprintf(out, "org: %s\nrepo: %s\n", org, repo)
	for _, e := range entries {
		if e.Status == diff.Ignored && !showIgnored {
			continue
		}
		switch e.Status {
		case diff.Mismatch:
			fmt.Fprintf(out, "  %s/%s: mismatch (yaml=%q live=%q)\n", e.Kind, e.Name, e.DesiredValue, e.LiveValue)
		default:
			fmt.Fprintf(out, "  %s/%s: %s\n", e.Kind, e.Name, e.Status)
		}
	}
}

// writeFile is a thin wrapper used by tests to materialize fixture YAML.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
