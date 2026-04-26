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

// Result reports the outcome of a single-repo run.
//
// Drift is set by AuditRepo. Failed counts per-entry write failures during
// ApplyRepo (and could be repurposed for enforce later).
type Result struct {
	Drift  bool
	Failed int
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

// ApplyRepo writes managed values for a single repo. It never deletes and
// never touches anything outside the repo's `managed` block. A per-entry
// "ok" or "FAILED: <err>" line is written for each managed entry; a final
// summary line is written if any entry failed.
//
// The repo's Actions and Dependabot public keys are fetched at most once
// per call (only when the corresponding section has at least one entry)
// and reused across all set calls.
func ApplyRepo(ctx context.Context, cfg *config.Config, org, repo string, backend gh.Backend, out io.Writer) (Result, error) {
	o, ok := cfg.Org(org)
	if !ok {
		return Result{}, fmt.Errorf("org %q not found in config", org)
	}
	r, ok := o.PerRepo[repo]
	if !ok {
		return Result{}, fmt.Errorf("repo %q not found under org %q", repo, org)
	}

	intents := plan.ForRepo(repo, r)
	resolved, err := resolveAll(intents)
	if err != nil {
		return Result{}, err
	}

	actionsKey, depKey, err := fetchKeys(ctx, backend, org, repo, intents)
	if err != nil {
		return Result{}, err
	}

	fmt.Fprintf(out, "org: %s\nrepo: %s\n", org, repo)
	res := Result{}
	for _, in := range intents {
		err := applyOne(ctx, backend, org, repo, in, resolved[entryKey(in)], actionsKey, depKey)
		if err != nil {
			res.Failed++
			fmt.Fprintf(out, "  %s/%s: FAILED: %v\n", in.Kind, in.Name, err)
			continue
		}
		fmt.Fprintf(out, "  %s/%s: ok\n", in.Kind, in.Name)
	}
	if res.Failed > 0 {
		fmt.Fprintf(out, "summary: %d failed\n", res.Failed)
	}
	return res, nil
}

func applyOne(ctx context.Context, backend gh.Backend, org, repo string, in plan.Intent, value string, actionsKey, depKey *gh.PublicKey) error {
	switch in.Kind {
	case plan.KindVar:
		return backend.SetRepoVariable(ctx, org, repo, in.Name, value)
	case plan.KindSecret:
		return backend.SetRepoSecret(ctx, org, repo, in.Name, actionsKey, value)
	case plan.KindDependabot:
		return backend.SetRepoDependabotSecret(ctx, org, repo, in.Name, depKey, value)
	}
	return fmt.Errorf("unknown kind %q", in.Kind)
}

func resolveAll(intents []plan.Intent) (map[string]string, error) {
	out := map[string]string{}
	for _, in := range intents {
		v, err := resolve.Resolve(in.Entry)
		if err != nil {
			return nil, fmt.Errorf("resolve %s/%s: %w", in.Kind, in.Name, err)
		}
		out[entryKey(in)] = v
	}
	return out, nil
}

func entryKey(in plan.Intent) string { return string(in.Kind) + "/" + in.Name }

func fetchKeys(ctx context.Context, backend gh.Backend, org, repo string, intents []plan.Intent) (actions, dependabot *gh.PublicKey, err error) {
	needsActions, needsDep := false, false
	for _, in := range intents {
		switch in.Kind {
		case plan.KindSecret:
			needsActions = true
		case plan.KindDependabot:
			needsDep = true
		}
	}
	if needsActions {
		actions, err = backend.GetRepoPublicKey(ctx, org, repo)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch actions public key: %w", err)
		}
	}
	if needsDep {
		dependabot, err = backend.GetRepoDependabotPublicKey(ctx, org, repo)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch dependabot public key: %w", err)
		}
	}
	return actions, dependabot, nil
}

// writeFile is a thin wrapper used by tests to materialize fixture YAML.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
