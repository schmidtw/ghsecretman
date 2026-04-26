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
		if in.Kind != plan.KindVar || in.Action != plan.ActionManaged {
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
		if in.Action != plan.ActionManaged {
			continue
		}
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
		if in.Action != plan.ActionManaged {
			continue
		}
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
		if in.Action != plan.ActionManaged {
			continue
		}
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

// EnforceOptions controls EnforceRepo behavior.
type EnforceOptions struct {
	// DryRun prints planned set/delete actions and makes zero write API
	// calls. The public-key fetch and value resolution are also skipped
	// since neither is needed without a real write.
	DryRun bool

	// Confirm, if non-nil and DryRun is false, is invoked after the live
	// state has been fetched and the extras list computed. The argument
	// is a list of "kind/name" strings, one per planned deletion. If
	// Confirm returns false, no writes or deletes are performed and
	// Result is the zero value. Confirm is ignored when DryRun is true.
	Confirm func(extras []string) bool
}

// EnforceRepo applies managed values and then deletes any "extra" entries
// — entries present on the repo but not listed in either the managed or
// ignored block. With DryRun=true, it prints intended set/delete lines
// without calling any write API.
//
// The TTY/--yes confirmation contract is owned by the CLI layer; by the
// time EnforceRepo is called, the caller has already decided to proceed.
func EnforceRepo(ctx context.Context, cfg *config.Config, org, repo string, backend gh.Backend, out io.Writer, opts EnforceOptions) (Result, error) {
	o, ok := cfg.Org(org)
	if !ok {
		return Result{}, fmt.Errorf("org %q not found in config", org)
	}
	r, ok := o.PerRepo[repo]
	if !ok {
		return Result{}, fmt.Errorf("repo %q not found under org %q", repo, org)
	}

	intents := plan.ForRepo(repo, r)

	resolved, err := resolveForEnforce(intents, opts.DryRun)
	if err != nil {
		return Result{}, err
	}

	live, err := fetchLive(ctx, backend, org, repo)
	if err != nil {
		return Result{}, err
	}
	entries := diff.Compute(repo, intents, desiredVarsFromResolved(intents, resolved), live, r.Ignored)

	if !opts.DryRun && opts.Confirm != nil && !opts.Confirm(extraKindNames(entries)) {
		return Result{}, nil
	}

	actionsKey, depKey, err := keysForEnforce(ctx, backend, org, repo, intents, opts.DryRun)
	if err != nil {
		return Result{}, err
	}

	fmt.Fprintf(out, "org: %s\nrepo: %s\n", org, repo)
	res := Result{}
	res.Failed += runApplyPhase(ctx, backend, org, repo, intents, resolved, actionsKey, depKey, out, opts.DryRun)
	res.Failed += runDeletePhase(ctx, backend, org, repo, entries, out, opts.DryRun)
	if res.Failed > 0 {
		fmt.Fprintf(out, "summary: %d failed\n", res.Failed)
	}
	return res, nil
}

func resolveForEnforce(intents []plan.Intent, dryRun bool) (map[string]string, error) {
	if dryRun {
		return nil, nil
	}
	return resolveAll(intents)
}

func keysForEnforce(ctx context.Context, backend gh.Backend, org, repo string, intents []plan.Intent, dryRun bool) (*gh.PublicKey, *gh.PublicKey, error) {
	if dryRun {
		return nil, nil, nil
	}
	return fetchKeys(ctx, backend, org, repo, intents)
}

func desiredVarsFromResolved(intents []plan.Intent, resolved map[string]string) map[string]string {
	out := map[string]string{}
	for _, in := range intents {
		if in.Kind == plan.KindVar && in.Action == plan.ActionManaged {
			out[in.Name] = resolved[entryKey(in)]
		}
	}
	return out
}

func extraKindNames(entries []diff.Entry) []string {
	out := make([]string, 0)
	for _, e := range entries {
		if e.Status == diff.Extra {
			out = append(out, fmt.Sprintf("%s/%s", e.Kind, e.Name))
		}
	}
	return out
}

func runApplyPhase(ctx context.Context, backend gh.Backend, org, repo string, intents []plan.Intent, resolved map[string]string, actionsKey, depKey *gh.PublicKey, out io.Writer, dryRun bool) int {
	failed := 0
	for _, in := range intents {
		if in.Action != plan.ActionManaged {
			continue
		}
		if dryRun {
			fmt.Fprintf(out, "  %s/%s: would-set\n", in.Kind, in.Name)
			continue
		}
		if err := applyOne(ctx, backend, org, repo, in, resolved[entryKey(in)], actionsKey, depKey); err != nil {
			failed++
			fmt.Fprintf(out, "  %s/%s: FAILED: %v\n", in.Kind, in.Name, err)
			continue
		}
		fmt.Fprintf(out, "  %s/%s: ok\n", in.Kind, in.Name)
	}
	return failed
}

func runDeletePhase(ctx context.Context, backend gh.Backend, org, repo string, entries []diff.Entry, out io.Writer, dryRun bool) int {
	failed := 0
	for _, e := range entries {
		if e.Status != diff.Extra {
			continue
		}
		if dryRun {
			fmt.Fprintf(out, "  %s/%s: would-delete\n", e.Kind, e.Name)
			continue
		}
		if err := deleteOne(ctx, backend, org, repo, e.Kind, e.Name); err != nil {
			failed++
			fmt.Fprintf(out, "  %s/%s: FAILED: %v\n", e.Kind, e.Name, err)
			continue
		}
		fmt.Fprintf(out, "  %s/%s: deleted\n", e.Kind, e.Name)
	}
	return failed
}

func deleteOne(ctx context.Context, backend gh.Backend, org, repo string, kind plan.Kind, name string) error {
	switch kind {
	case plan.KindVar:
		return backend.DeleteRepoVariable(ctx, org, repo, name)
	case plan.KindSecret:
		return backend.DeleteRepoSecret(ctx, org, repo, name)
	case plan.KindDependabot:
		return backend.DeleteRepoDependabotSecret(ctx, org, repo, name)
	}
	return fmt.Errorf("unknown kind %q", kind)
}

// writeFile is a thin wrapper used by tests to materialize fixture YAML.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
