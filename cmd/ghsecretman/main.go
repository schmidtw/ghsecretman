// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Command ghsecretman manages GitHub secrets, variables, and Dependabot
// secrets across an organization from a YAML configuration file.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/schmidtw/ghsecretman/internal/config"
	gh "github.com/schmidtw/ghsecretman/internal/github"
	"github.com/schmidtw/ghsecretman/internal/runner"
	"github.com/schmidtw/ghsecretman/internal/schema"
)

// version, commit, and date are set at build time via -ldflags
// "-X main.version=<value> -X main.commit=<sha> -X main.date=<rfc3339>".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// backendFactory is overridden in tests to inject a fake backend.
var backendFactory = func() (gh.Backend, error) { return gh.NewClientFromEnv() }

// isTTY reports whether stdin is connected to a terminal. It is a package
// variable so tests can override the answer without manipulating fds.
var isTTY = func() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// stdin is the prompt source. Overridable for tests.
var stdin io.Reader = os.Stdin

func main() {
	os.Exit(run(os.Args, version, os.Stdout, os.Stderr))
}

func run(args []string, ver string, stdout, stderr io.Writer) int {
	if len(args) >= 2 {
		switch args[1] {
		case "audit":
			return runAudit(args[2:], stdout, stderr)
		case "apply":
			return runApply(args[2:], stdout, stderr)
		case "enforce":
			return runEnforce(args[2:], stdout, stderr)
		case "example":
			return runExample(args[2:], stdout, stderr)
		case "version":
			fmt.Fprintf(stdout, "ghsecretman %s\ncommit %s\nbuilt %s\n", ver, commit, date)
			return 0
		case "-h", "--help", "help":
			printUsage(stdout)
			return 0
		}
	}

	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "ghsecretman %s\n", ver)
		return 0
	}

	printUsage(stderr)
	return 2
}

// printUsage writes the top-level help text. It is shown for `-h`, `--help`,
// `help`, and bare invocations.
func printUsage(w io.Writer) {
	fmt.Fprint(w, `ghsecretman: manage GitHub Actions secrets, Actions variables, and
             Dependabot secrets across an organization from a YAML file.

usage:
  ghsecretman <command> [flags]

commands:
  audit    Read-only diff between YAML config and live state.
  apply    Write managed values; never delete.
  enforce  Apply, then delete unlisted values. Supports --dry-run.
  example  Print an annotated example YAML config (or write it with -o).
  version  Print version, commit, and build date.

authentication:
  Reads GITHUB_TOKEN (preferred) or GH_TOKEN from the environment.

Run 'ghsecretman <command> -h' for command-specific flags.
See 'ghsecretman example' for the full schema with annotations.
`)
}

// runExample prints the embedded annotated example YAML configuration to
// stdout, or writes it to a file when -o/--output is supplied. Existing files
// are not overwritten unless -f/--force is set.
func runExample(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("example", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var output string
	fs.StringVar(&output, "output", "", "write to file instead of stdout")
	fs.StringVar(&output, "o", "", "write to file instead of stdout (shorthand)")
	var force bool
	fs.BoolVar(&force, "force", false, "overwrite an existing output file")
	fs.BoolVar(&force, "f", false, "overwrite (shorthand)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if output == "" {
		if _, err := io.WriteString(stdout, schema.Example); err != nil {
			fmt.Fprintf(stderr, "example: %v\n", err)
			return 1
		}
		return 0
	}

	if !force {
		if _, err := os.Stat(output); err == nil {
			fmt.Fprintf(stderr, "example: %s already exists; pass --force to overwrite\n", output)
			return 2
		}
	}
	if err := os.WriteFile(output, []byte(schema.Example), 0o600); err != nil {
		fmt.Fprintf(stderr, "example: %v\n", err)
		return 1
	}
	return 0
}

func runEnforce(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enforce", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to YAML config file")
	org := fs.String("org", "", "GitHub organization name")
	repo := fs.String("repo", "", "single repo to enforce; omit to iterate every repo in the org")
	dryRun := fs.Bool("dry-run", false, "print intended writes and deletes; make no API write calls")
	yes := fs.Bool("yes", false, "proceed without confirmation prompt")
	concurrency := fs.Int("concurrency", runner.DefaultConcurrency, "max repos processed in parallel for org-wide runs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" || *org == "" {
		fmt.Fprintln(stderr, "enforce: --config and --org are required")
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config: %v\n", err)
		return 2
	}

	backend, err := backendFactory()
	if err != nil {
		fmt.Fprintf(stderr, "github: %v\n", err)
		return 2
	}

	opts, code := buildEnforceOptions(*org, *repo, *dryRun, *yes, stdout, stderr)
	if code != 0 {
		return code
	}
	opts.Concurrency = *concurrency

	if *repo != "" {
		return runEnforceRepo(cfg, *org, *repo, backend, opts, stdout, stderr)
	}
	return runEnforceOrg(cfg, *org, backend, opts, stdout, stderr)
}

func buildEnforceOptions(org, repo string, dryRun, yes bool, stdout, stderr io.Writer) (runner.EnforceOptions, int) {
	opts := runner.EnforceOptions{DryRun: dryRun}
	if dryRun || yes {
		return opts, 0
	}
	if !isTTY() {
		fmt.Fprintln(stderr, "enforce: refusing to run on non-interactive stdin without --yes")
		return opts, 2
	}
	target := repo
	if target == "" {
		target = "all repos in " + org
	}
	opts.Confirm = func(extras []string) bool {
		return promptDeletions(stdin, stdout, org, target, extras)
	}
	return opts, 0
}

func runEnforceRepo(cfg *config.Config, org, repo string, backend gh.Backend, opts runner.EnforceOptions, stdout, stderr io.Writer) int {
	res, err := runner.EnforceRepo(context.Background(), cfg, org, repo, backend, stdout, opts)
	if err != nil {
		fmt.Fprintf(stderr, "enforce: %v\n", err)
		return 1
	}
	if res.Failed > 0 {
		return 1
	}
	return 0
}

func runEnforceOrg(cfg *config.Config, org string, backend gh.Backend, opts runner.EnforceOptions, stdout, stderr io.Writer) int {
	res, err := runner.Enforce(context.Background(), cfg, org, backend, stdout, opts)
	if err != nil {
		fmt.Fprintf(stderr, "enforce: %v\n", err)
		return 1
	}
	if res.FailedEntries > 0 || res.FailedRepos > 0 {
		return 1
	}
	return 0
}

func promptDeletions(in io.Reader, out io.Writer, org, repo string, extras []string) bool {
	fmt.Fprintf(out, "About to delete %d entries on %s/%s:\n", len(extras), org, repo)
	for _, x := range extras {
		fmt.Fprintf(out, "  - %s\n", x)
	}
	fmt.Fprint(out, "Proceed? [y/N]: ")
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to YAML config file")
	org := fs.String("org", "", "GitHub organization name")
	repo := fs.String("repo", "", "single repo to audit; omit to iterate every repo in the org")
	showIgnored := fs.Bool("show-ignored", false, "include ignored entries in output")
	concurrency := fs.Int("concurrency", runner.DefaultConcurrency, "max repos processed in parallel for org-wide runs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" || *org == "" {
		fmt.Fprintln(stderr, "audit: --config and --org are required")
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config: %v\n", err)
		return 2
	}

	backend, err := backendFactory()
	if err != nil {
		fmt.Fprintf(stderr, "github: %v\n", err)
		return 2
	}

	if *repo != "" {
		res, err := runner.AuditRepo(context.Background(), cfg, *org, *repo, backend, stdout, *showIgnored)
		if err != nil {
			fmt.Fprintf(stderr, "audit: %v\n", err)
			return 1
		}
		if res.Drift {
			return 1
		}
		return 0
	}

	res, err := runner.Audit(context.Background(), cfg, *org, backend, stdout, *showIgnored, runner.OrgOptions{Concurrency: *concurrency})
	if err != nil {
		fmt.Fprintf(stderr, "audit: %v\n", err)
		return 1
	}
	if res.Drift || res.FailedRepos > 0 {
		return 1
	}
	return 0
}

func runApply(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to YAML config file")
	org := fs.String("org", "", "GitHub organization name")
	repo := fs.String("repo", "", "single repo to apply; omit to iterate every repo in the org")
	concurrency := fs.Int("concurrency", runner.DefaultConcurrency, "max repos processed in parallel for org-wide runs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" || *org == "" {
		fmt.Fprintln(stderr, "apply: --config and --org are required")
		return 2
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "load config: %v\n", err)
		return 2
	}

	backend, err := backendFactory()
	if err != nil {
		fmt.Fprintf(stderr, "github: %v\n", err)
		return 2
	}

	if *repo != "" {
		res, err := runner.ApplyRepo(context.Background(), cfg, *org, *repo, backend, stdout)
		if err != nil {
			fmt.Fprintf(stderr, "apply: %v\n", err)
			return 1
		}
		if res.Failed > 0 {
			return 1
		}
		return 0
	}

	res, err := runner.Apply(context.Background(), cfg, *org, backend, stdout, runner.OrgOptions{Concurrency: *concurrency})
	if err != nil {
		fmt.Fprintf(stderr, "apply: %v\n", err)
		return 1
	}
	if res.FailedEntries > 0 || res.FailedRepos > 0 {
		return 1
	}
	return 0
}
