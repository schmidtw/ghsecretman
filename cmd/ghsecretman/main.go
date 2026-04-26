// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Command ghsecretman manages GitHub secrets, variables, and Dependabot
// secrets across an organization from a YAML configuration file.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/schmidtw/ghsecretman/internal/config"
	gh "github.com/schmidtw/ghsecretman/internal/github"
	"github.com/schmidtw/ghsecretman/internal/runner"
)

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

// backendFactory is overridden in tests to inject a fake backend.
var backendFactory = func() (gh.Backend, error) { return gh.NewClientFromEnv() }

func main() {
	os.Exit(run(os.Args, version, os.Stdout, os.Stderr))
}

func run(args []string, ver string, stdout, stderr io.Writer) int {
	if len(args) >= 2 {
		switch args[1] {
		case "audit":
			return runAudit(args[2:], stdout, stderr)
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

	fmt.Fprintln(stderr, "usage: ghsecretman audit --config <path> --org <name> --repo <name>")
	return 2
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to YAML config file")
	org := fs.String("org", "", "GitHub organization name")
	repo := fs.String("repo", "", "single repo to audit")
	showIgnored := fs.Bool("show-ignored", false, "include ignored entries in output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cfgPath == "" || *org == "" || *repo == "" {
		fmt.Fprintln(stderr, "audit: --config, --org, and --repo are required")
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
