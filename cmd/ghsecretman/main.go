// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Command ghsecretman manages GitHub secrets, variables, and Dependabot
// secrets across an organization from a YAML configuration file.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

func main() {
	os.Exit(run(os.Args, version, os.Stdout, os.Stderr))
}

func run(args []string, ver string, stdout, stderr io.Writer) int {
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

	fmt.Fprintln(stderr, "usage: ghsecretman [--version]")
	return 2
}
