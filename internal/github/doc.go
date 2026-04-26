// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package github wraps the upstream go-github client behind an interface
// the runner can fake in tests.
package github

import "github.com/google/go-github/v85/github"

var _ = github.Client{}
