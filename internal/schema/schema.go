// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package schema exposes the canonical annotated example YAML configuration
// for ghsecretman. The example is embedded at build time so the binary
// always carries the schema documentation matching its own behavior.
package schema

import _ "embed"

//go:embed example.yml
var Example string
