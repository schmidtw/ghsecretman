// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package resolve turns a config.Entry into its concrete string value by
// reading from value, env, or file as the entry directs.
package resolve

import (
	"fmt"
	"os"

	"github.com/schmidtw/ghsecretman/internal/config"
)

// FileError reports a failure to read a file-sourced value.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	return fmt.Sprintf("read file %q: %v", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// Resolve returns the concrete string value for the entry.
//
// `env:` resolution is intentionally lazy — callers invoke Resolve only when
// the entry is about to be used, so missing env vars surface only for entries
// that matter to the current run.
func Resolve(e *config.Entry) (string, error) {
	switch {
	case e.HasValue:
		return e.Value, nil
	case e.File != "":
		path := e.FileAbs
		if path == "" {
			path = e.File
		}
		data, err := os.ReadFile(path) // #nosec G304 -- path comes from validated config entry
		if err != nil {
			return "", &FileError{Path: path, Err: err}
		}
		return string(data), nil
	case e.Env != "":
		v, ok := os.LookupEnv(e.Env)
		if !ok {
			return "", fmt.Errorf("env var %q not set", e.Env)
		}
		return v, nil
	}
	return "", fmt.Errorf("entry has no source")
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
