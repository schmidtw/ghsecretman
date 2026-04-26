// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

// Package github wraps the upstream go-github SDK with the narrow surface
// ghsecretman needs: list repo Actions variables (with values), list repo
// Actions secret names, and list repo Dependabot secret names.
package github

import (
	"context"
	"errors"
	"fmt"
	"os"

	gogithub "github.com/google/go-github/v85/github"
)

// Backend is the interface the runner consumes; satisfied by *Client and
// by test fakes.
type Backend interface {
	ListRepoVariables(ctx context.Context, owner, repo string) (map[string]string, error)
	ListRepoSecrets(ctx context.Context, owner, repo string) ([]string, error)
	ListRepoDependabotSecrets(ctx context.Context, owner, repo string) ([]string, error)
}

// Client is the live GitHub backend.
type Client struct {
	gh *gogithub.Client
}

// NewClientFromEnv builds a Client authenticated from GITHUB_TOKEN
// (preferred) or GH_TOKEN (fallback).
func NewClientFromEnv() (*Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, errors.New("no GitHub token found in GITHUB_TOKEN or GH_TOKEN")
	}
	return &Client{gh: gogithub.NewClient(nil).WithAuthToken(token)}, nil
}

// NewClientFromGoGithub wraps an existing go-github client. Useful for tests
// that need to point at httptest.
func NewClientFromGoGithub(gh *gogithub.Client) *Client {
	return &Client{gh: gh}
}

// ListRepoVariables returns repo Actions variables as a name → value map.
//
// The single-page fetch is intentional for this slice; pagination support
// belongs in a later slice when org-wide fan-out makes it actually matter.
func (c *Client) ListRepoVariables(ctx context.Context, owner, repo string) (map[string]string, error) {
	vars, _, err := c.gh.Actions.ListRepoVariables(ctx, owner, repo, &gogithub.ListOptions{PerPage: 100})
	if err != nil {
		return nil, fmt.Errorf("list repo variables: %w", err)
	}
	out := make(map[string]string, len(vars.Variables))
	for _, v := range vars.Variables {
		out[v.Name] = v.Value
	}
	return out, nil
}

// ListRepoSecrets returns the names of repo Actions secrets.
func (c *Client) ListRepoSecrets(ctx context.Context, owner, repo string) ([]string, error) {
	secrets, _, err := c.gh.Actions.ListRepoSecrets(ctx, owner, repo, &gogithub.ListOptions{PerPage: 100})
	if err != nil {
		return nil, fmt.Errorf("list repo secrets: %w", err)
	}
	return namesOf(secrets), nil
}

// ListRepoDependabotSecrets returns the names of repo Dependabot secrets.
func (c *Client) ListRepoDependabotSecrets(ctx context.Context, owner, repo string) ([]string, error) {
	secrets, _, err := c.gh.Dependabot.ListRepoSecrets(ctx, owner, repo, &gogithub.ListOptions{PerPage: 100})
	if err != nil {
		return nil, fmt.Errorf("list repo dependabot secrets: %w", err)
	}
	return namesOf(secrets), nil
}

func namesOf(s *gogithub.Secrets) []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.Secrets))
	for _, sec := range s.Secrets {
		out = append(out, sec.Name)
	}
	return out
}
