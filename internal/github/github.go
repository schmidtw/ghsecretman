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

	GetRepoPublicKey(ctx context.Context, owner, repo string) (*PublicKey, error)
	GetRepoDependabotPublicKey(ctx context.Context, owner, repo string) (*PublicKey, error)

	SetRepoVariable(ctx context.Context, owner, repo, name, value string) error
	SetRepoSecret(ctx context.Context, owner, repo, name string, key *PublicKey, plaintext string) error
	SetRepoDependabotSecret(ctx context.Context, owner, repo, name string, key *PublicKey, plaintext string) error
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

// GetRepoPublicKey fetches the public key used to encrypt repo Actions secrets.
func (c *Client) GetRepoPublicKey(ctx context.Context, owner, repo string) (*PublicKey, error) {
	pk, _, err := c.gh.Actions.GetRepoPublicKey(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("get repo actions public key: %w", err)
	}
	return toPublicKey(pk)
}

// GetRepoDependabotPublicKey fetches the public key used to encrypt repo
// Dependabot secrets.
func (c *Client) GetRepoDependabotPublicKey(ctx context.Context, owner, repo string) (*PublicKey, error) {
	pk, _, err := c.gh.Dependabot.GetRepoPublicKey(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("get repo dependabot public key: %w", err)
	}
	return toPublicKey(pk)
}

// SetRepoVariable creates or updates a repo Actions variable.
//
// The GitHub API exposes create (POST) and update (PATCH) as separate
// endpoints. We try update first; on 404 we fall back to create. This
// keeps the Backend surface "set, don't ask".
func (c *Client) SetRepoVariable(ctx context.Context, owner, repo, name, value string) error {
	v := &gogithub.ActionsVariable{Name: name, Value: value}
	resp, err := c.gh.Actions.UpdateRepoVariable(ctx, owner, repo, v)
	if err == nil {
		return nil
	}
	if resp != nil && resp.StatusCode == 404 {
		if _, cerr := c.gh.Actions.CreateRepoVariable(ctx, owner, repo, v); cerr != nil {
			return fmt.Errorf("create repo variable %s: %w", name, cerr)
		}
		return nil
	}
	return fmt.Errorf("update repo variable %s: %w", name, err)
}

// SetRepoSecret creates or updates a repo Actions secret. plaintext is
// encrypted client-side with libsodium sealed-box against key before being
// sent to GitHub.
func (c *Client) SetRepoSecret(ctx context.Context, owner, repo, name string, key *PublicKey, plaintext string) error {
	if key == nil {
		return fmt.Errorf("set repo secret %s: missing public key", name)
	}
	enc, err := sealAnonymous(plaintext, key.Key)
	if err != nil {
		return fmt.Errorf("encrypt repo secret %s: %w", name, err)
	}
	es := &gogithub.EncryptedSecret{Name: name, KeyID: key.KeyID, EncryptedValue: enc}
	if _, err := c.gh.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, es); err != nil {
		return fmt.Errorf("set repo secret %s: %w", name, err)
	}
	return nil
}

// SetRepoDependabotSecret creates or updates a repo Dependabot secret using
// the Dependabot-specific public key.
func (c *Client) SetRepoDependabotSecret(ctx context.Context, owner, repo, name string, key *PublicKey, plaintext string) error {
	if key == nil {
		return fmt.Errorf("set repo dependabot secret %s: missing public key", name)
	}
	enc, err := sealAnonymous(plaintext, key.Key)
	if err != nil {
		return fmt.Errorf("encrypt repo dependabot secret %s: %w", name, err)
	}
	es := &gogithub.DependabotEncryptedSecret{Name: name, KeyID: key.KeyID, EncryptedValue: enc}
	if _, err := c.gh.Dependabot.CreateOrUpdateRepoSecret(ctx, owner, repo, es); err != nil {
		return fmt.Errorf("set repo dependabot secret %s: %w", name, err)
	}
	return nil
}

func toPublicKey(pk *gogithub.PublicKey) (*PublicKey, error) {
	if pk == nil || pk.KeyID == nil || pk.Key == nil {
		return nil, errors.New("github returned an empty public key")
	}
	return &PublicKey{KeyID: *pk.KeyID, Key: *pk.Key}, nil
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
