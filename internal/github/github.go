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
	"strings"

	gogithub "github.com/google/go-github/v85/github"
)

// OwnerType distinguishes a GitHub organization from a personal (user)
// account. The two differ in how their repositories are enumerated and in
// whether org-level secrets/variables exist at all: user accounts have no
// org-level Actions, variable, or Dependabot API, so that scope is
// unsupported for them.
type OwnerType int

const (
	// OwnerOrg is a GitHub organization.
	OwnerOrg OwnerType = iota
	// OwnerUser is a personal GitHub account.
	OwnerUser
)

// Backend is the interface the runner consumes; satisfied by *Client and
// by test fakes.
type Backend interface {
	// GetOwnerType reports whether owner is a GitHub organization or a
	// user account. The runner uses it to pick the repo-enumeration
	// endpoint and to skip org-level scope for user accounts.
	GetOwnerType(ctx context.Context, owner string) (OwnerType, error)

	ListOrgRepos(ctx context.Context, org string) ([]string, error)

	// ListUserRepos returns the names of every repository owned by the
	// authenticated user that belongs to owner. Private repos are
	// included. It is the user-account counterpart to ListOrgRepos.
	ListUserRepos(ctx context.Context, owner string) ([]string, error)

	ListRepoVariables(ctx context.Context, owner, repo string) (map[string]string, error)
	ListRepoSecrets(ctx context.Context, owner, repo string) ([]string, error)
	ListRepoDependabotSecrets(ctx context.Context, owner, repo string) ([]string, error)

	GetRepoPublicKey(ctx context.Context, owner, repo string) (*PublicKey, error)
	GetRepoDependabotPublicKey(ctx context.Context, owner, repo string) (*PublicKey, error)

	SetRepoVariable(ctx context.Context, owner, repo, name, value string) error
	SetRepoSecret(ctx context.Context, owner, repo, name string, key *PublicKey, plaintext string) error
	SetRepoDependabotSecret(ctx context.Context, owner, repo, name string, key *PublicKey, plaintext string) error

	DeleteRepoVariable(ctx context.Context, owner, repo, name string) error
	DeleteRepoSecret(ctx context.Context, owner, repo, name string) error
	DeleteRepoDependabotSecret(ctx context.Context, owner, repo, name string) error

	// Org-level operations. Org secrets, variables, and Dependabot secrets
	// are a different GitHub object class from their repo-level counterparts
	// and use a separate public key for encryption.
	ListOrgVariables(ctx context.Context, org string) (map[string]string, error)
	ListOrgSecrets(ctx context.Context, org string) ([]string, error)
	ListOrgDependabotSecrets(ctx context.Context, org string) ([]string, error)

	GetOrgPublicKey(ctx context.Context, org string) (*PublicKey, error)
	GetOrgDependabotPublicKey(ctx context.Context, org string) (*PublicKey, error)

	SetOrgVariable(ctx context.Context, org, name, value, visibility string, selectedRepoIDs []int64) error
	SetOrgSecret(ctx context.Context, org, name string, key *PublicKey, plaintext, visibility string, selectedRepoIDs []int64) error
	SetOrgDependabotSecret(ctx context.Context, org, name string, key *PublicKey, plaintext, visibility string, selectedRepoIDs []int64) error

	DeleteOrgVariable(ctx context.Context, org, name string) error
	DeleteOrgSecret(ctx context.Context, org, name string) error
	DeleteOrgDependabotSecret(ctx context.Context, org, name string) error

	// GetRepoID resolves a repo name to its numeric GitHub ID. Used to
	// translate `repos:` lists from configuration into the
	// `selected_repository_ids` payload expected by the org-level secret
	// and variable APIs.
	GetRepoID(ctx context.Context, org, repo string) (int64, error)
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

// GetOwnerType resolves whether owner is a GitHub organization or a user
// account by reading the `type` field of the public account record. Any
// type other than "User" (notably "Organization") is treated as an org.
func (c *Client) GetOwnerType(ctx context.Context, owner string) (OwnerType, error) {
	u, _, err := c.gh.Users.Get(ctx, owner)
	if err != nil {
		return OwnerOrg, fmt.Errorf("get owner %q: %w", owner, err)
	}
	if u != nil && strings.EqualFold(u.GetType(), "User") {
		return OwnerUser, nil
	}
	return OwnerOrg, nil
}

// ListUserRepos returns the names of every repository owned by the
// authenticated user whose owner login matches owner (case-insensitively,
// as GitHub logins are). It pages through GET /user/repos with the `owner`
// affiliation so private repos are included; the login filter drops repos
// reachable through other affiliations. Managing a user account's secrets
// requires authenticating as that user, so the authenticated-user endpoint
// is the right source here.
func (c *Client) ListUserRepos(ctx context.Context, owner string) ([]string, error) {
	opts := &gogithub.RepositoryListByAuthenticatedUserOptions{
		Affiliation: "owner",
		ListOptions: gogithub.ListOptions{PerPage: 100},
	}
	var names []string
	for {
		repos, resp, err := c.gh.Repositories.ListByAuthenticatedUser(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list user repos: %w", err)
		}
		for _, r := range repos {
			if r != nil && r.Name != nil && strings.EqualFold(r.GetOwner().GetLogin(), owner) {
				names = append(names, *r.Name)
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return names, nil
}

// ListOrgRepos returns the names of every repository in the org. Pages
// through the list until exhausted.
func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	opts := &gogithub.RepositoryListByOrgOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	}
	var names []string
	for {
		repos, resp, err := c.gh.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("list org repos: %w", err)
		}
		for _, r := range repos {
			if r != nil && r.Name != nil {
				names = append(names, *r.Name)
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return names, nil
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

// DeleteRepoVariable deletes a repo Actions variable.
func (c *Client) DeleteRepoVariable(ctx context.Context, owner, repo, name string) error {
	if _, err := c.gh.Actions.DeleteRepoVariable(ctx, owner, repo, name); err != nil {
		return fmt.Errorf("delete repo variable %s: %w", name, err)
	}
	return nil
}

// DeleteRepoSecret deletes a repo Actions secret.
func (c *Client) DeleteRepoSecret(ctx context.Context, owner, repo, name string) error {
	if _, err := c.gh.Actions.DeleteRepoSecret(ctx, owner, repo, name); err != nil {
		return fmt.Errorf("delete repo secret %s: %w", name, err)
	}
	return nil
}

// DeleteRepoDependabotSecret deletes a repo Dependabot secret.
func (c *Client) DeleteRepoDependabotSecret(ctx context.Context, owner, repo, name string) error {
	if _, err := c.gh.Dependabot.DeleteRepoSecret(ctx, owner, repo, name); err != nil {
		return fmt.Errorf("delete repo dependabot secret %s: %w", name, err)
	}
	return nil
}

// ListOrgVariables returns org-level Actions variables as name → value map.
func (c *Client) ListOrgVariables(ctx context.Context, org string) (map[string]string, error) {
	vars, _, err := c.gh.Actions.ListOrgVariables(ctx, org, &gogithub.ListOptions{PerPage: 100})
	if err != nil {
		return nil, fmt.Errorf("list org variables: %w", err)
	}
	out := make(map[string]string, len(vars.Variables))
	for _, v := range vars.Variables {
		out[v.Name] = v.Value
	}
	return out, nil
}

// ListOrgSecrets returns the names of org-level Actions secrets.
func (c *Client) ListOrgSecrets(ctx context.Context, org string) ([]string, error) {
	secrets, _, err := c.gh.Actions.ListOrgSecrets(ctx, org, &gogithub.ListOptions{PerPage: 100})
	if err != nil {
		return nil, fmt.Errorf("list org secrets: %w", err)
	}
	return namesOf(secrets), nil
}

// ListOrgDependabotSecrets returns the names of org-level Dependabot secrets.
func (c *Client) ListOrgDependabotSecrets(ctx context.Context, org string) ([]string, error) {
	secrets, _, err := c.gh.Dependabot.ListOrgSecrets(ctx, org, &gogithub.ListOptions{PerPage: 100})
	if err != nil {
		return nil, fmt.Errorf("list org dependabot secrets: %w", err)
	}
	return namesOf(secrets), nil
}

// GetOrgPublicKey fetches the public key used to encrypt org Actions secrets.
func (c *Client) GetOrgPublicKey(ctx context.Context, org string) (*PublicKey, error) {
	pk, _, err := c.gh.Actions.GetOrgPublicKey(ctx, org)
	if err != nil {
		return nil, fmt.Errorf("get org actions public key: %w", err)
	}
	return toPublicKey(pk)
}

// GetOrgDependabotPublicKey fetches the public key used to encrypt org
// Dependabot secrets.
func (c *Client) GetOrgDependabotPublicKey(ctx context.Context, org string) (*PublicKey, error) {
	pk, _, err := c.gh.Dependabot.GetOrgPublicKey(ctx, org)
	if err != nil {
		return nil, fmt.Errorf("get org dependabot public key: %w", err)
	}
	return toPublicKey(pk)
}

// SetOrgVariable creates or updates an org Actions variable with the given
// visibility envelope. selectedRepoIDs must be non-empty when visibility is
// "selected" and is ignored otherwise.
func (c *Client) SetOrgVariable(ctx context.Context, org, name, value, visibility string, selectedRepoIDs []int64) error {
	v := buildOrgVariable(name, value, visibility, selectedRepoIDs)
	resp, err := c.gh.Actions.UpdateOrgVariable(ctx, org, v)
	if err == nil {
		return nil
	}
	if resp != nil && resp.StatusCode == 404 {
		if _, cerr := c.gh.Actions.CreateOrgVariable(ctx, org, v); cerr != nil {
			return fmt.Errorf("create org variable %s: %w", name, cerr)
		}
		return nil
	}
	return fmt.Errorf("update org variable %s: %w", name, err)
}

// visibilitySelected names the only org-scope visibility value that takes a
// selected_repository_ids payload.
const visibilitySelected = "selected"

func buildOrgVariable(name, value, visibility string, selectedRepoIDs []int64) *gogithub.ActionsVariable {
	v := &gogithub.ActionsVariable{Name: name, Value: value}
	vis := visibility
	v.Visibility = &vis
	if visibility == visibilitySelected {
		ids := gogithub.SelectedRepoIDs(append([]int64(nil), selectedRepoIDs...))
		v.SelectedRepositoryIDs = &ids
	}
	return v
}

// SetOrgSecret creates or updates an org Actions secret with the given
// visibility envelope. plaintext is encrypted client-side with key.
func (c *Client) SetOrgSecret(ctx context.Context, org, name string, key *PublicKey, plaintext, visibility string, selectedRepoIDs []int64) error {
	if key == nil {
		return fmt.Errorf("set org secret %s: missing public key", name)
	}
	enc, err := sealAnonymous(plaintext, key.Key)
	if err != nil {
		return fmt.Errorf("encrypt org secret %s: %w", name, err)
	}
	es := &gogithub.EncryptedSecret{
		Name:           name,
		KeyID:          key.KeyID,
		EncryptedValue: enc,
		Visibility:     visibility,
	}
	if visibility == visibilitySelected {
		es.SelectedRepositoryIDs = gogithub.SelectedRepoIDs(append([]int64(nil), selectedRepoIDs...))
	}
	if _, err := c.gh.Actions.CreateOrUpdateOrgSecret(ctx, org, es); err != nil {
		return fmt.Errorf("set org secret %s: %w", name, err)
	}
	return nil
}

// SetOrgDependabotSecret creates or updates an org Dependabot secret with the
// given visibility envelope.
func (c *Client) SetOrgDependabotSecret(ctx context.Context, org, name string, key *PublicKey, plaintext, visibility string, selectedRepoIDs []int64) error {
	if key == nil {
		return fmt.Errorf("set org dependabot secret %s: missing public key", name)
	}
	enc, err := sealAnonymous(plaintext, key.Key)
	if err != nil {
		return fmt.Errorf("encrypt org dependabot secret %s: %w", name, err)
	}
	es := &gogithub.DependabotEncryptedSecret{
		Name:           name,
		KeyID:          key.KeyID,
		EncryptedValue: enc,
		Visibility:     visibility,
	}
	if visibility == visibilitySelected {
		es.SelectedRepositoryIDs = gogithub.DependabotSecretsSelectedRepoIDs(append([]int64(nil), selectedRepoIDs...))
	}
	if _, err := c.gh.Dependabot.CreateOrUpdateOrgSecret(ctx, org, es); err != nil {
		return fmt.Errorf("set org dependabot secret %s: %w", name, err)
	}
	return nil
}

// DeleteOrgVariable deletes an org Actions variable.
func (c *Client) DeleteOrgVariable(ctx context.Context, org, name string) error {
	if _, err := c.gh.Actions.DeleteOrgVariable(ctx, org, name); err != nil {
		return fmt.Errorf("delete org variable %s: %w", name, err)
	}
	return nil
}

// DeleteOrgSecret deletes an org Actions secret.
func (c *Client) DeleteOrgSecret(ctx context.Context, org, name string) error {
	if _, err := c.gh.Actions.DeleteOrgSecret(ctx, org, name); err != nil {
		return fmt.Errorf("delete org secret %s: %w", name, err)
	}
	return nil
}

// DeleteOrgDependabotSecret deletes an org Dependabot secret.
func (c *Client) DeleteOrgDependabotSecret(ctx context.Context, org, name string) error {
	if _, err := c.gh.Dependabot.DeleteOrgSecret(ctx, org, name); err != nil {
		return fmt.Errorf("delete org dependabot secret %s: %w", name, err)
	}
	return nil
}

// GetRepoID resolves a repo name to its numeric GitHub ID.
func (c *Client) GetRepoID(ctx context.Context, org, repo string) (int64, error) {
	r, _, err := c.gh.Repositories.Get(ctx, org, repo)
	if err != nil {
		return 0, fmt.Errorf("get repo %s/%s: %w", org, repo, err)
	}
	if r == nil || r.ID == nil {
		return 0, fmt.Errorf("get repo %s/%s: missing id", org, repo)
	}
	return *r.ID, nil
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
