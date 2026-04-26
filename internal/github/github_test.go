// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	gogithub "github.com/google/go-github/v85/github"
)

func TestClient_ListRepoVariables(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme/actions/variables": `{"total_count":2,"variables":[{"name":"V1","value":"one"},{"name":"V2","value":"two"}]}`,
	})
	defer srv.Close()

	got, err := c.ListRepoVariables(context.Background(), "example", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]string{"V1": "one", "V2": "two"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
}

func TestClient_ListRepoSecrets(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme/actions/secrets": `{"total_count":2,"secrets":[{"name":"S1"},{"name":"S2"}]}`,
	})
	defer srv.Close()

	got, err := c.ListRepoSecrets(context.Background(), "example", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(got)
	want := []string{"S1", "S2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestClient_ListRepoDependabotSecrets(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme/dependabot/secrets": `{"total_count":1,"secrets":[{"name":"D1"}]}`,
	})
	defer srv.Close()

	got, err := c.ListRepoDependabotSecrets(context.Background(), "example", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "D1" {
		t.Fatalf("got %v want [D1]", got)
	}
}

func TestClient_ApiError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	_, err := c.ListRepoVariables(context.Background(), "example", "acme")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewClientFromEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "tok-1")
	t.Setenv("GH_TOKEN", "")
	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("expected client")
	}
}

func TestNewClientFromEnv_FallbackToGH(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "tok-2")
	if _, err := NewClientFromEnv(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewClientFromEnv_NoToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if _, err := NewClientFromEnv(); err == nil {
		t.Fatal("expected error when no token set")
	}
}

func newTestClient(t *testing.T, responses map[string]string) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := responses[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	}))
	return srv, newClientPointingAt(t, srv.URL)
}

func newClientPointingAt(t *testing.T, baseURL string) *Client {
	t.Helper()
	gh := gogithub.NewClient(nil)
	u, err := url.Parse(baseURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	gh.BaseURL = u
	return NewClientFromGoGithub(gh)
}
