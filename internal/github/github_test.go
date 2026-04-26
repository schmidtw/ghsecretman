// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	gogithub "github.com/google/go-github/v85/github"
	"golang.org/x/crypto/nacl/box"
)

func TestClient_ListOrgRepos(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/orgs/example/repos": `[{"name":"alpha"},{"name":"beta"}]`,
	})
	defer srv.Close()

	got, err := c.ListOrgRepos(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(got)
	want := []string{"alpha", "beta"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestClient_ListOrgRepos_Pagination(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		seenPage []string
	)
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		page := r.URL.Query().Get("page")
		seenPage = append(seenPage, page)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "", "1":
			w.Header().Set("Link", `<`+srvURL+r.URL.Path+`?page=2>; rel="next"`)
			fmt.Fprint(w, `[{"name":"alpha"}]`)
		case "2":
			fmt.Fprint(w, `[{"name":"beta"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	srvURL = srv.URL
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)

	got, err := c.ListOrgRepos(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "alpha,beta" {
		t.Fatalf("got %v", got)
	}
	if len(seenPage) < 2 {
		t.Errorf("expected pagination across at least 2 pages; saw %v", seenPage)
	}
}

func TestClient_ListOrgRepos_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.ListOrgRepos(context.Background(), "example"); err == nil {
		t.Fatal("expected error")
	}
}

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
		"/repos/example/acme/actions/secrets": `{"total_count":2,"secrets":[{"name":"S1"},{"name":"S2"}]}`, // #nosec G101 -- fixture, no credentials
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
		"/repos/example/acme/dependabot/secrets": `{"total_count":1,"secrets":[{"name":"D1"}]}`, // #nosec G101 -- fixture, no credentials
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

func TestClient_GetRepoPublicKey(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme/actions/secrets/public-key": `{"key_id":"kid-actions","key":"AAAA"}`, // #nosec G101 -- fixture, no credentials
	})
	defer srv.Close()

	pk, err := c.GetRepoPublicKey(context.Background(), "example", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.KeyID != "kid-actions" || pk.Key != "AAAA" {
		t.Fatalf("got %+v", pk)
	}
}

func TestClient_GetRepoDependabotPublicKey(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme/dependabot/secrets/public-key": `{"key_id":"kid-dep","key":"BBBB"}`, // #nosec G101 -- fixture, no credentials
	})
	defer srv.Close()

	pk, err := c.GetRepoDependabotPublicKey(context.Background(), "example", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.KeyID != "kid-dep" || pk.Key != "BBBB" {
		t.Fatalf("got %+v", pk)
	}
}

func TestClient_GetRepoPublicKey_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.GetRepoPublicKey(context.Background(), "example", "acme"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := c.GetRepoDependabotPublicKey(context.Background(), "example", "acme"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetRepoVariable_Update(t *testing.T) {
	t.Parallel()
	var got struct {
		method string
		path   string
		body   map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got.body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)

	if err := c.SetRepoVariable(context.Background(), "example", "acme", "V", "ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.method != http.MethodPatch {
		t.Errorf("method: got %s want PATCH", got.method)
	}
	if got.path != "/repos/example/acme/actions/variables/V" {
		t.Errorf("path: %s", got.path)
	}
	if got.body["name"] != "V" || got.body["value"] != "ok" {
		t.Errorf("body: %+v", got.body)
	}
}

func TestClient_SetRepoVariable_CreateFallback(t *testing.T) {
	t.Parallel()
	var (
		mu    sync.Mutex
		calls []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPatch {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		// POST creates
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)

	if err := c.SetRepoVariable(context.Background(), "example", "acme", "V", "ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"PATCH /repos/example/acme/actions/variables/V",
		"POST /repos/example/acme/actions/variables",
	}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls: %v want %v", calls, want)
	}
}

func TestClient_SetRepoVariable_UpdateError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"server"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.SetRepoVariable(context.Background(), "example", "acme", "V", "ok"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetRepoVariable_CreateError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.SetRepoVariable(context.Background(), "example", "acme", "V", "ok"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetRepoSecret_EncryptsAndPuts(t *testing.T) {
	t.Parallel()
	pub, priv := genBoxKeypair(t)
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])

	var captured struct {
		method, path string
		body         map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)

	err := c.SetRepoSecret(context.Background(), "example", "acme", "S",
		&PublicKey{KeyID: "kid", Key: pubB64}, "plain-text-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodPut {
		t.Errorf("method: %s", captured.method)
	}
	if captured.path != "/repos/example/acme/actions/secrets/S" {
		t.Errorf("path: %s", captured.path)
	}
	if captured.body["key_id"] != "kid" {
		t.Errorf("key_id: %v", captured.body["key_id"])
	}
	encB64, _ := captured.body["encrypted_value"].(string)
	if encB64 == "" {
		t.Fatalf("encrypted_value missing in body: %+v", captured.body)
	}
	plain := decryptSealedBox(t, encB64, pub, priv)
	if plain != "plain-text-value" {
		t.Errorf("decrypted: got %q want %q", plain, "plain-text-value")
	}
}

func TestClient_SetRepoSecret_NilKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	if err := c.SetRepoSecret(context.Background(), "example", "acme", "S", nil, "v"); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestClient_SetRepoSecret_BadKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	err := c.SetRepoSecret(context.Background(), "example", "acme", "S",
		&PublicKey{KeyID: "kid", Key: "not-base64!!!"}, "v")
	if err == nil {
		t.Fatal("expected error for bad public key")
	}
}

func TestClient_SetRepoSecret_APIError(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetRepoSecret(context.Background(), "example", "acme", "S",
		&PublicKey{KeyID: "kid", Key: base64.StdEncoding.EncodeToString(pub[:])}, "v")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetRepoDependabotSecret_EncryptsAndPuts(t *testing.T) {
	t.Parallel()
	pub, priv := genBoxKeypair(t)
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])

	var captured struct {
		method, path string
		body         map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)

	err := c.SetRepoDependabotSecret(context.Background(), "example", "acme", "D",
		&PublicKey{KeyID: "kid-dep", Key: pubB64}, "dep-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodPut {
		t.Errorf("method: %s", captured.method)
	}
	if captured.path != "/repos/example/acme/dependabot/secrets/D" {
		t.Errorf("path: %s", captured.path)
	}
	if captured.body["key_id"] != "kid-dep" {
		t.Errorf("key_id: %v", captured.body["key_id"])
	}
	encB64, _ := captured.body["encrypted_value"].(string)
	if encB64 == "" {
		t.Fatalf("encrypted_value missing: %+v", captured.body)
	}
	plain := decryptSealedBox(t, encB64, pub, priv)
	if plain != "dep-secret" {
		t.Errorf("decrypted: got %q", plain)
	}
}

func TestClient_SetRepoDependabotSecret_NilKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	if err := c.SetRepoDependabotSecret(context.Background(), "example", "acme", "D", nil, "v"); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestClient_SetRepoDependabotSecret_BadKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	err := c.SetRepoDependabotSecret(context.Background(), "example", "acme", "D",
		&PublicKey{KeyID: "kid", Key: "not-base64!!!"}, "v")
	if err == nil {
		t.Fatal("expected error for bad public key")
	}
}

func TestClient_SetRepoDependabotSecret_APIError(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetRepoDependabotSecret(context.Background(), "example", "acme", "D",
		&PublicKey{KeyID: "kid", Key: base64.StdEncoding.EncodeToString(pub[:])}, "v")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteRepoVariable(t *testing.T) {
	t.Parallel()
	var captured struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteRepoVariable(context.Background(), "example", "acme", "V"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodDelete {
		t.Errorf("method: got %s want DELETE", captured.method)
	}
	if captured.path != "/repos/example/acme/actions/variables/V" {
		t.Errorf("path: %s", captured.path)
	}
}

func TestClient_DeleteRepoVariable_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteRepoVariable(context.Background(), "example", "acme", "V"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteRepoSecret(t *testing.T) {
	t.Parallel()
	var captured struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteRepoSecret(context.Background(), "example", "acme", "S"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodDelete {
		t.Errorf("method: got %s want DELETE", captured.method)
	}
	if captured.path != "/repos/example/acme/actions/secrets/S" {
		t.Errorf("path: %s", captured.path)
	}
}

func TestClient_DeleteRepoSecret_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteRepoSecret(context.Background(), "example", "acme", "S"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteRepoDependabotSecret(t *testing.T) {
	t.Parallel()
	var captured struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteRepoDependabotSecret(context.Background(), "example", "acme", "D"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodDelete {
		t.Errorf("method: got %s want DELETE", captured.method)
	}
	if captured.path != "/repos/example/acme/dependabot/secrets/D" {
		t.Errorf("path: %s", captured.path)
	}
}

func TestClient_DeleteRepoDependabotSecret_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteRepoDependabotSecret(context.Background(), "example", "acme", "D"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSealAnonymous_Roundtrip(t *testing.T) {
	t.Parallel()
	pub, priv := genBoxKeypair(t)
	encB64, err := sealAnonymous("hello world", base64.StdEncoding.EncodeToString(pub[:]))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	plain := decryptSealedBox(t, encB64, pub, priv)
	if plain != "hello world" {
		t.Errorf("decrypt: %q", plain)
	}
}

func TestSealAnonymous_BadKey(t *testing.T) {
	t.Parallel()
	if _, err := sealAnonymous("x", "not-base64!!"); err == nil {
		t.Error("expected error for bad base64")
	}
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := sealAnonymous("x", short); err == nil {
		t.Error("expected error for wrong key length")
	}
}

func genBoxKeypair(t *testing.T) (*[32]byte, *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func decryptSealedBox(t *testing.T, encB64 string, pub, priv *[32]byte) string {
	t.Helper()
	enc, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		t.Fatalf("decode encrypted: %v", err)
	}
	out, ok := box.OpenAnonymous(nil, enc, pub, priv)
	if !ok {
		t.Fatalf("OpenAnonymous failed")
	}
	return string(out)
}

func TestClient_ListOrgVariables(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/orgs/example/actions/variables": `{"total_count":2,"variables":[{"name":"V1","value":"one","visibility":"all"},{"name":"V2","value":"two","visibility":"private"}]}`,
	})
	defer srv.Close()

	got, err := c.ListOrgVariables(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["V1"] != "one" || got["V2"] != "two" {
		t.Errorf("got %v", got)
	}
}

func TestClient_ListOrgVariables_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.ListOrgVariables(context.Background(), "example"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ListOrgSecrets(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/orgs/example/actions/secrets": `{"total_count":1,"secrets":[{"name":"S1"}]}`, // #nosec G101 -- fixture
	})
	defer srv.Close()
	got, err := c.ListOrgSecrets(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "S1" {
		t.Fatalf("got %v", got)
	}
}

func TestClient_ListOrgSecrets_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.ListOrgSecrets(context.Background(), "example"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ListOrgDependabotSecrets(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/orgs/example/dependabot/secrets": `{"total_count":1,"secrets":[{"name":"D1"}]}`, // #nosec G101 -- fixture
	})
	defer srv.Close()
	got, err := c.ListOrgDependabotSecrets(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "D1" {
		t.Fatalf("got %v", got)
	}
}

func TestClient_ListOrgDependabotSecrets_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.ListOrgDependabotSecrets(context.Background(), "example"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_GetOrgPublicKeys(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/orgs/example/actions/secrets/public-key":    `{"key_id":"org-act","key":"AAAA"}`, // #nosec G101 -- fixture
		"/orgs/example/dependabot/secrets/public-key": `{"key_id":"org-dep","key":"BBBB"}`, // #nosec G101 -- fixture
	})
	defer srv.Close()
	pk, err := c.GetOrgPublicKey(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.KeyID != "org-act" || pk.Key != "AAAA" {
		t.Fatalf("got %+v", pk)
	}
	pk2, err := c.GetOrgDependabotPublicKey(context.Background(), "example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk2.KeyID != "org-dep" {
		t.Fatalf("got %+v", pk2)
	}
}

func TestClient_GetOrgPublicKey_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.GetOrgPublicKey(context.Background(), "example"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := c.GetOrgDependabotPublicKey(context.Background(), "example"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgVariable_Update_AllVisibility(t *testing.T) {
	t.Parallel()
	var captured struct {
		method, path string
		body         map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.SetOrgVariable(context.Background(), "example", "V", "v", "all", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodPatch {
		t.Errorf("method: %s", captured.method)
	}
	if captured.path != "/orgs/example/actions/variables/V" {
		t.Errorf("path: %s", captured.path)
	}
	if captured.body["visibility"] != "all" {
		t.Errorf("visibility: %v", captured.body["visibility"])
	}
	if _, ok := captured.body["selected_repository_ids"]; ok {
		t.Errorf("selected_repository_ids should be omitted for non-selected visibility: %+v", captured.body)
	}
}

func TestClient_SetOrgVariable_CreateFallback_Selected(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		calls    []string
		lastBody map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPatch {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &lastBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.SetOrgVariable(context.Background(), "example", "V", "v", "selected", []int64{11, 22}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantCalls := []string{
		"PATCH /orgs/example/actions/variables/V",
		"POST /orgs/example/actions/variables",
	}
	if strings.Join(calls, "|") != strings.Join(wantCalls, "|") {
		t.Errorf("calls: %v", calls)
	}
	if lastBody["visibility"] != "selected" {
		t.Errorf("visibility: %v", lastBody["visibility"])
	}
	ids, _ := lastBody["selected_repository_ids"].([]any)
	if len(ids) != 2 {
		t.Errorf("ids: %+v", lastBody["selected_repository_ids"])
	}
}

func TestClient_SetOrgVariable_UpdateError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"server"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.SetOrgVariable(context.Background(), "example", "V", "v", "all", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgVariable_CreateError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.SetOrgVariable(context.Background(), "example", "V", "v", "all", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgSecret_PrivateVisibility(t *testing.T) {
	t.Parallel()
	pub, priv := genBoxKeypair(t)
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])
	var captured struct {
		method, path string
		body         map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetOrgSecret(context.Background(), "example", "S",
		&PublicKey{KeyID: "kid", Key: pubB64}, "plain", "private", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodPut {
		t.Errorf("method: %s", captured.method)
	}
	if captured.path != "/orgs/example/actions/secrets/S" {
		t.Errorf("path: %s", captured.path)
	}
	if captured.body["visibility"] != "private" {
		t.Errorf("visibility: %v", captured.body["visibility"])
	}
	if _, ok := captured.body["selected_repository_ids"]; ok {
		t.Errorf("selected_repository_ids should be omitted: %+v", captured.body)
	}
	enc, _ := captured.body["encrypted_value"].(string)
	plain := decryptSealedBox(t, enc, pub, priv)
	if plain != "plain" {
		t.Errorf("decrypted: %q", plain)
	}
}

func TestClient_SetOrgSecret_SelectedVisibility(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])
	var captured struct{ body map[string]any }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetOrgSecret(context.Background(), "example", "S",
		&PublicKey{KeyID: "kid", Key: pubB64}, "x", "selected", []int64{1, 2, 3})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.body["visibility"] != "selected" {
		t.Errorf("visibility: %v", captured.body["visibility"])
	}
	ids, _ := captured.body["selected_repository_ids"].([]any)
	if len(ids) != 3 {
		t.Errorf("ids: %v", captured.body["selected_repository_ids"])
	}
}

func TestClient_SetOrgSecret_NilKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	if err := c.SetOrgSecret(context.Background(), "example", "S", nil, "v", "all", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgSecret_BadKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	err := c.SetOrgSecret(context.Background(), "example", "S",
		&PublicKey{KeyID: "kid", Key: "not-base64!!!"}, "v", "all", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgSecret_APIError(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetOrgSecret(context.Background(), "example", "S",
		&PublicKey{KeyID: "kid", Key: base64.StdEncoding.EncodeToString(pub[:])}, "v", "all", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgDependabotSecret_PrivateVisibility(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])
	var captured struct {
		path string
		body map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetOrgDependabotSecret(context.Background(), "example", "D",
		&PublicKey{KeyID: "kid-dep", Key: pubB64}, "v", "private", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.path != "/orgs/example/dependabot/secrets/D" {
		t.Errorf("path: %s", captured.path)
	}
	if captured.body["visibility"] != "private" {
		t.Errorf("visibility: %v", captured.body["visibility"])
	}
}

func TestClient_SetOrgDependabotSecret_SelectedVisibility(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])
	var captured struct{ body map[string]any }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured.body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetOrgDependabotSecret(context.Background(), "example", "D",
		&PublicKey{KeyID: "kid-dep", Key: pubB64}, "v", "selected", []int64{99})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ids, _ := captured.body["selected_repository_ids"].([]any)
	if len(ids) != 1 {
		t.Errorf("ids: %v", captured.body["selected_repository_ids"])
	}
}

func TestClient_SetOrgDependabotSecret_NilKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	if err := c.SetOrgDependabotSecret(context.Background(), "example", "D", nil, "v", "all", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgDependabotSecret_BadKey(t *testing.T) {
	t.Parallel()
	c := newClientPointingAt(t, "http://127.0.0.1:0")
	err := c.SetOrgDependabotSecret(context.Background(), "example", "D",
		&PublicKey{KeyID: "kid", Key: "not-base64!!!"}, "v", "all", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SetOrgDependabotSecret_APIError(t *testing.T) {
	t.Parallel()
	pub, _ := genBoxKeypair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	err := c.SetOrgDependabotSecret(context.Background(), "example", "D",
		&PublicKey{KeyID: "kid", Key: base64.StdEncoding.EncodeToString(pub[:])}, "v", "all", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteOrgVariable(t *testing.T) {
	t.Parallel()
	var captured struct{ method, path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteOrgVariable(context.Background(), "example", "V"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.method != http.MethodDelete || captured.path != "/orgs/example/actions/variables/V" {
		t.Errorf("captured: %+v", captured)
	}
}

func TestClient_DeleteOrgVariable_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteOrgVariable(context.Background(), "example", "V"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteOrgSecret(t *testing.T) {
	t.Parallel()
	var captured struct{ path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteOrgSecret(context.Background(), "example", "S"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.path != "/orgs/example/actions/secrets/S" {
		t.Errorf("path: %s", captured.path)
	}
}

func TestClient_DeleteOrgSecret_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteOrgSecret(context.Background(), "example", "S"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteOrgDependabotSecret(t *testing.T) {
	t.Parallel()
	var captured struct{ path string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteOrgDependabotSecret(context.Background(), "example", "D"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.path != "/orgs/example/dependabot/secrets/D" {
		t.Errorf("path: %s", captured.path)
	}
}

func TestClient_DeleteOrgDependabotSecret_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if err := c.DeleteOrgDependabotSecret(context.Background(), "example", "D"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_GetRepoID(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme": `{"id":12345,"name":"acme"}`,
	})
	defer srv.Close()
	id, err := c.GetRepoID(context.Background(), "example", "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 12345 {
		t.Errorf("got %d", id)
	}
}

func TestClient_GetRepoID_Error(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	c := newClientPointingAt(t, srv.URL)
	if _, err := c.GetRepoID(context.Background(), "example", "acme"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_GetRepoID_MissingID(t *testing.T) {
	t.Parallel()
	srv, c := newTestClient(t, map[string]string{
		"/repos/example/acme": `{"name":"acme"}`,
	})
	defer srv.Close()
	if _, err := c.GetRepoID(context.Background(), "example", "acme"); err == nil {
		t.Fatal("expected error for missing id")
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
