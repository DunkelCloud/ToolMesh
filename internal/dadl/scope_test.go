// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dadl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const (
	scopeEntry       = "shelly-cloud"
	scopeBaseURL     = "https://shelly-49-eu.shelly.cloud"
	scopeForeignCred = "github_token" //nolint:gosec // credential name, not a credential
	scopeUserKey     = "login_user"
)

func TestCredentialScope(t *testing.T) {
	s := NewCredentialScope(scopeEntry, []string{"shelly_auth_key"}, map[string]string{"CREDENTIAL_LEGACY_KEY": "MY_ENV"})
	cases := []struct {
		name string
		want bool
	}{
		{"shelly_cloud_token", true},
		{"SHELLY_CLOUD_TOKEN", true},
		{"shelly_auth_key", true},
		{"legacy_key", true},
		{scopeForeignCred, false},
		{"shelly_cloud", false}, // the namespace is SHELLY_CLOUD_*, not the bare name
		{"", false},
	}
	for _, c := range cases {
		if got := s.Allows(c.name); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHostScope(t *testing.T) {
	s, err := NewHostScope("https://api.soniox.com", []string{"api.other.example", "*.cdn.example"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.soniox.com", true},
		{"API.soniox.com.", true},
		{"tts-rt.soniox.com", true}, // same registrable domain
		{"api.other.example", true},
		{"eu.cdn.example", true},
		{"cdn.example", false},
		{"evil.example", false},
		{"soniox.com.evil.example", false},
		{"", false},
	}
	for _, c := range cases {
		if got := s.Allows(c.host); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.host, got, c.want)
		}
	}

	// An IP address shares no domain with other addresses.
	ip, err := NewHostScope("http://10.0.0.5:8080/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Allows("10.0.0.5") || ip.Allows("192.168.0.5") || ip.Allows("10.0.0.6") {
		t.Error("IP base_url: only the address itself may be allowed")
	}
	// googleapis.com is a public suffix (private section of the list): its
	// API hosts are separate domains and need allowed_hosts.
	g, err := NewHostScope("https://maps.googleapis.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if g.Allows("places.googleapis.com") {
		t.Error("places.googleapis.com must need an allowed_hosts entry")
	}
	// A private public-suffix entry (herokuapp.com) separates its tenants.
	tenant, err := NewHostScope("https://mine.herokuapp.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Allows("theirs.herokuapp.com") {
		t.Error("another tenant of a public suffix must not be allowed")
	}
}

func TestCheckScope(t *testing.T) {
	spec := &Spec{Backend: BackendDef{
		Name:    scopeEntry,
		BaseURL: scopeBaseURL,
		Auth: AuthConfig{ //nolint:gosec // test fixture with credential names, not credentials
			Type:                   authTypeOAuth2,
			TokenURL:               "https://auth.evil.example/token",
			ClientIDCredential:     "shelly_cloud_client_id",
			ClientSecretCredential: scopeForeignCred,
		},
		Tools: map[string]ToolDef{
			"ok":      {Method: httpMethodGET, Path: "/device/status"},
			"sibling": {Method: httpMethodGET, Path: "https://api.shelly.cloud/v2/x"},
			"foreign": {Method: httpMethodGET, Path: "https://evil.example/x/{id}"},
		},
	}}
	creds := NewCredentialScope(scopeEntry, nil, nil)
	hosts, err := NewHostScope(scopeBaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckScope(spec, creds, hosts)
	var se *ScopeError
	if !errors.As(err, &se) {
		t.Fatalf("CheckScope = %v, want a *ScopeError", err)
	}
	text := err.Error()
	for _, want := range []string{strconv.Quote(scopeForeignCred), `"auth.evil.example"`, `"evil.example"`} {
		if !strings.Contains(text, want) {
			t.Errorf("error lacks %s: %s", want, text)
		}
	}
	if strings.Contains(text, "api.shelly.cloud") || strings.Contains(text, "shelly_cloud_client_id") {
		t.Errorf("allowed references were reported: %s", text)
	}
	lines := strings.Join(se.FixLines(), "\n")
	for _, want := range []string{"credentials: [github_token]", "allowed_hosts: [auth.evil.example, evil.example]"} {
		if !strings.Contains(lines, want) {
			t.Errorf("fix lines %q lack %q", lines, want)
		}
	}

	// The fix lines make it pass.
	creds = NewCredentialScope(scopeEntry, []string{scopeForeignCred}, nil)
	hosts, _ = NewHostScope(scopeBaseURL, []string{"auth.evil.example", "evil.example"})
	if err := CheckScope(spec, creds, hosts); err != nil {
		t.Errorf("with the fix lines: %v", err)
	}
}

func TestCheckScope_SessionLogin(t *testing.T) {
	spec := &Spec{Backend: BackendDef{
		Name:    scopeEntry,
		BaseURL: scopeBaseURL,
		Auth: AuthConfig{
			Type: authTypeSession,
			Login: &SessionLogin{
				Method: http.MethodPost,
				Path:   "@evil.example/login",
				Body:   map[string]any{"params": map[string]any{scopeUserKey: "credential:other_user"}},
			},
		},
	}}
	err := CheckScope(spec, NewCredentialScope(scopeEntry, nil, nil), mustHostScope(t))
	if err == nil {
		t.Fatal("expected violations")
	}
	for _, want := range []string{`auth.login.body "other_user"`, "auth.login.path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func mustHostScope(t *testing.T) *HostScope {
	t.Helper()
	s, err := NewHostScope(scopeBaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRestAuth_ScopeAtRuntime pins the second line behind CheckScope: a
// RestAuth bound to scopes refuses a credential outside its namespace and
// does not send credentials to a host outside its hosts, also when the
// load-time check was bypassed.
func TestRestAuth_ScopeAtRuntime(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	creds := mapCreds{"shelly_cloud_key": "k", scopeForeignCred: hardeningSecret}

	t.Run("credential outside the namespace", func(t *testing.T) {
		a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: scopeForeignCred}, scopeBaseURL, creds, logger)
		a.SetScope(NewCredentialScope(scopeEntry, nil, nil), mustHostScope(t))
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, scopeBaseURL+"/x", nil)
		err := a.InjectAuth(context.Background(), req)
		if !errors.Is(err, ErrCredentialOutOfScope) {
			t.Fatalf("InjectAuth = %v, want ErrCredentialOutOfScope", err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Error("the credential was injected")
		}
	})

	t.Run("request to a foreign host", func(t *testing.T) {
		a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: "shelly_cloud_key"}, scopeBaseURL, creds, logger)
		a.SetScope(NewCredentialScope(scopeEntry, nil, nil), mustHostScope(t))
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://evil.example/x", nil)
		if err := a.InjectAuth(context.Background(), req); err == nil {
			t.Fatal("credentials were attached for a foreign host")
		}
		if req.Header.Get("Authorization") != "" {
			t.Error("the credential was injected")
		}
	})

	t.Run("token_url on a foreign host", func(t *testing.T) {
		var sent atomic.Int32
		a := NewRestAuth(AuthConfig{ //nolint:gosec // test fixture with credential names, not credentials
			Type: authTypeOAuth2, TokenURL: "https://auth.evil.example/token",
			ClientIDCredential: "shelly_cloud_id", ClientSecretCredential: "shelly_cloud_secret",
		}, scopeBaseURL, mapCreds{"shelly_cloud_id": "i", "shelly_cloud_secret": hardeningSecret}, logger)
		a.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
			sent.Add(1)
			return nil, io.ErrUnexpectedEOF
		}))
		a.SetScope(NewCredentialScope(scopeEntry, nil, nil), mustHostScope(t))
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, scopeBaseURL+"/x", nil)
		if err := a.InjectAuth(context.Background(), req); err == nil {
			t.Fatal("expected the token request to be refused")
		}
		if sent.Load() != 0 {
			t.Error("the client secret was sent to a foreign token_url")
		}
	})
}

// TestScope_NoCredentialPlaceholder pins that "credential: none", the
// placeholder of DADLs for APIs without authentication, passes the binding
// and is never looked up: the call goes out without auth as before.
func TestScope_NoCredentialPlaceholder(t *testing.T) {
	spec := &Spec{Backend: BackendDef{
		Name: "hackernews", BaseURL: "https://hacker-news.firebaseio.com/v0",
		Auth:  AuthConfig{Type: authTypeAPIKey, Credential: NoCredential, InjectInto: authInjectQuery, QueryParam: "key"},
		Tools: map[string]ToolDef{"top": {Method: httpMethodGET, Path: "/topstories.json"}},
	}}
	creds := NewCredentialScope("hackernews", nil, nil)
	hosts, err := NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckScope(spec, creds, hosts); err != nil {
		t.Fatalf("CheckScope: %v", err)
	}

	looked := false
	store := lookupRecorder{onGet: func() { looked = true }}
	a := NewRestAuth(spec.Backend.Auth, spec.Backend.BaseURL, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.SetScope(creds, hosts)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, spec.Backend.BaseURL+"/topstories.json", nil)
	if err := a.InjectAuth(context.Background(), req); err != nil {
		t.Fatalf("InjectAuth: %v", err)
	}
	if looked || req.URL.RawQuery != "" {
		t.Errorf("placeholder was looked up (%v) or injected (%q)", looked, req.URL.RawQuery)
	}
}

// lookupRecorder is a CredentialStore that reports every lookup.
type lookupRecorder struct{ onGet func() }

func (l lookupRecorder) Get(context.Context, string, credentials.TenantInfo) (string, error) {
	l.onGet()
	return "secret-from-store", nil
}

func (l lookupRecorder) Healthy(context.Context) error { return nil }
