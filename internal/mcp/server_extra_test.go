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

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

const (
	initBodyExtra     = `{"jsonrpc": "2.0", "id": 1, "method": "initialize"}`
	invalidGrantError = "invalid_grant"
)

func TestOriginAllowed(t *testing.T) {
	srv, _ := newTestServer(t, &config.Config{
		CORSAllowedOrigins: []string{
			"https://claude.ai",
			"*.example.com",
		},
	})

	tests := []struct {
		origin string
		want   bool
	}{
		{"https://claude.ai", true},
		{"https://foo.example.com", true},
		{"https://bar.example.com", true},
		{"https://evil-example.com", false}, // must not match *.example.com
		{"https://example.com", true},       // apex matches *.example.com
		{"https://other.org", false},
		{"not a url", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := srv.originAllowed(tt.origin); got != tt.want {
				t.Errorf("originAllowed(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{"no xff fallback to remote", "", "203.0.113.5:443", "203.0.113.5"},
		{"single public xff", "198.51.100.7", "10.0.0.1:443", "198.51.100.7"},
		{"private on right, public on left", "198.51.100.7, 10.0.0.1", "10.0.0.1:443", "198.51.100.7"},
		{"all private xff falls back to remote", "10.0.0.1, 192.168.1.1", "203.0.113.8:443", "203.0.113.8"},
		{"malformed entries skipped", "garbage, 198.51.100.9", "10.0.0.1:443", "198.51.100.9"},
		{"remote addr without port", "", "bare-host", "bare-host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(r); got != tt.want {
				t.Errorf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractBearer(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc123")
	if got := extractBearer(r); got != "abc123" {
		t.Errorf("extractBearer = %q", got)
	}

	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r2.Header.Set("Authorization", "Basic xyz")
	if got := extractBearer(r2); got != "" {
		t.Errorf("non-Bearer must return empty, got %q", got)
	}
}

func TestMCP_InvalidContentType(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})
	body := initBodyExtra
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	// Wrong content type.
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	errObj, _ := resp["error"].(map[string]any)
	if errObj == nil || errObj["code"].(float64) != -32700 {
		t.Errorf("expected parse error, got %v", resp)
	}
}

func TestMCP_BodyTooLarge(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})
	// >10 MB body.
	big := bytes.Repeat([]byte("x"), 11<<20)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Body is consumed via JSON decoder which will fail; server returns Parse error.
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == nil {
		t.Error("expected error for oversized body")
	}
}

func TestMCP_Notification_Returns202(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})
	// No "id" field → notification → 202.
	body := `{"jsonrpc": "2.0", "method": "initialized"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", w.Code)
	}
}

func TestAuthenticate_Anonymous(t *testing.T) {
	srv, _ := newTestServer(t, &config.Config{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	uc := srv.authenticate(req)
	if uc.Authenticated {
		t.Error("expected Authenticated=false for anonymous")
	}
	if uc.UserID != "anonymous" {
		t.Errorf("got UserID=%q, want anonymous", uc.UserID)
	}
}

func TestAuthenticate_APIKey_Legacy(t *testing.T) {
	srv, _ := newTestServer(t, &config.Config{APIKey: "my-secret"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-secret")
	uc := srv.authenticate(req)
	if !uc.Authenticated {
		t.Error("expected Authenticated=true for matching API key")
	}

	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer wrong")
	uc2 := srv.authenticate(req2)
	if uc2.Authenticated {
		t.Error("expected Authenticated=false for wrong API key")
	}
}

func TestTokenGrant_ClientIDMismatch(t *testing.T) {
	// Register a client and get an auth code, then attempt to exchange it
	// with the wrong client_id — should fail with invalid_grant.
	_, mux, _ := newTestServerWithRedis(t, &config.Config{
		AuthPassword: "pw",
		Issuer:       "https://toolmesh.io/",
	})

	regBody := `{"redirect_uris": ["https://example.com/cb"], "client_name": "t"}`
	regReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	mux.ServeHTTP(regW, regReq)
	var regResp map[string]any
	_ = json.NewDecoder(regW.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Get an auth code via form POST.
	codeVerifier := "verifier-with-enough-entropy-01234567890"
	// Any S256 challenge works since we won't actually reach PKCE verification.
	form := url.Values{
		"password":       {"pw"},
		"client_id":      {clientID},
		"redirect_uri":   {"https://example.com/cb"},
		"state":          {"s"},
		"code_challenge": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"scope":          {"claudeai"},
	}
	authReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authW := httptest.NewRecorder()
	mux.ServeHTTP(authW, authReq)
	loc := authW.Header().Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")

	// Exchange with wrong client_id.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"client_id":     {"wrong-client-id"},
	}
	tokReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokW := httptest.NewRecorder()
	mux.ServeHTTP(tokW, tokReq)

	var tokResp map[string]any
	_ = json.NewDecoder(tokW.Body).Decode(&tokResp)
	if tokResp["error"] != invalidGrantError {
		t.Errorf("expected invalid_grant for client_id mismatch, got %v", tokResp)
	}
}

func TestRefreshTokenGrant_MissingClientID(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"whatever"},
		// no client_id
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != invalidGrantError {
		t.Errorf("expected invalid_grant, got %v", resp)
	}
}

func TestRegister_InvalidRedirectURI(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	body := `{"redirect_uris": ["http://evil.example.com/cb"], "client_name": "x"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRegister_WrongContentType(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAuthorize_MissingPKCE(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?client_id=x&redirect_uri=https://example.com/cb", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
