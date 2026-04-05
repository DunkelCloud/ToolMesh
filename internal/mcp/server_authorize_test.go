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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

func TestAuthorize_GetRendersLoginForm(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{AuthPassword: "pw"})

	// Register first.
	regBody := `{"redirect_uris": ["https://example.com/cb"], "client_name": "t"}`
	regReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	mux.ServeHTTP(regW, regReq)
	var regResp map[string]any
	_ = json.NewDecoder(regW.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	url := "/authorize?client_id=" + clientID + "&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&state=s1&code_challenge=x&code_challenge_method=S256"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ToolMesh") {
		t.Error("expected login form")
	}
}

func TestAuthorize_GetInvalidChallengeMethod(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	url := "/authorize?client_id=c&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=x&code_challenge_method=plain"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d", w.Code)
	}
}

func TestAuthorize_GetUnknownClient(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	url := "/authorize?client_id=nonexistent&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&code_challenge=x"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d", w.Code)
	}
}

func TestAuthorize_MethodNotAllowed(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/authorize", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d", w.Code)
	}
}

func TestToken_MethodNotAllowed(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d", w.Code)
	}
}

func TestRegister_MethodNotAllowed(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d", w.Code)
	}
}
