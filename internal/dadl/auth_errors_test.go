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
	"net/http"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// errMockCreds always returns the provided error from Get.
type errMockCreds struct{ err error }

func (m *errMockCreds) Get(_ context.Context, _ string, _ credentials.TenantInfo) (string, error) {
	return "", m.err
}
func (m *errMockCreds) Healthy(_ context.Context) error { return nil }

func TestRestAuth_InjectBearer_UnexpectedError(t *testing.T) {
	auth := NewRestAuth(
		AuthConfig{Type: "bearer", Credential: "X"},
		"", &errMockCreds{err: errors.New("backend exploded")},
		newQuietLogger(),
	)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected error")
	}
}

func TestRestAuth_InjectAPIKey_UnexpectedError(t *testing.T) {
	auth := NewRestAuth(
		AuthConfig{Type: "apikey", Credential: "X"},
		"", &errMockCreds{err: errors.New("broken")},
		newQuietLogger(),
	)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected error")
	}
}

func TestRestAuth_InjectAPIKey_Missing(t *testing.T) {
	auth := NewRestAuth(
		AuthConfig{Type: "apikey", Credential: "MISSING", InjectInto: "header", HeaderName: "X-API"},
		"", &realMockCreds{creds: map[string]string{}},
		newQuietLogger(),
	)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Errorf("missing credential should be skipped, got %v", err)
	}
	if req.Header.Get("X-API") != "" {
		t.Error("header should not be set when credential missing")
	}
}

func TestRestAuth_InjectBasic_PasswordError(t *testing.T) {
	// Username is present but password lookup returns unexpected error.
	creds := &errMockCredsSelective{
		values: map[string]string{"USER": "alice"},
		errFor: "PASS",
		err:    errors.New("vault down"),
	}
	auth := NewRestAuth(
		AuthConfig{
			Type:               "basic",
			UsernameCredential: "USER",
			PasswordCredential: "PASS",
		}, "", creds, newQuietLogger())
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected error")
	}
}

type errMockCredsSelective struct {
	values map[string]string
	errFor string
	err    error
}

func (m *errMockCredsSelective) Get(_ context.Context, name string, _ credentials.TenantInfo) (string, error) {
	if name == m.errFor {
		return "", m.err
	}
	v, ok := m.values[name]
	if !ok {
		return "", credentials.ErrCredentialNotFound
	}
	return v, nil
}
func (m *errMockCredsSelective) Healthy(_ context.Context) error { return nil }

func TestRestAuth_OAuth2_ClientSecretError(t *testing.T) {
	creds := &errMockCredsSelective{
		values: map[string]string{"CID": "c"},
		errFor: "SEC",
		err:    errors.New("vault error"),
	}
	auth := NewRestAuth(AuthConfig{ //nolint:gosec // test credentials, not real
		Type:                   "oauth2",
		ClientIDCredential:     "CID",
		ClientSecretCredential: "SEC",
		TokenURL:               "http://example.com/token",
	}, "", creds, newQuietLogger())
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected error")
	}
}

func TestRestAuth_InjectBasic_PasswordMissing(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{"U": "alice"}}
	auth := NewRestAuth(AuthConfig{
		Type:               "basic",
		UsernameCredential: "U",
		PasswordCredential: "MISSING",
	}, "", creds, newQuietLogger())
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Errorf("missing password should be skipped, got %v", err)
	}
}
