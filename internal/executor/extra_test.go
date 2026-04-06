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

package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// mockCreds is a credential store that returns preset values.
type mockCreds struct {
	get    map[string]string
	listed map[string]string
	err    error
}

func (m *mockCreds) Get(_ context.Context, name string, _ credentials.TenantInfo) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	v, ok := m.get[name]
	if !ok {
		return "", credentials.ErrCredentialNotFound
	}
	return v, nil
}

func (m *mockCreds) ListByPrefix(_ context.Context, _ string, _ credentials.TenantInfo) (map[string]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listed, nil
}

func (m *mockCreds) Healthy(_ context.Context) error { return nil }

func TestResolveCredentials_PrefixLister(t *testing.T) {
	exec := New(nil, &mockCreds{listed: map[string]string{"GITHUB_TOKEN": "tok"}}, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil)
	got := exec.resolveCredentials(context.Background(), "github", credentials.TenantInfo{})
	if got["GITHUB_TOKEN"] != "tok" {
		t.Errorf("got %v", got)
	}
}

func TestResolveCredentials_Fallback(t *testing.T) {
	// No prefix match but Get finds a credential.
	exec := New(nil, &mockCreds{
		get:    map[string]string{"GITHUB_API_KEY": "fallback-key"},
		listed: map[string]string{}, // empty prefix listing
	}, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil)
	got := exec.resolveCredentials(context.Background(), "github", credentials.TenantInfo{})
	if got["GITHUB_API_KEY"] != "fallback-key" {
		t.Errorf("got %v", got)
	}
}

func TestResolveCredentials_NoneFound(t *testing.T) {
	exec := New(nil, &mockCreds{get: map[string]string{}, listed: map[string]string{}}, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil)
	got := exec.resolveCredentials(context.Background(), "github", credentials.TenantInfo{})
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestFilterAuthorizedTools_NoAuthorizer(t *testing.T) {
	exec := New(nil, nil, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil)
	tools := []backend.ToolDescriptor{{Name: "a"}, {Name: "b"}}
	got := exec.FilterAuthorizedTools(context.Background(), "u1", tools)
	if len(got) != 2 {
		t.Errorf("expected passthrough when no authorizer, got %d", len(got))
	}
}

func TestFilterAuthorizedTools_WithAuthorizer(t *testing.T) {
	// Spin up an httptest server that mocks OpenFGA and allows only "a".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/check") {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `tool:a`) {
				_, _ = w.Write([]byte(`{"allowed": true}`))
			} else {
				_, _ = w.Write([]byte(`{"allowed": false}`))
			}
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	authorizer, err := authz.NewAuthorizer(srv.URL, "01ARZ3NDEKTSV4RRFFQ69G5FAV", newTestLogger())
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	exec := New(authorizer, nil, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil)
	tools := []backend.ToolDescriptor{{Name: "a"}, {Name: "b"}}
	got := exec.FilterAuthorizedTools(context.Background(), "u1", tools)
	if len(got) != 1 || got[0].Name != "a" {
		t.Errorf("filtered = %v", got)
	}
}

var _ = userctx.WithUserContext
var _ = errors.New
