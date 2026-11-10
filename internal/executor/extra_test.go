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
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// recordingCreds is a credential store that counts every read.
type recordingCreds struct{ reads atomic.Int32 }

func (r *recordingCreds) Get(context.Context, string, credentials.TenantInfo) (string, error) {
	r.reads.Add(1)
	return "store-read", nil
}

func (r *recordingCreds) ListByPrefix(context.Context, string, credentials.TenantInfo) (map[string]string, error) {
	r.reads.Add(1)
	return map[string]string{"GITHUB_TOKEN": "store-list"}, nil
}

func (r *recordingCreds) Healthy(context.Context) error { return nil }

// TestExecuteTool_ReadsNoCredentials pins that the executor reads no
// credentials for a call: each backend reads its own, within its credential
// binding, when it sends a request. A listing by the tool's name prefix
// would read outside that binding.
func TestExecuteTool_ReadsNoCredentials(t *testing.T) {
	store := &recordingCreds{}
	exec := New(nil, store, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil, nil)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})
	if _, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "github_list_repos"}); err != nil {
		t.Fatal(err)
	}
	if n := store.reads.Load(); n != 0 {
		t.Errorf("the executor read the credential store %d times", n)
	}
}

func TestFilterAuthorizedTools_NoAuthorizer(t *testing.T) {
	exec := New(nil, nil, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil, nil)
	tools := []backend.ToolDescriptor{{Name: "a"}, {Name: "b"}}
	got := exec.FilterAuthorizedTools(context.Background(), &userctx.UserContext{UserID: "u1"}, tools)
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

	authorizer, err := authz.NewExternal(srv.URL, "01ARZ3NDEKTSV4RRFFQ69G5FAV", newTestLogger())
	if err != nil {
		t.Fatalf("NewExternal: %v", err)
	}
	exec := New(authorizer, nil, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil, nil)
	tools := []backend.ToolDescriptor{{Name: "a"}, {Name: "b"}}
	got := exec.FilterAuthorizedTools(context.Background(), &userctx.UserContext{UserID: "u1"}, tools)
	if len(got) != 1 || got[0].Name != "a" {
		t.Errorf("filtered = %v", got)
	}
}

var _ = userctx.WithUserContext
var _ = errors.New
