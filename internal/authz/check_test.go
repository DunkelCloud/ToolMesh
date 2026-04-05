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

package authz

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockFGA spins up an httptest server that mimics the minimal OpenFGA
// endpoints used by Check() and Healthy(). The allow param decides what
// the /check endpoint returns.
func mockFGA(allow bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/check"):
			if allow {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"allowed": true}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"allowed": false}`))
			}
		case r.URL.Path == "/stores":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"stores": []}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
}

func newAuthzForTest(t *testing.T, srv *httptest.Server) *Authorizer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	a, err := NewAuthorizer(srv.URL, "01ARZ3NDEKTSV4RRFFQ69G5FAV", logger)
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	return a
}

func TestAuthorizer_Check_Allowed(t *testing.T) {
	srv := mockFGA(true)
	defer srv.Close()

	a := newAuthzForTest(t, srv)
	allowed, err := a.Check(context.Background(), "u1", "test:echo")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

func TestAuthorizer_Check_Denied(t *testing.T) {
	srv := mockFGA(false)
	defer srv.Close()

	a := newAuthzForTest(t, srv)
	allowed, err := a.Check(context.Background(), "u1", "test:echo")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
}

func TestAuthorizer_Healthy(t *testing.T) {
	srv := mockFGA(true)
	defer srv.Close()

	a := newAuthzForTest(t, srv)
	if err := a.Healthy(context.Background()); err != nil {
		t.Errorf("Healthy: %v", err)
	}
}
