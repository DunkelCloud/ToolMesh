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

package backend

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestRESTAdapter_Setters(t *testing.T) {
	spec := &dadl.Spec{
		Spec:    "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{Name: "t", Type: "rest", BaseURL: "https://api.example.com"},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	a.SetBlobTTL(30 * time.Minute)
	if a.blobTTL != 30*time.Minute {
		t.Errorf("blobTTL = %v", a.blobTTL)
	}
	a.SetHTTPTimeout(42 * time.Second)
	if a.httpClient.Timeout != 42*time.Second {
		t.Errorf("httpClient timeout = %v", a.httpClient.Timeout)
	}
	a.SetStreamingHTTPTimeout(13 * time.Second)
	if a.streamingHTTPClient.Timeout != 13*time.Second {
		t.Errorf("streaming timeout = %v", a.streamingHTTPClient.Timeout)
	}
}

func TestRESTAdapter_Healthy(t *testing.T) {
	// Upstream that responds 200 to HEAD.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec:    "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{Name: "t", Type: "rest", BaseURL: srv.URL},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Healthy(context.Background()); err != nil {
		t.Errorf("Healthy: %v", err)
	}
}

func TestRESTAdapter_Healthy_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec:    "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{Name: "t", Type: "rest", BaseURL: srv.URL},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err := a.Healthy(context.Background()); err == nil {
		t.Error("expected error for 500 health check")
	}
}

func TestRESTAdapter_Execute_UnknownTool(t *testing.T) {
	spec := &dadl.Spec{
		Spec:    "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{Name: "t", Type: "rest", BaseURL: "https://api.example.com"},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	_, err := a.Execute(context.Background(), "nonexistent", nil)
	if err == nil {
		t.Error("expected error for unknown tool")
	}
}
