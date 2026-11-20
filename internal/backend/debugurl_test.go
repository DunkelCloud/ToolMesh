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
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_DebugLogHidesQueryKey pins that the debug trace of a
// backend request shows the URL without the API key a backend sends in its
// query string. The key goes to the API as before; the log names the
// parameter and that a value was sent, not the value.
func TestRESTAdapter_DebugLogHidesQueryKey(t *testing.T) {
	const (
		keyParam  = "access_key"
		keyName   = "debug_api_key" //nolint:gosec // credential name, not a credential
		keySecret = "s3cr3t-value-0123456789"
	)
	var sent atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get(keyParam)
		sent.Store(&q)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	const tool = "lookup"
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: "apikey", Credential: keyName, InjectInto: authInjectQuery, QueryParam: keyParam},
			Tools: map[string]dadl.ToolDef{
				tool: {Method: testMethodGET, Path: "/lookup", Params: map[string]dadl.ParamDef{
					"term": {Type: schemaTypeString, In: paramInQuery, Required: true},
				}},
			},
		},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{keyName: keySecret}}, logger, testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), tool, map[string]any{"term": "ToolMesh"})
	if err != nil || result.IsError {
		t.Fatalf("Execute: %v %+v", err, result)
	}
	if got := sent.Load(); got == nil || *got != keySecret {
		t.Fatalf("the API did not receive the key: %v", got)
	}

	out := logs.String()
	if !strings.Contains(out, "REST request") {
		t.Fatalf("no debug trace of the request:\n%s", out)
	}
	if strings.Contains(out, keySecret) {
		t.Errorf("the debug log carries the API key:\n%s", out)
	}
	for _, want := range []string{keyParam + "=%5BREDACTED%5D", "term=ToolMesh"} {
		if !strings.Contains(out, want) {
			t.Errorf("the debug log lacks %q:\n%s", want, out)
		}
	}
}
