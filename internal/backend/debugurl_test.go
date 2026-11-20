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
	"net/url"
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

// TestRESTAdapter_LoggableURL pins the two cases the plain case does not
// show: a DADL without query_param sends the key under an empty name, and
// a base URL can carry a password.
func TestRESTAdapter_LoggableURL(t *testing.T) {
	const secret = "s3cr3t-value-9876543210"
	parse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	adapter := func(auth dadl.AuthConfig) *RESTAdapter {
		return &RESTAdapter{spec: &dadl.Spec{Backend: dadl.BackendDef{Auth: auth}}}
	}
	cases := []struct {
		name string
		auth dadl.AuthConfig
		url  string
		want string
	}{
		{"named parameter", dadl.AuthConfig{InjectInto: authInjectQuery, QueryParam: "key"},
			"https://api.example.com/x?key=" + secret + "&term=a", "https://api.example.com/x?key=%5BREDACTED%5D&term=a"},
		{"empty parameter name", dadl.AuthConfig{InjectInto: authInjectQuery},
			"https://api.example.com/x?=" + secret + "&term=a", "https://api.example.com/x?=%5BREDACTED%5D&term=a"},
		{"password in the URL", dadl.AuthConfig{},
			"https://svc:" + secret + "@api.example.com/x?term=a", "https://svc:xxxxx@api.example.com/x?term=a"},
		{"header auth leaves the query alone", dadl.AuthConfig{InjectInto: "header"},
			"https://api.example.com/x?key=visible", "https://api.example.com/x?key=visible"},
	}
	for _, c := range cases {
		got := adapter(c.auth).loggableURL(parse(c.url))
		if got != c.want || strings.Contains(got, secret) {
			t.Errorf("%s: loggableURL = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestLoggableEndpoint pins what a log line shows of a backend's configured
// URL: no query string and no password, where a credential may sit.
func TestLoggableEndpoint(t *testing.T) {
	const endpoint = "https://tools.example.org/stream"
	cases := map[string]string{
		"":                                    "",
		endpoint:                              endpoint,
		endpoint + "?api_key=s3cr3t&x=1#frag": endpoint,
		"https://user:s3cr3t@mcp.example.com/mcp": "https://user@mcp.example.com/mcp",
	}
	for raw, want := range cases {
		if got := loggableEndpoint(raw); got != want {
			t.Errorf("loggableEndpoint(%q) = %q, want %q", raw, got, want)
		}
	}
}
