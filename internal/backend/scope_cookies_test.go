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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_SessionCookieStaysOnPort pins, end to end, that the
// session cookie of a session-auth backend does not follow a redirect from
// the base host to the same host on another port, which the host binding
// refuses. The redirect checker strips the auth headers there, but Go adds
// jar cookies after CheckRedirect, and a cookie jar ignores ports.
func TestRESTAdapter_SessionCookieStaysOnPort(t *testing.T) {
	other := &headerRecorder{}
	otherSrv := httptest.NewServer(other)
	defer otherSrv.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "S3SSION", Path: "/"}) //nolint:gosec // test cookie, attributes do not matter
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.Redirect(w, r, otherSrv.URL+"/landing", http.StatusFound)
	}))
	defer origin.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    scopeEntryName,
			Type:    transportTypeREST,
			BaseURL: origin.URL,
			Auth: dadl.AuthConfig{
				Type: "session",
				Login: &dadl.SessionLogin{
					Method: http.MethodPost,
					Path:   "/login",
					Body:   map[string]any{"user": "credential:mine_user"},
				},
			},
			Tools: map[string]dadl.ToolDef{
				redirectTestTool: {Method: testMethodGET, Path: redirectTestPath},
				// Outside include_tools; it only names the other port.
				"elsewhere": {Method: testMethodGET, Path: otherSrv.URL + "/x"},
			},
		},
	}
	opts := testRESTOpts
	opts.IncludeTools = []string{redirectTestTool}
	opts.Scope = &BackendScope{EntryName: scopeEntryName, Owners: dadl.NewCredentialOwners(scopeEntryName)}
	a, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{"mine_user": "alice"}}, quietLogger(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Execute(context.Background(), redirectTestTool, nil); err != nil {
		t.Logf("execute: %v", err)
	}
	if _, h := other.snapshot(); h.Get("Cookie") != "" {
		t.Errorf("the session cookie %q reached %s, which the host binding refuses", h.Get("Cookie"), otherSrv.URL)
	}
}
