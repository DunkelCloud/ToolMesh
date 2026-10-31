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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Fixture values of the health tests.
const (
	healthTestToken      = "health-secret-token" //nolint:gosec // test credential literal
	healthTestRawBody    = "RAW-UPSTREAM-BODY"
	healthTestStatusPath = "/status"

	healthBlockInline     = "  health:\n    path: /status"
	healthBlockExpectPath = "  health:\n    path: /status\n    expect_path: $.status"
)

// healthDADL renders a DADL for the health tests: bearer auth, a
// parameterless get_me tool with a response pipeline, and the given health
// block and auth/defaults overrides.
func healthDADL(baseURL, health, defaults string) string {
	return fmt.Sprintf(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: healthapi
  type: rest
  base_url: %s
  auth:
    type: bearer
    credential: api_token
%s
%s
  tools:
    get_me:
      method: GET
      path: /me
      access: read
      params:
        verbose: { type: boolean, in: query, default: false }
      response:
        result_path: $.data
`, baseURL, defaults, health)
}

// newHealthAdapter parses doc and builds an adapter with the test token.
func newHealthAdapter(t *testing.T, doc string, opts RESTAdapterOptions) *RESTAdapter {
	t.Helper()
	spec, err := dadl.ParseBytes([]byte(doc))
	if err != nil {
		t.Fatalf("parse dadl: %v", err)
	}
	creds := &testCredStore{creds: map[string]string{"api_token": healthTestToken}}
	a, err := NewRESTAdapter(spec, creds, slog.Default(), opts)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	return a
}

// healthServer answers every request with status and body and records the
// last request.
type healthServer struct {
	mu     sync.Mutex
	status int
	body   string
	last   *http.Request
	calls  int
}

func (h *healthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.last, h.calls = r, h.calls+1
	status, body := h.status, h.body
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestRESTAdapter_CheckHealth_Outcomes(t *testing.T) {
	expiry := time.Date(2026, 10, 16, 23, 42, 0, 0, time.UTC)
	tests := []struct {
		name       string
		health     string
		defaults   string
		status     int
		body       string
		wantOK     bool
		wantError  string // substring of Error; "" = no error
		wantReason string
		wantExpiry time.Time
	}{
		{
			name:   "2xx passes",
			health: healthBlockInline,
			status: http.StatusOK, body: `{"status":"ok"}`, wantOK: true,
		},
		{
			name:   "401 maps to unauthorized with the provider message",
			health: healthBlockInline, defaults: "  defaults:\n    errors:\n      message_path: $.error.message",
			status: http.StatusUnauthorized, body: `{"error":{"message":"token expired"}}`,
			wantError: "[unauthorized] HTTP 401: token expired", wantReason: "unauthorized (HTTP 401)",
		},
		{
			name:   "raw body never becomes the message",
			health: healthBlockInline, defaults: "  defaults:\n    errors:\n      message_path: $.error.message",
			status: http.StatusInternalServerError, body: healthTestRawBody,
			wantError: "[internal] HTTP 500", wantReason: "internal (HTTP 500)",
		},
		{
			name:   "errors.map overrides the default code",
			health: healthBlockInline, defaults: "  defaults:\n    errors:\n      map:\n        403: token_revoked",
			status: http.StatusForbidden, body: `{}`,
			wantError: "[token_revoked] HTTP 403", wantReason: "token_revoked (HTTP 403)",
		},
		{
			name:   "2xx other than expect_status fails",
			health: "  health:\n    path: /status\n    expect_status: 204",
			status: http.StatusOK, body: `{}`,
			wantError: "[unexpected_status] HTTP 200; expected HTTP 204", wantReason: "unexpected_status (HTTP 200)",
		},
		{
			name:   "non-2xx expect_status passes",
			health: "  health:\n    path: /status\n    expect_status: 404",
			status: http.StatusNotFound, body: `{}`, wantOK: true,
		},
		{
			name:   "expect_path present",
			health: healthBlockExpectPath,
			status: http.StatusOK, body: `{"status":false}`, wantOK: true,
		},
		{
			name:   "expect_path missing",
			health: healthBlockExpectPath,
			status: http.StatusOK, body: `{"state":"ok"}`,
			wantError: "no value at $.status", wantReason: "expect_path $.status missing (HTTP 200)",
		},
		{
			name:   "expect_path on a non-JSON body",
			health: healthBlockExpectPath,
			status: http.StatusOK, body: healthTestRawBody,
			wantError: "no value at $.status",
		},
		{
			name:   "auth_expires_path RFC 3339",
			health: "  health:\n    path: /status\n    auth_expires_path: $.token.expires_at",
			status: http.StatusOK, body: `{"token":{"expires_at":"2026-10-16T23:42:00Z"}}`,
			wantOK: true, wantExpiry: expiry,
		},
		{
			name:   "auth_expires_path epoch seconds",
			health: "  health:\n    path: /status\n    auth_expires_path: $.exp",
			status: http.StatusOK, body: fmt.Sprintf(`{"exp":%d}`, expiry.Unix()),
			wantOK: true, wantExpiry: expiry,
		},
		{
			name:   "auth_expires_path unparsable is unknown",
			health: "  health:\n    path: /status\n    auth_expires_path: $.exp",
			status: http.StatusOK, body: `{"exp":"soon"}`, wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(&healthServer{status: tt.status, body: tt.body})
			defer srv.Close()
			a := newHealthAdapter(t, healthDADL(srv.URL, tt.health, tt.defaults), testRESTOpts)

			res := a.CheckHealth(context.Background())
			if res.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v (error %q)", res.OK, tt.wantOK, res.Error)
			}
			if res.HTTPStatus != tt.status || res.ErrorCode != "" {
				t.Errorf("HTTPStatus, ErrorCode = %d, %q; want %d, none", res.HTTPStatus, res.ErrorCode, tt.status)
			}
			if tt.wantError == "" && res.Error != "" {
				t.Errorf("Error = %q, want none", res.Error)
			}
			if !strings.Contains(res.Error, tt.wantError) {
				t.Errorf("Error = %q, want containing %q", res.Error, tt.wantError)
			}
			if tt.wantReason != "" && res.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", res.Reason, tt.wantReason)
			}
			if strings.Contains(res.Error, healthTestRawBody) || strings.Contains(res.Reason, healthTestRawBody) {
				t.Errorf("raw response body leaked into the result: %+v", res)
			}
			if !res.AuthExpiresAt.Equal(tt.wantExpiry) {
				t.Errorf("AuthExpiresAt = %s, want %s", res.AuthExpiresAt, tt.wantExpiry)
			}
			if res.CheckedAt.IsZero() || res.Latency < 0 {
				t.Errorf("CheckedAt, Latency = %s, %s; want set", res.CheckedAt, res.Latency)
			}
		})
	}
}

// A form-1 check sends the referenced tool's request — path, defaults and
// injected auth — and evaluates the raw body: the tool's result_path does
// not apply.
func TestRESTAdapter_CheckHealth_ToolReference(t *testing.T) {
	hs := &healthServer{status: http.StatusOK, body: `{"data":{"id":1},"meta":{"ok":true}}`}
	srv := httptest.NewServer(hs)
	defer srv.Close()
	a := newHealthAdapter(t, healthDADL(srv.URL, "  health:\n    tool: get_me\n    expect_path: $.meta.ok", ""), testRESTOpts)

	res := a.CheckHealth(context.Background())
	if !res.OK {
		t.Fatalf("check failed: %+v", res)
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.last.URL.Path != "/me" || hs.last.URL.RawQuery != "verbose=false" {
		t.Errorf("request = %s?%s, want /me?verbose=false", hs.last.URL.Path, hs.last.URL.RawQuery)
	}
	if got := hs.last.Header.Get("Authorization"); got != "Bearer "+healthTestToken {
		t.Errorf("Authorization = %q, want the injected bearer token", got)
	}
}

// The operator's backends.yaml expiry fills auth_expires_at when the
// response reports none; the API's own answer takes precedence.
func TestRESTAdapter_CheckHealth_ExpiryPrecedence(t *testing.T) {
	operator := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	opts := testRESTOpts
	opts.AuthExpiresAt = operator

	srv := httptest.NewServer(&healthServer{status: http.StatusOK, body: `{"exp":"2026-10-16T23:42:00Z"}`})
	defer srv.Close()

	plain := newHealthAdapter(t, healthDADL(srv.URL, healthBlockInline, ""), opts)
	if got := plain.CheckHealth(context.Background()).AuthExpiresAt; !got.Equal(operator) {
		t.Errorf("without auth_expires_path: AuthExpiresAt = %s, want the operator value %s", got, operator)
	}

	withPath := newHealthAdapter(t, healthDADL(srv.URL, "  health:\n    path: /status\n    auth_expires_path: $.exp", ""), opts)
	want := time.Date(2026, 10, 16, 23, 42, 0, 0, time.UTC)
	if got := withPath.CheckHealth(context.Background()).AuthExpiresAt; !got.Equal(want) {
		t.Errorf("with auth_expires_path: AuthExpiresAt = %s, want the response value %s", got, want)
	}
}

func TestRESTAdapter_CheckHealth_TransportFailures(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		addr := closedLocalAddr(t)
		a := newHealthAdapter(t, healthDADL("http://"+addr, healthBlockInline, ""), testRESTOpts)
		res := a.CheckHealth(context.Background())
		if res.OK || res.HTTPStatus != 0 || res.ErrorCode != HealthErrConnectionRefused {
			t.Fatalf("result = %+v, want connection_refused without a status", res)
		}
		if res.Reason != "no response (connection_refused)" {
			t.Errorf("Reason = %q", res.Reason)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer srv.Close()
		defer close(release)
		a := newHealthAdapter(t, healthDADL(srv.URL, "  health:\n    path: /status\n    timeout: 100ms", ""), testRESTOpts)
		res := a.CheckHealth(context.Background())
		if res.OK || res.ErrorCode != HealthErrTimeout {
			t.Fatalf("result = %+v, want timeout", res)
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		srv := httptest.NewTLSServer(&healthServer{status: http.StatusOK, body: `{}`})
		defer srv.Close()
		a := newHealthAdapter(t, healthDADL(srv.URL, healthBlockInline, ""), testRESTOpts)
		res := a.CheckHealth(context.Background())
		if res.OK || res.ErrorCode != HealthErrTLS {
			t.Fatalf("result = %+v, want tls_error", res)
		}
	})

	t.Run("query credential stays out of the error", func(t *testing.T) {
		addr := closedLocalAddr(t)
		doc := strings.Replace(healthDADL("http://"+addr, healthBlockInline, ""),
			"    type: bearer\n    credential: api_token\n",
			"    type: apikey\n    credential: api_token\n    inject_into: query\n    query_param: key\n", 1)
		a := newHealthAdapter(t, doc, testRESTOpts)
		res := a.CheckHealth(context.Background())
		if res.OK || strings.Contains(res.Error, healthTestToken) {
			t.Fatalf("result = %+v, want a failure without the query credential", res)
		}
	})
}

func TestClassifyTransportError(t *testing.T) {
	wrap := func(err error) error {
		return &url.Error{Op: "Get", URL: "https://api.example.com/x?key=SECRET", Err: err}
	}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"deadline", wrap(context.DeadlineExceeded), HealthErrTimeout},
		{"dns", wrap(&net.DNSError{Err: "no such host", Name: "api.example.invalid", IsNotFound: true}), HealthErrDNS},
		{"refused", wrap(&net.OpError{Op: "dial", Err: errConnRefusedForTest(t)}), HealthErrConnectionRefused},
		{"net timeout", wrap(&net.OpError{Op: "dial", Err: timeoutErr{}}), HealthErrTimeout},
		{"anything else", wrap(errors.New("malformed HTTP response")), HealthErrProtocol},
	}
	for _, tt := range tests {
		if got := classifyTransportError(tt.err); got != tt.want {
			t.Errorf("%s: classifyTransportError = %q, want %q", tt.name, got, tt.want)
		}
		if strings.Contains(transportErrorMessage(tt.err), "SECRET") {
			t.Errorf("%s: transportErrorMessage leaks the request URL", tt.name)
		}
	}
}

// timeoutErr is a net.Error reporting a timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// closedLocalAddr returns a loopback address nobody listens on.
func closedLocalAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// errConnRefusedForTest returns the platform's refused-connection error by
// dialing a port nobody listens on.
func errConnRefusedForTest(t *testing.T) error {
	t.Helper()
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", closedLocalAddr(t))
	if err == nil {
		_ = conn.Close()
		return errors.New("dial unexpectedly succeeded")
	}
	return err
}

func TestHealthResult_MarshalJSON(t *testing.T) {
	res := HealthResult{
		OK:            false,
		HTTPStatus:    401,
		Latency:       1500 * time.Millisecond,
		CheckedAt:     time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		AuthExpiresAt: time.Date(2026, 10, 16, 23, 42, 0, 0, time.UTC),
		Error:         "[unauthorized] HTTP 401",
		Reason:        "unauthorized (HTTP 401)",
	}
	got, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"ok":false,"http_status":401,"latency_ms":1500,"checked_at":"2026-10-30T12:00:00Z","auth_expires_at":"2026-10-16T23:42:00Z","error":"[unauthorized] HTTP 401"}`
	if string(got) != want {
		t.Errorf("JSON = %s\nwant   %s", got, want)
	}

	got, _ = json.Marshal(HealthResult{OK: true, CheckedAt: res.CheckedAt})
	if string(got) != `{"ok":true,"latency_ms":0,"checked_at":"2026-10-30T12:00:00Z"}` {
		t.Errorf("passing JSON = %s, want only ok, latency_ms and checked_at", got)
	}
}

func TestRESTAdapter_SyntheticHealthTool(t *testing.T) {
	hs := &healthServer{status: http.StatusUnauthorized, body: `{}`}
	srv := httptest.NewServer(hs)
	defer srv.Close()
	a := newHealthAdapter(t, healthDADL(srv.URL, healthBlockInline, ""), testRESTOpts)

	tools, err := a.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found *ToolDescriptor
	for i := range tools {
		if tools[i].Name == dadl.HealthToolName {
			found = &tools[i]
		}
	}
	if found == nil {
		t.Fatalf("ListTools = %v, want the synthetic health tool", tools)
	}
	if !found.Unranked || found.Access != "read" || !strings.HasPrefix(found.Description, "Standardized backend health check") {
		t.Errorf("descriptor = %+v, want unranked, read, standardized description", found)
	}
	if d, ok := a.LookupTool(dadl.HealthToolName); !ok || !d.Unranked {
		t.Errorf("LookupTool(health) = %+v, %v; want the synthetic descriptor", d, ok)
	}

	var observed []HealthResult
	a.SetHealthObserver(func(name string, r HealthResult) {
		if name != "healthapi" {
			t.Errorf("observer got backend %q", name)
		}
		observed = append(observed, r)
	})

	result, err := a.Execute(context.Background(), dadl.HealthToolName, map[string]any{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("a failed check must be a successful call: %+v", result)
	}
	var wire map[string]any
	text := result.Content[0].(map[string]any)["text"].(string)
	if err := json.Unmarshal([]byte(text), &wire); err != nil {
		t.Fatalf("result is not JSON: %v: %s", err, text)
	}
	if wire["ok"] != false || wire["http_status"] != float64(401) || wire["error"] == nil {
		t.Errorf("result = %v, want ok false, http_status 401, an error", wire)
	}
	if len(observed) != 1 || observed[0].HTTPStatus != 401 {
		t.Errorf("observer saw %+v, want the one result", observed)
	}

	result, err = a.Execute(context.Background(), dadl.HealthToolName, map[string]any{"verbose": true})
	if err != nil || !result.IsError {
		t.Errorf("Execute with an argument = %+v, %v; want a parameter error result", result, err)
	}
}

// A declared tool named health takes precedence over the synthetic one.
func TestRESTAdapter_DeclaredHealthToolWins(t *testing.T) {
	hs := &healthServer{status: http.StatusOK, body: `{"raw":"declared"}`}
	srv := httptest.NewServer(hs)
	defer srv.Close()
	doc := healthDADL(srv.URL, healthBlockInline, "") + "    health:\n      method: GET\n      path: /healthz\n"
	a := newHealthAdapter(t, doc, testRESTOpts)

	result, err := a.Execute(context.Background(), dadl.HealthToolName, map[string]any{})
	if err != nil || result.IsError {
		t.Fatalf("Execute = %+v, %v", result, err)
	}
	if text := result.Content[0].(map[string]any)["text"].(string); text != `{"raw":"declared"}` {
		t.Errorf("result = %s, want the declared tool's raw response", text)
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.last.URL.Path != "/healthz" {
		t.Errorf("request path = %s, want the declared tool's /healthz", hs.last.URL.Path)
	}
	if d, _ := a.LookupTool(dadl.HealthToolName); d.Unranked {
		t.Error("the declared health tool must stay ranked")
	}
}

func TestRESTAdapter_HealthToolSurface(t *testing.T) {
	srv := httptest.NewServer(&healthServer{status: http.StatusOK, body: `{}`})
	defer srv.Close()

	listsHealth := func(a *RESTAdapter) bool {
		tools, _ := a.ListTools(context.Background())
		for _, tool := range tools {
			if tool.Name == dadl.HealthToolName {
				return true
			}
		}
		return false
	}

	t.Run("expose false", func(t *testing.T) {
		a := newHealthAdapter(t, healthDADL(srv.URL, "  health:\n    path: /status\n    expose: false", ""), testRESTOpts)
		if listsHealth(a) {
			t.Error("health listed with expose: false")
		}
		if !a.HasHealthCheck() {
			t.Error("expose: false must keep the check for monitoring")
		}
		if _, err := a.Execute(context.Background(), dadl.HealthToolName, nil); err == nil {
			t.Error("Execute(health) with expose: false succeeded")
		}
	})

	t.Run("include_tools without health hides it", func(t *testing.T) {
		opts := testRESTOpts
		opts.IncludeTools = []string{"get_me"}
		a := newHealthAdapter(t, healthDADL(srv.URL, healthBlockInline, ""), opts)
		if listsHealth(a) {
			t.Error("health listed although include_tools does not name it")
		}
		if _, err := a.Execute(context.Background(), dadl.HealthToolName, nil); err == nil {
			t.Error("Execute(health) outside include_tools succeeded")
		}
	})

	t.Run("include_tools and expose_tools accept health", func(t *testing.T) {
		opts := testRESTOpts
		opts.IncludeTools = []string{dadl.HealthToolName}
		opts.ExposeTools = []string{dadl.HealthToolName}
		a := newHealthAdapter(t, healthDADL(srv.URL, healthBlockInline, ""), opts)
		if !listsHealth(a) {
			t.Error("health missing although include_tools names it")
		}
		promoted := a.PromotedTools()
		if len(promoted) != 1 || promoted[0].Canonical != "healthapi_health" {
			t.Errorf("PromotedTools = %+v, want healthapi_health", promoted)
		}
	})

	t.Run("no check declared", func(t *testing.T) {
		a := newHealthAdapter(t, healthDADL(srv.URL, "", ""), testRESTOpts)
		if listsHealth(a) || a.HasHealthCheck() {
			t.Error("health offered without a declaration")
		}
		if res := a.CheckHealth(context.Background()); res.OK || res.Error == "" {
			t.Errorf("CheckHealth without a declaration = %+v, want a failure", res)
		}
	})
}

// The composite keeps the Unranked flag when it prefixes tool names.
func TestCompositeBackend_ListToolsKeepsUnranked(t *testing.T) {
	srv := httptest.NewServer(&healthServer{status: http.StatusOK, body: `{}`})
	defer srv.Close()
	a := newHealthAdapter(t, healthDADL(srv.URL, healthBlockInline, ""), testRESTOpts)
	comp := NewCompositeBackend(map[string]ToolBackend{"healthapi": a})
	tools, err := comp.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range tools {
		if tool.Name == "healthapi_health" {
			if !tool.Unranked {
				t.Error("composite dropped Unranked")
			}
			return
		}
	}
	t.Fatalf("healthapi_health missing from %v", tools)
}
