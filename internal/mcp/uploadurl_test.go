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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	testUploadURLBase  = "http://localhost:8080"
	testMsgInvalidSize = "invalid size"
)

// uploadURLSetup is a handler and the routes of its server, sharing one blob
// store as main wires them.
type uploadURLSetup struct {
	handler *Handler
	mux     *http.ServeMux
	store   *blob.Store
}

func newUploadURLSetup(t *testing.T, limits blob.UploadLimits) uploadURLSetup {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	store, err := blob.NewStore(t.TempDir(), testUploadURLBase, logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	handler.SetBlobStore(store, limits)
	srv := NewServer(handler, &config.Config{APIKey: testAPIKey, AuthUser: testBrokerUser}, logger, nil, nil, nil, nil, nil, nil)
	srv.SetBlobStore(store, limits)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	return uploadURLSetup{handler: handler, mux: mux, store: store}
}

func brokerUserCtx() context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testBrokerUser, Authenticated: true})
}

// createdUploadURL is the answer of create_upload_url.
type createdUploadURL struct {
	UploadURL string    `json:"upload_url"`
	Method    string    `json:"method"`
	Handle    string    `json:"handle"`
	Expires   time.Time `json:"upload_url_expires"`
	MaxBytes  int64     `json:"max_bytes"`
	PartBytes int64     `json:"part_bytes"`
	How       string    `json:"how"`
}

func createUploadURL(t *testing.T, h *Handler, params map[string]any) createdUploadURL {
	t.Helper()
	failed, text := callTool(t, h, brokerUserCtx(), toolCreateUploadURL, params)
	if failed {
		t.Fatalf("create_upload_url failed: %s", text)
	}
	var c createdUploadURL
	if err := json.Unmarshal([]byte(text), &c); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, text)
	}
	return c
}

func TestCreateUploadURL_RoundTrip(t *testing.T) {
	s := newUploadURLSetup(t, blob.DefaultUploadLimits())
	c := createUploadURL(t, s.handler, map[string]any{
		argNameContentType: "video/mp4",
		argNameSize:        float64(11),
		argNameFilename:    "short.mp4",
		argNameTTL:         "2h",
	})
	path, ok := strings.CutPrefix(c.UploadURL, testUploadURLBase+blob.UploadURLPathPrefix)
	if !ok || path == "" {
		t.Fatalf("upload_url = %q, want it under %s%s", c.UploadURL, testUploadURLBase, blob.UploadURLPathPrefix)
	}
	if c.Method != http.MethodPut || !blob.IsHandle(c.Handle) || c.PartBytes != blob.UploadURLPartBytes || c.MaxBytes != blob.DefaultUploadLimits().MaxBytes || c.How == "" {
		t.Errorf("answer = %+v", c)
	}
	if d := time.Until(c.Expires); d <= 0 || d > time.Hour {
		t.Errorf("URL expires in %v, want within the hour", d)
	}

	// The PUT carries no credential.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, blob.UploadURLPathPrefix+path, strings.NewReader("hello world"))
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT = %d %s, want 201", rec.Code, rec.Body.String())
	}
	id, _, _, err := blob.ParseHandle(c.Handle)
	if err != nil {
		t.Fatalf("ParseHandle: %v", err)
	}
	info, err := s.store.Stat(id)
	if err != nil || info.Size != 11 || info.ContentType != "video/mp4" || info.Filename != "short.mp4" {
		t.Errorf("blob = %+v, %v; want the 11 bytes with type and name", info, err)
	}
	if d := time.Until(info.ExpiresAt); d < 119*time.Minute {
		t.Errorf("blob expires in %v, want the TTL of 2h", d)
	}
	if _, ofUser := s.store.Usage(testBrokerUser); ofUser != 11 {
		t.Errorf("usage of %s = %d, want 11", testBrokerUser, ofUser)
	}

	tools, err := s.handler.BuildToolList(brokerUserCtx())
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, d := range tools {
		listed = listed || d.Name == toolCreateUploadURL
	}
	if !listed {
		t.Errorf("%s is not listed although the file broker is on", toolCreateUploadURL)
	}
}

func TestCreateUploadURL_Refusals(t *testing.T) {
	s := newUploadURLSetup(t, blob.UploadLimits{MaxBytes: 100, DefaultTTL: time.Hour, MaxTTL: time.Hour})
	for _, tt := range []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"negative size", map[string]any{argNameSize: float64(-1)}, testMsgInvalidSize},
		{"fractional size", map[string]any{argNameSize: 1.5}, testMsgInvalidSize},
		{"size as text", map[string]any{argNameSize: "10"}, testMsgInvalidSize},
		{"size over the limit", map[string]any{argNameSize: float64(101)}, "exceeding the 100 byte limit"},
		{"invalid ttl", map[string]any{argNameTTL: "soon"}, "invalid ttl"},
		{"invalid content type", map[string]any{argNameContentType: "a;;b"}, "invalid content type"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			failed, text := callTool(t, s.handler, brokerUserCtx(), toolCreateUploadURL, tt.params)
			if !failed || !strings.Contains(text, tt.want) || !strings.HasPrefix(text, toolCreateUploadURL+": ") {
				t.Errorf("result = %v %q, want an error with %q", failed, text, tt.want)
			}
		})
	}
}

// A client that keeps the tool list it got before this server offered
// create_upload_url still reaches it from inside execute_code.
func TestCreateUploadURL_FromCodeMode(t *testing.T) {
	s := newUploadURLSetup(t, blob.DefaultUploadLimits())
	failed, text := callTool(t, s.handler, brokerUserCtx(), toolExecuteCode, map[string]any{
		argNameCode: `const r = await toolmesh.create_upload_url({size: 3}); return r.method + " " + r.handle + " " + r.upload_url;`,
	})
	if failed || !strings.Contains(text, "PUT tm-blob://") || !strings.Contains(text, blob.UploadURLPathPrefix) {
		t.Errorf("create_upload_url from code mode: failed=%v %s", failed, text)
	}

	// Without a file broker the name is not there.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mb := &mockTestBackend{}
	h := NewHandler(executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil), mb, nil, "", nil, logger, false)
	h.SetBlobStore(nil, blob.DefaultUploadLimits())
	failed, text = callTool(t, h, brokerUserCtx(), toolExecuteCode, map[string]any{
		argNameCode: `return typeof toolmesh.create_upload_url;`,
	})
	if failed || !strings.Contains(text, "undefined") {
		t.Errorf("without a file broker: failed=%v %s, want undefined", failed, text)
	}
}

// The token of an upload URL is its credential: it reaches no log line, not
// the request log and not the log of a panic.
func TestUploadURL_TokenNotLogged(t *testing.T) {
	const madeUp = "made-up-value-of-an-upload-url-for-this-test"
	logs := &loginLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))

	var inner http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			panic("boom")
		}
		w.WriteHeader(http.StatusNotFound)
	})
	h := PanicRecovery(logger)(RequestLogging(logger)(inner))
	for _, method := range []string{http.MethodPut, http.MethodPost} {
		req := httptest.NewRequestWithContext(context.Background(), method, blob.UploadURLPathPrefix+madeUp, strings.NewReader("x"))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	out := logs.String()
	if strings.Contains(out, madeUp) {
		t.Errorf("the token is in the log:\n%s", out)
	}
	// Start and end of the PUT, start of the POST and its panic.
	if n := strings.Count(out, blob.UploadURLPathPrefix+"[REDACTED]"); n != 4 {
		t.Errorf("%d redacted paths in the log, want 4:\n%s", n, out)
	}
	multipart := strings.TrimSuffix(blob.UploadURLPathPrefix, "/")
	for p, want := range map[string]string{
		multipart:                                 multipart,
		blob.UploadURLPathPrefix:                  blob.UploadURLPathPrefix,
		"/files//upload/" + madeUp:                blob.UploadURLPathPrefix + redactedMark,
		"//files/upload/" + madeUp:                blob.UploadURLPathPrefix + redactedMark,
		"/files/./upload/" + madeUp:               blob.UploadURLPathPrefix + redactedMark,
		"/blobs/0123456789abcdef0123456789ab":     "/blobs/0123456789abcdef0123456789ab",
		blob.UploadURLPathPrefix + madeUp + "/..": blob.UploadURLPathPrefix + redactedMark + "/..",
	} {
		if got := loggedPath(p); got != want {
			t.Errorf("loggedPath(%q) = %q, want %q", p, got, want)
		}
	}
}

// The result of create_upload_url carries the URL; at level DEBUG, ToolMesh
// logs tool results, and those lines carry the token replaced.
func TestUploadURL_TokenNotInDebugLog(t *testing.T) {
	logs := &loginLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mb := &mockTestBackend{}
	handler := NewHandler(executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil), mb, nil, "", nil, logger, false)
	store, err := blob.NewStore(t.TempDir(), testUploadURLBase, logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	handler.SetBlobStore(store, blob.DefaultUploadLimits())
	srv := NewServer(handler, &config.Config{APIKey: testAPIKey, AuthUser: testBrokerUser}, logger, nil, nil, nil, nil, nil, nil)
	srv.SetBlobStore(store, blob.DefaultUploadLimits())
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	var tokens []string
	find := func(text string) {
		t.Helper()
		i := strings.Index(text, blob.UploadURLPathPrefix)
		if i < 0 || len(text) < i+len(blob.UploadURLPathPrefix)+43 {
			t.Fatalf("no upload URL in %s", text)
		}
		tokens = append(tokens, text[i+len(blob.UploadURLPathPrefix):i+len(blob.UploadURLPathPrefix)+43])
	}
	// A direct tools/call over /mcp, and one from inside execute_code.
	find(postToolCall(t, mux, toolCreateUploadURL, `{}`).Body.String())
	_, text := callTool(t, handler, brokerUserCtx(), toolExecuteCode, map[string]any{
		argNameCode: `const r = await toolmesh.create_upload_url({}); return r.upload_url;`,
	})
	find(text)
	// The URL passed on in the code of execute_code, over /mcp and directly:
	// it then is in the request payload, the tool call parameters and the
	// logged code.
	url := testUploadURLBase + blob.UploadURLPathPrefix + tokens[0]
	postToolCall(t, mux, toolExecuteCode, `{"code":"return \"`+url+`\".length;"}`)
	callTool(t, handler, brokerUserCtx(), toolExecuteCode, map[string]any{
		argNameCode: `const u = "` + url + `"; return u.length;`,
	})

	out := logs.String()
	for _, tok := range tokens {
		if strings.Contains(out, tok) {
			t.Errorf("token %s… is in the debug log", tok[:6])
		}
	}
	for _, msg := range []string{`"msg":"mcp response"`, `"msg":"execute_code complete"`, `"msg":"mcp request payload"`, `"msg":"tool call params"`, `"msg":"execute_code input"`} {
		if !strings.Contains(out, msg) {
			t.Errorf("no %s line: the test does not see the lines it guards", msg)
		}
	}
	if !strings.Contains(out, blob.UploadURLPathPrefix+redactedMark) {
		t.Error("no redacted upload URL in the debug log")
	}
}
