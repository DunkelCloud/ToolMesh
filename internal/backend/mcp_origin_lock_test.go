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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	originLockKeyEnv  = "MCP_KEY"
	originLockMCPPath = "/mcp"
)

// originRecorder counts requests and keeps the last Authorization header
// per name.
type originRecorder struct {
	mu   sync.Mutex
	hits map[string]int
	auth map[string]string
}

func newOriginRecorder() *originRecorder {
	return &originRecorder{hits: map[string]int{}, auth: map[string]string{}}
}

func (r *originRecorder) record(name string, req *http.Request) {
	_, _ = io.Copy(io.Discard, req.Body)
	r.mu.Lock()
	r.hits[name]++
	r.auth[name] = req.Header.Get("Authorization")
	r.mu.Unlock()
}

func (r *originRecorder) get(name string) (int, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[name], r.auth[name]
}

// otherHostURL rewrites a 127.0.0.1 httptest URL to "localhost", so two
// test servers play two hosts.
func otherHostURL(t *testing.T, srvURL, path string) string {
	t.Helper()
	u, err := url.Parse(srvURL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(u.Host)
	return u.Scheme + "://localhost:" + port + path
}

func mcpClientOf(t *testing.T, tr mcp.Transport) *http.Client {
	t.Helper()
	switch x := tr.(type) {
	case *mcp.StreamableClientTransport:
		return x.HTTPClient
	case *mcp.SSEClientTransport:
		return x.HTTPClient
	}
	t.Fatalf("unexpected transport %T", tr)
	return nil
}

// TestCreateHTTPTransport_StaysOnEndpointOrigin exercises the client that
// createHTTPTransport builds, for streamable and legacy SSE endpoints, with
// and without api_key_env: requests reach the endpoint origin (with the
// token when one is configured), a redirect to another host is refused and
// that host sees no request at all, including a 307 that would re-send the
// body.
func TestCreateHTTPTransport_StaysOnEndpointOrigin(t *testing.T) {
	rec := newOriginRecorder()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record("other", r)
		_, _ = w.Write([]byte("{}"))
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record("origin", r)
		switch {
		case strings.HasSuffix(r.URL.Path, "/redirect"):
			http.Redirect(w, r, otherHostURL(t, other.URL, "/x"), http.StatusTemporaryRedirect)
		case strings.HasSuffix(r.URL.Path, "/moved"):
			http.Redirect(w, r, "/landing", http.StatusFound)
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
	defer origin.Close()

	a := newEmptyMCPAdapter(&testCredStore{creds: map[string]string{originLockKeyEnv: "tok"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, key := range []string{originLockKeyEnv, ""} {
		for _, suffix := range []string{originLockMCPPath, "/sse"} {
			tr, err := a.createHTTPTransport(context.Background(), BackendEntry{Name: "b", Transport: "http", URL: origin.URL + suffix, APIKeyEnv: key})
			if err != nil {
				t.Fatal(err)
			}
			hc := mcpClientOf(t, tr)
			if hc.CheckRedirect == nil {
				t.Errorf("%s key=%q: no redirect policy", suffix, key)
			}

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+"/moved", http.NoBody)
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatalf("%s key=%q: same-origin redirect failed: %v", suffix, key, err)
			}
			_ = resp.Body.Close()
			wantAuth := ""
			if key != "" {
				wantAuth = "Bearer tok"
			}
			if _, auth := rec.get("origin"); auth != wantAuth {
				t.Errorf("%s key=%q: origin Authorization = %q, want %q", suffix, key, auth, wantAuth)
			}

			body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, origin.URL+"/redirect", body)
			if resp, err := hc.Do(req); err == nil {
				_ = resp.Body.Close()
				t.Errorf("%s key=%q: 307 to another host was followed", suffix, key)
			}
			req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, otherHostURL(t, other.URL, "/direct"), http.NoBody)
			if resp, err := hc.Do(req); err == nil {
				_ = resp.Body.Close()
				t.Errorf("%s key=%q: request to another origin was sent", suffix, key)
			}
		}
	}
	if hits, _ := rec.get("other"); hits != 0 {
		t.Errorf("the other host received %d requests, want 0", hits)
	}
}

// TestSSEEndpointEventOnOtherOrigin pins that a legacy SSE server cannot
// send the client's messages to another host through its endpoint event.
func TestSSEEndpointEventOnOtherOrigin(t *testing.T) {
	rec := newOriginRecorder()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record("other", r)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer other.Close()

	for _, tc := range []struct {
		name, endpoint string
		wantSent       bool
	}{
		{"other host", otherHostURL(t, other.URL, "/messages"), false},
		{"same origin", "/messages?sid=1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					rec.record("origin-post", r)
					w.WriteHeader(http.StatusAccepted)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", tc.endpoint)
				if fl, ok := w.(http.Flusher); ok {
					fl.Flush()
				}
				<-r.Context().Done()
			}))
			defer origin.Close()

			a := newEmptyMCPAdapter(&testCredStore{creds: map[string]string{originLockKeyEnv: "tok"}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			tr, err := a.createHTTPTransport(context.Background(), BackendEntry{Name: "b", Transport: "http", URL: origin.URL + "/sse", APIKeyEnv: originLockKeyEnv})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := tr.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			msg, err := jsonrpc.DecodeMessage(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			if err != nil {
				t.Fatal(err)
			}
			err = conn.Write(ctx, msg)
			if tc.wantSent && err != nil {
				t.Fatalf("same-origin message endpoint: %v", err)
			}
			if !tc.wantSent && err == nil {
				t.Error("message to an endpoint on another host was sent")
			}
		})
	}
	if hits, _ := rec.get("other"); hits != 0 {
		t.Errorf("the other host received %d requests, want 0", hits)
	}
	if hits, auth := rec.get("origin-post"); hits != 1 || auth != "Bearer tok" {
		t.Errorf("same-origin message: hits %d, Authorization %q", hits, auth)
	}
}
