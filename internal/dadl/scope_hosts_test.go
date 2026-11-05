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

package dadl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

const mineToken = "mine_token" //nolint:gosec // credential name, not a credential

// TestHostScope_SchemeAndPort pins the scheme and port binding: with an
// https base_url no credential leaves over http, the base host takes its
// own port only, the other hosts of its domain and of allowed_hosts the
// default port only, and an allowed_hosts entry with :port that port.
func TestHostScope_SchemeAndPort(t *testing.T) {
	s, err := NewHostScope("https://api.example.com:8443/v1", []string{"files.other.example:9000", "cdn.other.example", "*.wild.example", "[2001:db8::1]:8080"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://api.example.com:8443/x", true},
		{"https://API.EXAMPLE.COM.:8443/x", true},
		{"http://api.example.com:8443/x", false}, // downgrade
		{"https://api.example.com/x", false},     // base host, other port
		{"https://api.example.com:9443/x", false},
		{"https://other.example.com/x", true}, // same domain, default port
		{"https://example.com/x", true},
		{"https://other.example.com:8443/x", false},
		{"http://other.example.com/x", false},
		{"https://files.other.example:9000/x", true},
		{"https://files.other.example/x", false},
		{"https://cdn.other.example/x", true},
		{"https://cdn.other.example:444/x", false},
		{"https://a.b.wild.example/x", true},
		{"https://wild.example/x", false},
		{"https://evilwild.example/x", false},
		{"https://[2001:db8:0::1]:8080/x", true}, // another spelling of the address
		{"https://[2001:db8::1]/x", false},
		{"https://api.example.com.evil.io:8443/x", false},
		{"ftp://api.example.com:8443/x", false},
		{"https://127.0.0.1:8443/x", false},
	}
	for _, c := range cases {
		if got := s.Allows(c.url); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.url, got, c.want)
		}
	}

	// An http base_url may also reach https hosts; its own host on another
	// port only with an allowed_hosts entry.
	h, err := NewHostScope("http://intranet.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Allows("http://intranet.example.com/x") || !h.Allows("https://sso.example.com/x") || h.Allows("https://intranet.example.com/x") {
		t.Error("http base_url: wrong decision")
	}
}

// TestNewHostScope_AllowedHostsForms pins that an allowed_hosts entry is a
// host, *.domain, an IP address or one of them with :port, and that any
// other text is refused at load instead of silently matching nothing.
func TestNewHostScope_AllowedHostsForms(t *testing.T) {
	good := []string{"api.example.com", "API.Example.com.", "*.example.com", "files.example.com:8443", "10.0.0.5", "10.0.0.5:8080", "[2001:db8::1]", "[2001:db8::1]:443", "2001:db8::1", "under_score.example"}
	for _, g := range good {
		if _, err := NewHostScope("https://api.example.com", []string{g}); err != nil {
			t.Errorf("%q refused: %v", g, err)
		}
	}
	bad := []string{"", "https://host.example", "host.example/path", "user@host.example", "host.example:0", "host.example:99999", "host.example:http",
		"*.10.0.0.5", "[2001:db8::1", "[host.example]:443", "-bad.example", "a..example", "fe80::1%eth0", "host .example", "*.", "x], allowed_hosts: [evil.example"}
	for _, b := range bad {
		if _, err := NewHostScope("https://api.example.com", []string{b}); err == nil {
			t.Errorf("%q accepted", b)
		}
	}
	if _, err := NewHostScope("ftp://api.example.com", nil); err == nil {
		t.Error("a base_url other than http(s) was accepted")
	}
}

// TestCheckScope_SchemeDowngrade pins the static check: an absolute tool
// path over http under an https base_url is refused without a fix line,
// and a foreign port is refused with the host:port entry that allows it.
func TestCheckScope_SchemeDowngrade(t *testing.T) {
	spec := &Spec{Backend: BackendDef{Name: "mine", BaseURL: "https://api.example.com/api",
		Auth: AuthConfig{Type: authTypeBearer, Credential: mineToken},
		Tools: map[string]ToolDef{
			"plain": {Method: httpMethodGET, Path: "http://api.example.com/ping"},
			"port":  {Method: httpMethodGET, Path: "https://api.example.com:8443/ping"},
		}}}
	hosts, err := NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckScope(spec, credScope(t, "mine", nil, nil), hosts)
	var se *ScopeError
	if !errors.As(err, &se) || len(se.Violations) != 2 {
		t.Fatalf("CheckScope = %v, want two violations", err)
	}
	if !strings.Contains(err.Error(), "uses http while base_url uses https") {
		t.Errorf("the downgrade is not named: %v", err)
	}
	lines := strings.Join(se.FixLines(), "\n")
	if lines != "allowed_hosts: ['api.example.com:8443']" && lines != "allowed_hosts: [api.example.com:8443]" {
		t.Errorf("fix lines = %q, want only the port entry", lines)
	}
}

// TestRestAuth_SchemeDowngradeAtRuntime pins the second line: a request
// over http under an https base_url gets no credential, also when the
// load-time check was bypassed.
func TestRestAuth_SchemeDowngradeAtRuntime(t *testing.T) {
	a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: mineToken}, "https://api.example.com",
		mapCreds{mineToken: hardeningSecret}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hosts, err := NewHostScope("https://api.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.SetScope(credScope(t, "mine", nil, nil), hosts)
	for _, raw := range []string{"http://api.example.com/x", "https://api.example.com:8443/x"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
		if err := a.InjectAuth(context.Background(), req); err == nil {
			t.Errorf("%s: credentials were attached", raw)
		}
		if req.Header.Get("Authorization") != "" {
			t.Errorf("%s: the credential was injected", raw)
		}
	}
}
