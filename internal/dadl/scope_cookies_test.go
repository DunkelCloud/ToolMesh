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
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
)

// otherPortURL is the base host of the cookie test on another port.
const otherPortURL = "https://api.example.com:8443/x"

// TestSessionCookieJar_HostScope pins that the session cookie jar follows
// the host binding: it answers only for the scheme, host and port the scope
// allows, so a session cookie does not follow a redirect to another port or
// to http of the same host, and it stores no cookies such a destination sets.
func TestSessionCookieJar_HostScope(t *testing.T) {
	const base = "https://api.example.com"
	a := NewRestAuth(AuthConfig{Type: authTypeSession, Login: &SessionLogin{Method: http.MethodPost, Path: formsLogin}},
		base, mapCreds{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hosts, err := NewHostScope(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.SetScope(credScope(t, "mine", nil, nil), hosts)
	jar := a.CookieJar()
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	jar.SetCookies(parse(base+formsLogin), []*http.Cookie{{Name: "session", Value: "S3SSION", Path: "/"}}) //nolint:gosec // test cookie, attributes do not matter
	if len(jar.Cookies(parse(base+"/x"))) != 1 {
		t.Fatal("the base host lost its session cookie")
	}
	for _, other := range []string{otherPortURL, "http://api.example.com/x", "https://evil.example/x"} {
		if c := jar.Cookies(parse(other)); len(c) != 0 {
			t.Errorf("%s got cookies %v", other, c)
		}
	}
	jar.SetCookies(parse(otherPortURL), []*http.Cookie{{Name: "planted", Value: "1", Path: "/"}}) //nolint:gosec // test cookie, attributes do not matter
	for _, c := range jar.Cookies(parse(base + "/x")) {
		if c.Name == "planted" {
			t.Error("a cookie set by another port reached the base host")
		}
	}
}
