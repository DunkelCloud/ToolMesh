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

package auth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const (
	spoofedIP = "6.6.6.6"
	clientIP  = "198.51.100.7"
)

func clientIPRequest(remote string, xff ...string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

// TestClientIP_DefaultIgnoresPrivatePeers pins that with the default list a
// peer on a private address cannot choose its address: a LAN client without
// a proxy, or every client of a Docker setup whose peer is the bridge
// gateway.
func TestClientIP_DefaultIgnoresPrivatePeers(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies(nil)
	for _, c := range []struct{ name, remote, host string }{
		{"docker gateway", "172.17.0.1:40000", "172.17.0.1"},
		{"compose network gateway", "172.18.0.1:40000", "172.18.0.1"},
		{"rootless port driver", "10.0.2.100:40000", "10.0.2.100"},
		{"lan client", "192.168.1.9:40000", "192.168.1.9"},
	} {
		if got := ClientIP(clientIPRequest(c.remote, spoofedIP)); got != c.host {
			t.Errorf("%s: ClientIP = %q, want the peer %q", c.name, got, c.host)
		}
	}
}

// TestClientIP_ProxyChain pins the walk behind trusted proxies: a private
// client address appended by the proxy is the client, not a hop to skip.
func TestClientIP_ProxyChain(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies(nil)
	if got := ClientIP(clientIPRequest("127.0.0.1:1", "6.6.6.6, 192.168.1.50")); got != "192.168.1.50" {
		t.Errorf("LAN client behind a loopback proxy: ClientIP = %q, want 192.168.1.50", got)
	}

	// A proxy container listed by address: what it appends is the client,
	// even when that is the Docker gateway (all it can see).
	SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("172.18.0.5/32")})
	if got := ClientIP(clientIPRequest("172.18.0.5:1", "6.6.6.6, 172.18.0.1")); got != "172.18.0.1" {
		t.Errorf("proxy container: ClientIP = %q, want 172.18.0.1", got)
	}
}

func TestClientIP_Parsing(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies(nil)
	const proxy = "127.0.0.1:1"
	cases := []struct {
		name string
		xff  []string
		want string
	}{
		{"entry with port is skipped", []string{"6.6.6.6, 198.51.100.7:443"}, spoofedIP},
		{"bracketed ipv6 is skipped", []string{"6.6.6.6, [2001:db8::1]"}, spoofedIP},
		{"ipv4-mapped is unmapped", []string{"::ffff:198.51.100.7"}, clientIP},
		{"empty entries", []string{",, 198.51.100.7 ,,"}, clientIP},
		{"two header lines, last wins", []string{spoofedIP, clientIP}, clientIP},
		{"all garbage falls back to remote", []string{"a, b, c"}, "127.0.0.1"},
		{"empty header falls back to remote", []string{""}, "127.0.0.1"},
	}
	for _, c := range cases {
		if got := ClientIP(clientIPRequest(proxy, c.xff...)); got != c.want {
			t.Errorf("%s: ClientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestClientIP_WarnsOnUntrustedForwardedFor pins the hint for an operator
// whose reverse proxy is not listed: one WARN, not one per request.
func TestClientIP_WarnsOnUntrustedForwardedFor(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies(nil)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	lastUntrustedForwardedWarn.Store(0)
	t.Cleanup(func() { lastUntrustedForwardedWarn.Store(0) })

	_ = ClientIP(clientIPRequest("172.18.0.5:1", clientIP))
	_ = ClientIP(clientIPRequest("172.18.0.5:1", "198.51.100.8"))
	_ = ClientIP(clientIPRequest("203.0.113.9:1"))
	out := buf.String()
	if n := strings.Count(out, "TOOLMESH_TRUSTED_PROXIES"); n != 1 {
		t.Errorf("warning logged %d times, want once: %s", n, out)
	}
	if !strings.Contains(out, "remote=172.18.0.5") {
		t.Errorf("warning does not name the peer: %s", out)
	}
}
