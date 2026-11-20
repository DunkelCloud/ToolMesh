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
	"net/netip"
	"testing"
)

// TestClientIP_MappedTrustedProxyEntries pins that a trusted proxy listed
// in IPv4-mapped IPv6 form, as a dual-stack listener reports its peers, is
// trusted: its X-Forwarded-For header is honored, whether the connection
// shows the proxy as IPv4 or in mapped form. Such an entry used to match
// nothing, and every client behind the proxy was counted as one.
func TestClientIP_MappedTrustedProxyEntries(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	const client = "198.51.100.23"
	for _, entry := range []string{"::ffff:172.18.0.10/128", "::ffff:172.18.0.0/112"} {
		SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix(entry)})
		for _, remote := range []string{"172.18.0.10:4711", "[::ffff:172.18.0.10]:4711"} {
			if got := ClientIP(clientIPRequest(remote, client)); got != client {
				t.Errorf("entry %s, peer %s: ClientIP = %q, want the forwarded client %q", entry, remote, got, client)
			}
		}
		// Another address stays untrusted.
		if got := ClientIP(clientIPRequest("172.19.0.10:4711", client)); got == client {
			t.Errorf("entry %s: an address outside it was trusted", entry)
		}
	}
}

// TestSetTrustedProxies_DropsShortMappedPrefix pins that a mapped prefix
// shorter than /96 trusts nobody. Kept as an IPv6 prefix it would cover
// "::1" and every other address that starts with zeros.
func TestSetTrustedProxies_DropsShortMappedPrefix(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/8")})
	const client = "198.51.100.24"
	for _, remote := range []string{"[::1]:4711", "10.0.0.5:4711", "[::ffff:10.0.0.5]:4711"} {
		if got := ClientIP(clientIPRequest(remote, client)); got == client {
			t.Errorf("peer %s was trusted through a mapped /8", remote)
		}
	}
}

func TestUnmapProxyPrefix(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"192.0.2.0/24", "192.0.2.0/24", true},
		{"2001:db8::/32", "2001:db8::/32", true},
		{"::ffff:10.0.0.5/128", "10.0.0.5/32", true},
		{"::ffff:10.64.0.0/106", "10.64.0.0/10", true},
		{"::ffff:0.0.0.0/96", "0.0.0.0/0", true},
		{"::ffff:10.0.0.0/90", "::ffff:10.0.0.0/90", false},
	}
	for _, c := range cases {
		got, ok := UnmapProxyPrefix(netip.MustParsePrefix(c.in))
		if got.String() != c.want || ok != c.ok {
			t.Errorf("UnmapProxyPrefix(%s) = %s, %v; want %s, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
