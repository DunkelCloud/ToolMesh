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
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
)

// DefaultTrustedProxies are the networks whose X-Forwarded-For header
// ClientIP honors unless SetTrustedProxies installs another list: loopback
// and the private ranges, where a reverse proxy on the same host or in the
// same Docker network sits. A request from any other address is identified
// by its connection address alone.
var DefaultTrustedProxies = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// trustedProxies holds the list installed by SetTrustedProxies; nil means
// DefaultTrustedProxies.
var trustedProxies atomic.Pointer[[]netip.Prefix]

// SetTrustedProxies sets the networks whose X-Forwarded-For header ClientIP
// honors (TOOLMESH_TRUSTED_PROXIES). An empty, non-nil list trusts no proxy;
// nil restores DefaultTrustedProxies.
func SetTrustedProxies(prefixes []netip.Prefix) {
	if prefixes == nil {
		trustedProxies.Store(nil)
		return
	}
	cp := slices.Clone(prefixes)
	trustedProxies.Store(&cp)
}

// isTrustedProxy reports whether addr belongs to a trusted proxy network.
func isTrustedProxy(addr netip.Addr) bool {
	list := DefaultTrustedProxies
	if p := trustedProxies.Load(); p != nil {
		list = *p
	}
	addr = addr.Unmap().WithZone("")
	for _, n := range list {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP returns the address of the client a request comes from. The
// X-Forwarded-For header is honored only when the connection itself comes
// from a trusted proxy; otherwise anyone could choose the address that the
// login throttle, the registration limit and the logs see. Behind trusted
// proxies the header is read from the right: the first entry that is not a
// trusted proxy itself is the client. When every entry is a trusted proxy,
// the leftmost one is the originating client.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil || !isTrustedProxy(remote) {
		return host
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return host
	}
	parts := strings.Split(strings.Join(values, ","), ",")
	client := host
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		client = ip.Unmap().String()
		if !isTrustedProxy(ip) {
			return client
		}
	}
	return client
}
