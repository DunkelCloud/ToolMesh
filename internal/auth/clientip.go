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
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultTrustedProxies are the addresses whose X-Forwarded-For header
// ClientIP honors unless SetTrustedProxies installs another list: loopback
// only, where a reverse proxy on the same host connects from. A proxy in a
// container or on another machine has to be listed. Private ranges are not
// trusted by default: a client on a LAN, or every client of a Docker setup
// that shows its bridge gateway as the peer, would otherwise choose its own
// address.
var DefaultTrustedProxies = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// untrustedForwardedWarnInterval spaces out the warning about an
// X-Forwarded-For header from an address that is not a trusted proxy.
const untrustedForwardedWarnInterval = time.Hour

// lastUntrustedForwardedWarn is the time of the last such warning in Unix
// nanoseconds; 0 means none yet.
var lastUntrustedForwardedWarn atomic.Int64

// warnUntrustedForwarded logs, at most once per interval, that a request
// from remote carried X-Forwarded-For which was ignored. Behind a reverse
// proxy that is not listed every client shares the proxy's address, and this
// line is what tells the operator.
func warnUntrustedForwarded(remote string) {
	now := time.Now().UnixNano()
	last := lastUntrustedForwardedWarn.Load()
	if last != 0 && now-last < int64(untrustedForwardedWarnInterval) {
		return
	}
	if !lastUntrustedForwardedWarn.CompareAndSwap(last, now) {
		return
	}
	slog.Warn("X-Forwarded-For from an address that is not a trusted proxy is ignored; if ToolMesh runs behind a reverse proxy at this address, add the proxy's address to TOOLMESH_TRUSTED_PROXIES, otherwise every client shares its per-address limits",
		"remote", remote)
}

// trustedProxies holds the list installed by SetTrustedProxies; nil means
// DefaultTrustedProxies.
var trustedProxies atomic.Pointer[[]netip.Prefix]

// SetTrustedProxies sets the proxy addresses whose X-Forwarded-For header
// ClientIP honors (TOOLMESH_TRUSTED_PROXIES). An empty, non-nil list trusts no proxy;
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
	values := r.Header.Values("X-Forwarded-For")
	remote, err := netip.ParseAddr(host)
	if err != nil || !isTrustedProxy(remote) {
		if len(values) > 0 {
			warnUntrustedForwarded(host)
		}
		return host
	}
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
