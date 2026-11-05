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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// ValidateBaseURL checks that a base URL does not point to private, loopback,
// or link-local addresses. This prevents SSRF when DADL specs are loaded from
// untrusted sources (e.g., community registry).
func ValidateBaseURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid base_url: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != urlSchemeHTTP {
		return fmt.Errorf("base_url must use http or https scheme, got %q", parsed.Scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("base_url has no hostname")
	}

	// Check for obviously private hostnames
	lower := strings.ToLower(hostname)
	if lower == hostnameLocalhost || lower == hostnameGoogleMetadata {
		return fmt.Errorf("base_url points to private hostname %q", hostname)
	}

	// Resolve and check IPs — fail closed on DNS errors.
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(context.Background(), hostname)
	if err != nil {
		return fmt.Errorf("base_url DNS resolution failed for %q (fail closed): %w", hostname, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if IsPrivateIP(ip) {
			return fmt.Errorf("base_url %q resolves to private/loopback or reserved address %s", rawURL, ipStr)
		}
	}

	return nil
}

// reservedNets are special-use ranges (RFC 6890 and successors) that are not
// globally reachable unicast destinations and that net.IP's own predicates
// do not cover. A backend or file_url target in one of them reaches internal
// infrastructure, carrier equipment or a translator to such addresses.
var reservedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // shared address space (carrier-grade NAT)
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, includes 255.255.255.255
		"100::/64",        // discard-only
		"2001:db8::/32",   // documentation
		"ff00::/8",        // multicast
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// Translation prefixes whose last 32 bits carry an IPv4 address: NAT64
// (RFC 6052 well-known and local-use prefixes) and 6to4 (2002::/16, where the
// IPv4 address follows the prefix).
var (
	nat64WellKnown = mustCIDR("64:ff9b::/96")
	nat64Local     = mustCIDR("64:ff9b:1::/48")
	sixToFour      = mustCIDR("2002::/16")
)

func mustCIDR(c string) *net.IPNet {
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		panic(err) //nolint:forbidigo // compile-time constant CIDR; cannot fail
	}
	return n
}

// IsPrivateIP returns true if the IP is not a safe destination for a request
// that the server makes on someone's behalf: loopback, private, the
// unspecified address, link-local, a well-known cloud metadata address, any
// special-use range in reservedNets, or an IPv6 translation address (NAT64,
// 6to4) whose embedded IPv4 address is one of those. The unspecified address
// (0.0.0.0 / ::) is included because the kernel routes a connection to it to
// a loopback service. A nil (unparsable) IP is treated as private to fail
// closed.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	if ip.To4() == nil && len(ip) == net.IPv6len {
		switch {
		case nat64WellKnown.Contains(ip), nat64Local.Contains(ip):
			return IsPrivateIP(ip[12:16])
		case sixToFour.Contains(ip):
			return IsPrivateIP(ip[2:6])
		}
	}
	return false
}

// SSRFSafeTransport returns an *http.Transport that validates resolved IPs at
// connection time (preventing DNS rebinding) and blocks redirects to private IPs.
//
// When allowPrivate is true, IP validation is skipped (for admin-configured
// backends that intentionally target internal networks).
// When tlsSkipVerify is true, TLS certificate validation is disabled (for
// backends using self-signed certificates).
func SSRFSafeTransport(timeout time.Duration, allowPrivate, tlsSkipVerify bool) *http.Transport {
	return guardedTransport(timeout, allowPrivate, nil, tlsSkipVerify)
}

// guardedTransport returns a transport whose dialer checks the resolved
// addresses of every destination it is not told to trust: none when
// allowAll is set, otherwise every "host:port" not in trusted. A trusted
// destination may resolve to a private address; any other must resolve to
// public ones only.
func guardedTransport(timeout time.Duration, allowAll bool, trusted map[string]bool, tlsSkipVerify bool) *http.Transport {
	dialer := &net.Dialer{Timeout: timeout}

	var tlsConfig *tls.Config
	if tlsSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // admin-configured per-backend opt-in
	}

	if allowAll {
		return &http.Transport{
			DialContext:     dialer.DialContext,
			TLSClientConfig: tlsConfig,
		}
	}
	return &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf dial: invalid address %q: %w", addr, err)
			}
			if trusted[destinationKey(host, port)] {
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("ssrf dial: DNS resolution failed for %q: %w", host, err)
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil && IsPrivateIP(ip) {
					return nil, fmt.Errorf("ssrf dial: resolved IP %s for %q is private/reserved", ipStr, host)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}
}

// destinationKey normalizes a dial destination for the trusted set.
func destinationKey(host, port string) string {
	return net.JoinHostPort(strings.TrimSuffix(strings.ToLower(host), "."), port)
}

// declaredDestinations lists the "host:port" destinations a backend's
// configuration names itself: base_url (which backends.yaml url overrides),
// the OAuth2 token_url, and the hosts of absolute tool paths. With
// allow_private_url these may resolve to private addresses; a host learned
// at run time, from a redirect or a URL the server returns, may not.
func declaredDestinations(spec *dadl.Spec) map[string]bool {
	out := map[string]bool{}
	add := func(raw string) {
		lower := strings.ToLower(raw)
		if !strings.HasPrefix(lower, urlSchemeHTTP+"://") && !strings.HasPrefix(lower, urlSchemeHTTPS+"://") {
			return
		}
		authority := raw[strings.Index(raw, "://")+3:]
		if i := strings.IndexAny(authority, "/?#"); i >= 0 {
			authority = authority[:i]
		}
		if strings.Contains(authority, "{") {
			return // a placeholder in the host is no declared destination
		}
		u, err := url.Parse(raw[:strings.Index(raw, "://")+3] + authority)
		if err != nil || u.Hostname() == "" {
			return
		}
		out[destinationKey(u.Hostname(), effectivePort(u))] = true
	}
	add(spec.Backend.BaseURL)
	add(spec.Backend.Auth.TokenURL)
	for _, tool := range spec.Backend.Tools {
		add(tool.Path)
	}
	return out
}

// redirectSafeHeaders lists the request headers that survive a redirect to a
// different origin. Everything else is removed: injected credentials in
// Authorization or custom headers (X-API-Key, PRIVATE-TOKEN, session headers),
// cookies set by hand, header parameters a caller supplied, and the Referer,
// which Go fills with the previous URL including its query string (and so
// with a query-injected API key).
var redirectSafeHeaders = map[string]struct{}{
	"Accept":            {},
	"Accept-Encoding":   {},
	"Accept-Language":   {},
	"Cache-Control":     {},
	"If-Modified-Since": {},
	"If-None-Match":     {},
	"If-Range":          {},
	"Range":             {},
	"User-Agent":        {},
}

// newBackendRedirectChecker returns the CheckRedirect function for requests to
// a configured backend. Such requests can carry credentials injected by
// ToolMesh. Go's client copies every custom header to the redirect target and
// strips only Authorization and Cookie, and only for some host changes, so an
// upstream redirect (or an open redirect on the upstream) would otherwise hand
// an X-API-Key or PRIVATE-TOKEN to a third party.
//
// Compared with the origin of the first request, a redirect
//   - to http from https is refused (no downgrade, whatever the host),
//   - to the same origin, or from http to https on the same host and default
//     ports, is followed unchanged,
//   - to any other origin is refused when it would re-send a request body
//     (307/308), and otherwise followed with only redirectSafeHeaders kept.
//
// The redirect count and private-address checks of newRedirectChecker apply
// in every case. Error texts name only the target host, never its path or
// query.
func newBackendRedirectChecker(allowPrivate bool) func(*http.Request, []*http.Request) error {
	base := newRedirectChecker(allowPrivate)
	return func(req *http.Request, via []*http.Request) error {
		if err := base(req, via); err != nil {
			return err
		}
		if len(via) == 0 || via[0].URL == nil || req.URL == nil {
			return nil
		}
		orig, next := via[0].URL, req.URL
		if strings.EqualFold(orig.Scheme, urlSchemeHTTPS) && !strings.EqualFold(next.Scheme, urlSchemeHTTPS) {
			return fmt.Errorf("redirect from https to %s://%s refused: backend requests are never downgraded", next.Scheme, next.Host)
		}
		if sameOrigin(orig, next) || isHTTPSUpgrade(orig, next) {
			return nil
		}
		if req.Body != nil && req.Body != http.NoBody {
			return fmt.Errorf("redirect to %s refused: a request body is not re-sent to another host", next.Host)
		}
		for name := range req.Header {
			if _, keep := redirectSafeHeaders[http.CanonicalHeaderKey(name)]; !keep {
				delete(req.Header, name)
			}
		}
		return nil
	}
}

// effectivePort returns the explicit port of u or the default port of its
// scheme.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case urlSchemeHTTPS:
		return "443"
	case urlSchemeHTTP:
		return "80"
	}
	return ""
}

// sameOrigin reports whether a and b share scheme, host and port.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

// isHTTPSUpgrade reports whether b is the https form of the http URL a on the
// same host with default ports, the common "http to https" redirect.
func isHTTPSUpgrade(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, urlSchemeHTTP) && strings.EqualFold(b.Scheme, urlSchemeHTTPS) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == "80" && effectivePort(b) == "443"
}

// newRedirectChecker returns a CheckRedirect function. When allowPrivate is
// true, only the redirect count is enforced. Otherwise, redirect targets are
// also validated against private/loopback addresses.
func newRedirectChecker(allowPrivate bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if allowPrivate {
			return nil
		}
		hostname := req.URL.Hostname()
		if hostname == "" {
			return nil
		}
		lower := strings.ToLower(hostname)
		if lower == hostnameLocalhost || lower == hostnameGoogleMetadata {
			return fmt.Errorf("redirect to private hostname %q blocked", hostname)
		}
		ips, err := net.DefaultResolver.LookupHost(req.Context(), hostname)
		if err != nil {
			return fmt.Errorf("redirect DNS resolution failed for %q: %w", hostname, err)
		}
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip != nil && IsPrivateIP(ip) {
				return fmt.Errorf("redirect to private IP %s (%q) blocked", ipStr, hostname)
			}
		}
		return nil
	}
}
