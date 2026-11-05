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
	"net/netip"
	"net/url"
	"strings"
	"time"
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

	// Resolve and check every address; fail closed on DNS errors, zones and
	// answers that do not parse.
	if _, err := resolvePublic(context.Background(), hostname); err != nil {
		return fmt.Errorf("base_url %q: %w", rawURL, err)
	}
	return nil
}

// resolvePublic resolves host and returns its addresses when every one of
// them is a public destination (see IsPrivateIP). It fails closed: on a DNS
// error, on an answer that does not parse as an address, and on any address
// with an IPv6 zone. A zoned literal such as "::ffff:127.0.0.1%x" comes back
// from the resolver unchanged, net.ParseIP rejects it, and the dialer ignores
// the zone, so a check that skips unparsable answers would let it through.
func resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	if strings.Contains(host, "%") {
		return nil, fmt.Errorf("address %q with an IPv6 zone is not allowed", host)
	}
	lower := strings.TrimSuffix(strings.ToLower(host), ".")
	if lower == hostnameLocalhost || lower == hostnameGoogleMetadata {
		return nil, fmt.Errorf("private hostname %q is not allowed (private/loopback)", host)
	}
	answers, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %q (fail closed): %w", host, err)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("DNS resolution returned no address for %q (fail closed)", host)
	}
	addrs := make([]netip.Addr, 0, len(answers))
	for _, s := range answers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("resolved value %q for %q is no address (fail closed)", s, host)
		}
		if a.Zone() != "" {
			return nil, fmt.Errorf("resolved address %s for %q has an IPv6 zone, not allowed", s, host)
		}
		if IsPrivateIP(net.IP(a.AsSlice())) {
			return nil, fmt.Errorf("%q resolves to private/loopback or reserved address %s", host, s)
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

// IsPrivateIP returns true if the IP is loopback, private, the unspecified
// address, link-local, or a well-known cloud metadata address. The unspecified
// address (0.0.0.0 / ::) is included because the kernel routes a connection to
// it to a loopback service, so it must be treated as private. A nil (unparsable)
// IP is treated as private to fail closed.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
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
	dialer := &net.Dialer{Timeout: timeout}

	var tlsConfig *tls.Config
	if tlsSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // admin-configured per-backend opt-in
	}

	if allowPrivate {
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
			addrs, err := resolvePublic(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("ssrf dial: %w", err)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0].String(), port))
		},
	}
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
		if _, err := resolvePublic(req.Context(), hostname); err != nil {
			return fmt.Errorf("redirect blocked: %w", err)
		}
		return nil
	}
}
