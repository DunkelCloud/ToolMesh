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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// allowPrivateBaseURL is a test hook that disables private-IP checks in
// ValidateBaseURL and the SSRF-safe transport/redirect hooks. Production code
// must never set this to true.
var allowPrivateBaseURL = false

// ValidateBaseURL checks that a base URL does not point to private, loopback,
// or link-local addresses. This prevents SSRF when DADL specs are loaded from
// untrusted sources (e.g., community registry).
func ValidateBaseURL(rawURL string) error {
	if allowPrivateBaseURL {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid base_url: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("base_url must use http or https scheme, got %q", parsed.Scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("base_url has no hostname")
	}

	// Check for obviously private hostnames
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "metadata.google.internal" {
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
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("base_url %q resolves to private/loopback address %s", rawURL, ipStr)
		}
		// AWS metadata endpoint
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return fmt.Errorf("base_url %q resolves to cloud metadata address %s", rawURL, ipStr)
		}
	}

	return nil
}

// IsPrivateIP returns true if the IP is loopback, private, link-local, or
// a well-known cloud metadata address.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

// SSRFSafeTransport returns an *http.Transport that validates resolved IPs at
// connection time (preventing DNS rebinding) and blocks redirects to private IPs.
func SSRFSafeTransport(timeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: timeout}
	if allowPrivateBaseURL {
		return &http.Transport{DialContext: dialer.DialContext}
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("ssrf dial: invalid address %q: %w", addr, err)
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

// ssrfSafeCheckRedirect validates that redirect targets do not point to private IPs.
func ssrfSafeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if allowPrivateBaseURL {
		return nil
	}
	hostname := req.URL.Hostname()
	if hostname == "" {
		return nil
	}
	lower := strings.ToLower(hostname)
	if lower == "localhost" || lower == "metadata.google.internal" {
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
