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
	"net/url"
	"strings"
)

// ValidateBaseURL checks that a base URL does not point to private, loopback,
// or link-local addresses. This prevents SSRF when DADL specs are loaded from
// untrusted sources (e.g., community registry).
func ValidateBaseURL(rawURL string) error {
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

	// Resolve and check IPs
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(context.Background(), hostname)
	if err != nil {
		// DNS resolution failed — allow (the host may not be resolvable from the build environment)
		return nil
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
