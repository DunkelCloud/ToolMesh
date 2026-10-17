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
	"strings"
)

// ClientIP extracts the client IP address. Uses the rightmost non-private IP
// from X-Forwarded-For to prevent spoofing (H-6), falling back to RemoteAddr.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Walk from right to left, return the first non-private IP.
		// The rightmost entry is set by the closest trusted proxy.
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
				continue
			}
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
