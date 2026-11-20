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
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestClientIP_WarningCountsIgnoredRequests pins that the warning about an
// ignored X-Forwarded-For header says how many requests it stands for: the
// line is logged at most once per interval, and the count tells one stray
// request from all of the traffic arriving through a proxy nobody listed.
func TestClientIP_WarningCountsIgnoredRequests(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies(nil)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	reset := func() {
		lastUntrustedForwardedWarn.Store(0)
		ignoredForwarded.Store(0)
	}
	reset()
	t.Cleanup(reset)

	const proxy = "172.18.0.5:1"
	for range 3 {
		_ = ClientIP(clientIPRequest(proxy, "198.51.100.8"))
	}
	if out := buf.String(); strings.Count(out, "TOOLMESH_TRUSTED_PROXIES") != 1 || !strings.Contains(out, "requests=1") {
		t.Fatalf("first warning: %s", out)
	}

	// An interval later the next request logs again, with the requests
	// that were ignored in between.
	buf.Reset()
	lastUntrustedForwardedWarn.Store(time.Now().Add(-2 * untrustedForwardedWarnInterval).UnixNano())
	_ = ClientIP(clientIPRequest(proxy, "198.51.100.9"))
	if out := buf.String(); strings.Count(out, "TOOLMESH_TRUSTED_PROXIES") != 1 || !strings.Contains(out, "requests=3") {
		t.Errorf("second warning does not count the requests since the first: %s", out)
	}
}

// TestForwardedForIgnored pins when a request counts as carrying a header
// ClientIP does not honor.
func TestForwardedForIgnored(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	SetTrustedProxies([]netip.Prefix{netip.MustParsePrefix("172.18.0.10/32")})
	header := []string{"198.51.100.77"}
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   bool
	}{
		{"no header", "172.18.0.1:1", nil, false},
		{"header from an unlisted address", "172.18.0.1:1", header, true},
		{"header from the listed proxy", "172.18.0.10:1", header, false},
		{"header from a peer that is no address", "pipe", header, true},
	}
	for _, c := range cases {
		if got := ForwardedForIgnored(clientIPRequest(c.remote, c.xff...)); got != c.want {
			t.Errorf("%s: ForwardedForIgnored = %v, want %v", c.name, got, c.want)
		}
	}
}
