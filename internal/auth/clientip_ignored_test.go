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
