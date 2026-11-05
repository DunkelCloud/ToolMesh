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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSSRF_ZonedLiteralsRefused pins that an IPv6 literal with a zone cannot
// slip past the private-address checks: the resolver returns it unchanged,
// net.ParseIP rejects it, and the dialer would connect to the embedded
// address while ignoring the zone.
func TestSSRF_ZonedLiteralsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("internal-secret"))
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: SSRFSafeTransport(5*time.Second, false, false)}
	for _, host := range []string{"[::ffff:127.0.0.1%25zz]", "[::ffff:7f00:1%25eth0]"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+host+":"+port+"/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Errorf("%s reached the loopback server through the SSRF-safe transport: %q", host, body)
		}
	}

	check := newRedirectChecker(false)
	for _, raw := range []string{
		"http://[::ffff:10.0.0.1%25zz]/",
		"http://[fe80::1%25eth0]/",
		"http://[::ffff:169.254.169.254%25x]/latest/meta-data/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		req := (&http.Request{URL: u}).WithContext(context.Background())
		if err := check(req, []*http.Request{{URL: u}}); err == nil {
			t.Errorf("redirect checker accepted %s", raw)
		}
		if err := ValidateBaseURL(raw); err == nil {
			t.Errorf("ValidateBaseURL accepted %s", raw)
		}
	}
}

func TestResolvePublic(t *testing.T) {
	ctx := context.Background()
	for _, host := range []string{"127.0.0.1", "::1", "10.1.2.3", "fe80::1%eth0", "::ffff:127.0.0.1%x", "localhost", "LOCALHOST.", "metadata.google.internal"} {
		if _, err := resolvePublic(ctx, host); err == nil {
			t.Errorf("resolvePublic(%q) accepted a private or zoned address", host)
		}
	}
	addrs, err := resolvePublic(ctx, "93.184.215.14")
	if err != nil || len(addrs) != 1 {
		t.Errorf("resolvePublic(public literal) = %v, %v", addrs, err)
	}
}
