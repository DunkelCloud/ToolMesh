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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withStrictSSRF disables the allow-private-base-url test hook for the
// duration of a test. Tests that exercise SSRF-rejection paths must set
// this so they behave like production.
func withStrictSSRF(t *testing.T) {
	t.Helper()
	prev := allowPrivateBaseURL
	allowPrivateBaseURL = false
	t.Cleanup(func() { allowPrivateBaseURL = prev })
}

func TestValidateBaseURL_Rejects(t *testing.T) {
	withStrictSSRF(t)

	tests := []struct {
		name    string
		url     string
		wantSub string
	}{
		{"localhost", "http://localhost/api", "private hostname"},
		{"metadata.google.internal", "http://metadata.google.internal/", "private hostname"},
		{"loopback_ipv4", "http://127.0.0.1/", "private/loopback"},
		{"loopback_ipv6", "http://[::1]/", "private/loopback"},
		{"private_10", "http://10.0.0.1/", "private/loopback"},
		{"aws_metadata", "http://169.254.169.254/", "private/loopback"},
		{"invalid_scheme", "ftp://example.com/", "scheme"},
		{"no_hostname", "http:///foo", "hostname"},
		{"dns_failure", "http://this-host-does-not-exist.invalid/", "DNS resolution"},
		{"parse_error", "://not a url", "invalid base_url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBaseURL(tt.url)
			if err == nil {
				t.Fatalf("expected error for %q", tt.url)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestValidateBaseURL_AllowedWhenHookOn(t *testing.T) {
	// With the hook enabled (default in tests via export_test.go init),
	// all URLs pass through.
	if err := ValidateBaseURL("http://127.0.0.1/"); err != nil {
		t.Errorf("with allowPrivateBaseURL=true, expected nil, got %v", err)
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"169.254.0.1", true},
		{"169.254.169.254", true},
		{"::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := IsPrivateIP(net.ParseIP(tt.ip)); got != tt.want {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestSSRFSafeTransport_AllowHookOn(t *testing.T) {
	// With hook enabled, transport skips IP validation and dials directly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := SSRFSafeTransport(5 * time.Second)
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestSSRFSafeTransport_RejectsPrivateIP(t *testing.T) {
	withStrictSSRF(t)

	// Dial 127.0.0.1 directly — the transport must refuse.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := SSRFSafeTransport(5 * time.Second)
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected SSRF refusal for private IP, got nil")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error %q should mention private/reserved", err.Error())
	}
}

func TestSSRFSafeCheckRedirect(t *testing.T) {
	// Build fake via chain — we don't actually need real requests.
	mkReq := func(host string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+host+"/", nil)
		return r
	}

	t.Run("too many redirects", func(t *testing.T) {
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = mkReq("example.com")
		}
		if err := ssrfSafeCheckRedirect(mkReq("example.com"), via); err == nil {
			t.Error("expected error on >=10 redirects")
		}
	})

	t.Run("hook on allows all", func(t *testing.T) {
		// Hook is on by default in tests (see export_test.go).
		if err := ssrfSafeCheckRedirect(mkReq("127.0.0.1"), nil); err != nil {
			t.Errorf("with hook on, expected nil, got %v", err)
		}
	})

	t.Run("hook off rejects localhost", func(t *testing.T) {
		withStrictSSRF(t)
		if err := ssrfSafeCheckRedirect(mkReq("localhost"), nil); err == nil {
			t.Error("expected rejection for localhost")
		}
	})

	t.Run("hook off rejects metadata", func(t *testing.T) {
		withStrictSSRF(t)
		if err := ssrfSafeCheckRedirect(mkReq("metadata.google.internal"), nil); err == nil {
			t.Error("expected rejection for metadata")
		}
	})

	t.Run("hook off rejects dns failure", func(t *testing.T) {
		withStrictSSRF(t)
		if err := ssrfSafeCheckRedirect(mkReq("this-does-not-exist.invalid"), nil); err == nil {
			t.Error("expected rejection for DNS failure")
		}
	})

	t.Run("empty hostname passes", func(t *testing.T) {
		withStrictSSRF(t)
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", nil)
		r.URL.Host = ""
		if err := ssrfSafeCheckRedirect(r, nil); err != nil {
			t.Errorf("empty hostname: expected nil, got %v", err)
		}
	})
}
