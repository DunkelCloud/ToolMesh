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

package config

import (
	"strings"
	"testing"
)

// TestLoad_CredentialsPageListener pins the settings of the credentials
// page's own listener: it is optional, and its settings only go together.
// A setting that would be ignored stops the start, because whoever set an
// address for the page expects the page to be there and nowhere else.
func TestLoad_CredentialsPageListener(t *testing.T) {
	const (
		bind = ":8444"
		addr = "https://toolmesh.internal.example:8444"
		cert = "/certs/page.crt"
		key  = "/certs/page.key"
		// plain is the address of a listener without TLS on a private network.
		plain = "http://10.0.0.5:8444"
		// hostOnly is what the error says about an address with more than
		// scheme and host.
		hostOnly = "scheme and host only"
		// badPort is what the error says about a listener without a usable port.
		badPort = "port from 1 to 65535"
	)
	cases := []struct {
		name                 string
		bind, url, cert, key string
		wantURL              string
		wantErr              string // part of the error; "" = loads
	}{
		{name: "nothing set: the page stays on the main listener"},
		{name: "listener behind a proxy of one's own", bind: bind, url: addr, wantURL: addr},
		{name: "trailing slash is dropped", bind: "10.0.0.5:8444", url: addr + "/", wantURL: addr},
		{name: "plain http on a private network", bind: bind, url: plain, wantURL: plain},
		{name: "listener with its own certificate", bind: bind, url: addr, cert: cert, key: key, wantURL: addr},
		{name: "the https port is not part of the address", bind: bind, url: "https://toolmesh.internal.example:443", wantURL: "https://toolmesh.internal.example"},
		{name: "the http port is not part of the address", bind: bind, url: "http://10.0.0.5:80/", wantURL: "http://10.0.0.5"},
		{name: "another scheme's port stays", bind: bind, url: "https://toolmesh.internal.example:80", wantURL: "https://toolmesh.internal.example:80"},
		{name: "an IPv6 address", bind: "[::1]:8444", url: "https://[2001:db8::5]:8444", wantURL: "https://[2001:db8::5]:8444"},
		{name: "an IPv6 address on the scheme's port", bind: bind, url: "https://[2001:db8::5]:443", wantURL: "https://[2001:db8::5]"},

		{name: "bind without the address", bind: bind, wantErr: envCredentialsBind + " needs " + envCredentialsURL},
		{name: "address without bind", url: addr, wantErr: envCredentialsBind},
		{name: "certificate without bind", cert: cert, key: key, wantErr: envCredentialsBind},
		{name: "bind that is no address", bind: "8444", url: addr, wantErr: envCredentialsBind},
		{name: "bind without a port", bind: "10.0.0.5:", url: addr, wantErr: badPort},
		{name: "bind with nothing but the colon", bind: ":", url: addr, wantErr: badPort},
		{name: "bind on port 0", bind: ":0", url: addr, wantErr: badPort},
		{name: "bind on a port by name", bind: ":https", url: addr, wantErr: badPort},
		{name: "bind on a port too large", bind: ":70000", url: addr, wantErr: badPort},
		{name: "address with an empty port", bind: bind, url: "https://toolmesh.internal.example:", wantErr: hostOnly},
		{name: "address with a port but no host", bind: bind, url: "https://:8444", wantErr: hostOnly},
		{name: "address with the page's path", bind: bind, url: addr + "/credentials", wantErr: hostOnly},
		{name: "address with a query", bind: bind, url: addr + "/?x=1", wantErr: hostOnly},
		{name: "address with a user", bind: bind, url: "https://user@toolmesh.internal.example", wantErr: hostOnly},
		{name: "address of another scheme", bind: bind, url: "ftp://toolmesh.internal.example", wantErr: "http:// or https://"},
		{name: "address without a host", bind: bind, url: "https://", wantErr: hostOnly},
		{name: "certificate without its key", bind: bind, url: addr, cert: cert, wantErr: "go together"},
		{name: "key without its certificate", bind: bind, url: addr, key: key, wantErr: "go together"},
		{name: "certificate with an http address", bind: bind, url: plain, cert: cert, key: key, wantErr: "serves https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envCredentialsBind, tc.bind)
			t.Setenv(envCredentialsURL, tc.url)
			t.Setenv(envCredentialsTLSCert, tc.cert)
			t.Setenv(envCredentialsTLSKey, tc.key)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load() error = %v, want one that names %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CredentialsBind != tc.bind || cfg.CredentialsURL != tc.wantURL || cfg.CredentialsTLSCert != tc.cert || cfg.CredentialsTLSKey != tc.key {
				t.Errorf("loaded bind %q, address %q, certificate %q, key %q", cfg.CredentialsBind, cfg.CredentialsURL, cfg.CredentialsTLSCert, cfg.CredentialsTLSKey)
			}
		})
	}
}
