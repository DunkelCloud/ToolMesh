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

// TestLoad_TLS pins the settings of TLS on the main listener. TLS is off
// unless a certificate is configured, so an instance behind a reverse proxy
// loads as before. The settings only go together, and one that would be
// ignored stops the start: whoever set it expects https.
func TestLoad_TLS(t *testing.T) {
	const (
		issuer   = "https://toolmesh.example.com/"
		host     = "toolmesh.example.com"
		cert     = "/certs/toolmesh.crt"
		key      = "/certs/toolmesh.key"
		on       = "true"
		redirect = ":8081"
		staging  = "https://acme-staging-v02.api.letsencrypt.org/directory"
		mail     = "admin@example.com"
		// What the errors say.
		together    = "go together"
		servesHTTPS = "serves https"
		needsACME   = "without " + envTLSACME + "=true"
		badPort     = "port from 1 to 65535"
	)
	cases := []struct {
		name                         string
		issuer                       string // "" leaves the placeholder
		cert, key, acme              string
		email, directory, redirectTo string
		wantEnabled                  bool
		wantHost, wantDirectory      string
		wantErr                      string // part of the error; "" = loads
	}{
		{name: "nothing set: plain http, as behind a reverse proxy"},
		{name: "nothing set, with an address", issuer: issuer},
		{name: "ACME switched off explicitly", issuer: issuer, acme: "false"},

		{name: "certificate files", issuer: issuer, cert: cert, key: key, wantEnabled: true},
		{name: "certificate files with the placeholder issuer", cert: cert, key: key, wantEnabled: true},
		{name: "certificate files and the redirect listener", issuer: issuer, cert: cert, key: key, redirectTo: redirect, wantEnabled: true},
		{name: "certificate without its key", issuer: issuer, cert: cert, wantErr: together},
		{name: "key without its certificate", issuer: issuer, key: key, wantErr: together},
		{name: "certificate files with an http issuer", issuer: "http://toolmesh.example.com/", cert: cert, key: key, wantErr: servesHTTPS},
		{name: "certificate files and ACME", issuer: issuer, cert: cert, key: key, acme: on, wantErr: "not from both"},

		{name: "ACME", issuer: issuer, acme: on, wantEnabled: true, wantHost: host, wantDirectory: DefaultACMEDirectory},
		{name: "ACME, host name in another case", issuer: "https://ToolMesh.Example.com/", acme: on, wantEnabled: true, wantHost: host, wantDirectory: DefaultACMEDirectory},
		{name: "ACME, issuer on another port", issuer: "https://toolmesh.example.com:8443/", acme: on, wantEnabled: true, wantHost: host, wantDirectory: DefaultACMEDirectory},
		{name: "ACME with contact, directory and redirect listener", issuer: issuer, acme: on, email: mail, directory: staging, redirectTo: redirect, wantEnabled: true, wantHost: host, wantDirectory: staging},
		{name: "ACME with the placeholder issuer", acme: on, wantErr: envTLSACME + " needs " + envIssuer},
		{name: "ACME with an http issuer", issuer: "http://toolmesh.example.com/", acme: on, wantErr: servesHTTPS},
		{name: "ACME with an IPv4 issuer", issuer: "https://203.0.113.5/", acme: on, wantErr: "an IP address"},
		{name: "ACME with an IPv6 issuer", issuer: "https://[2001:db8::5]/", acme: on, wantErr: "an IP address"},
		{name: "ACME with a host name of one label", issuer: "https://toolmesh/", acme: on, wantErr: "full host name"},
		{name: "ACME that is neither true nor false", issuer: issuer, acme: "yes", wantErr: "must be true or false"},
		{name: "ACME directory over plain http", issuer: issuer, acme: on, directory: "http://ca.example.com/directory", wantErr: envTLSACMEDirectory},
		{name: "ACME directory that is no address", issuer: issuer, acme: on, directory: "letsencrypt", wantErr: envTLSACMEDirectory},
		{name: "ACME contact that is no address", issuer: issuer, acme: on, email: "admin example.com", wantErr: envTLSACMEEmail},
		{name: "ACME contact as a mailto link", issuer: issuer, acme: on, email: "mailto:" + mail, wantErr: envTLSACMEEmail},
		{name: "ACME contact without a domain", issuer: issuer, acme: on, email: "admin@", wantErr: envTLSACMEEmail},

		{name: "contact without ACME", issuer: issuer, email: mail, wantErr: needsACME},
		{name: "directory without ACME", issuer: issuer, directory: staging, wantErr: needsACME},
		{name: "contact with certificate files", issuer: issuer, cert: cert, key: key, email: mail, wantErr: needsACME},

		{name: "redirect listener without https", issuer: issuer, redirectTo: redirect, wantErr: "does not serve https"},
		{name: "redirect listener with the placeholder issuer", cert: cert, key: key, redirectTo: redirect, wantErr: envHTTPRedirectBind + " needs " + envIssuer},
		{name: "redirect listener on port 0", issuer: issuer, cert: cert, key: key, redirectTo: ":0", wantErr: badPort},
		{name: "redirect listener without a port", issuer: issuer, cert: cert, key: key, redirectTo: "10.0.0.5:", wantErr: badPort},
		{name: "redirect listener that is no address", issuer: issuer, acme: on, redirectTo: "8081", wantErr: envHTTPRedirectBind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envIssuer, tc.issuer)
			t.Setenv(envTLSCert, tc.cert)
			t.Setenv(envTLSKey, tc.key)
			t.Setenv(envTLSACME, tc.acme)
			t.Setenv(envTLSACMEEmail, tc.email)
			t.Setenv(envTLSACMEDirectory, tc.directory)
			t.Setenv(envHTTPRedirectBind, tc.redirectTo)
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
			if cfg.TLSEnabled() != tc.wantEnabled {
				t.Errorf("TLSEnabled() = %v, want %v", cfg.TLSEnabled(), tc.wantEnabled)
			}
			if cfg.TLSCert != tc.cert || cfg.TLSKey != tc.key || cfg.TLSACME != (tc.acme == on) {
				t.Errorf("loaded certificate %q, key %q, ACME %v", cfg.TLSCert, cfg.TLSKey, cfg.TLSACME)
			}
			if cfg.TLSACMEHost != tc.wantHost || cfg.TLSACMEDirectory != tc.wantDirectory || cfg.TLSACMEEmail != tc.email {
				t.Errorf("loaded ACME host %q, directory %q, contact %q; want %q, %q, %q", cfg.TLSACMEHost, cfg.TLSACMEDirectory, cfg.TLSACMEEmail, tc.wantHost, tc.wantDirectory, tc.email)
			}
			if cfg.HTTPRedirectBind != tc.redirectTo {
				t.Errorf("loaded redirect listener %q, want %q", cfg.HTTPRedirectBind, tc.redirectTo)
			}
		})
	}
}
