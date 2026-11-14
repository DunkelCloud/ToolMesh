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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/enroll"
)

const (
	listenLoopback = "127.0.0.1:0"
	listenPageBody = "the credentials page"
	listenPageAddr = "https://credentials.internal.example:8444"
	listenMain     = "main"    // describe() of a page on the main listener
	listenRenewed  = "renewed" // name of the second certificate of the reload test
)

// listenPage stands in for the credentials page: it answers with a fixed
// text and says whether the request arrived over TLS.
func listenPage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("X-Over-TLS", "yes")
		}
		_, _ = io.WriteString(w, listenPageBody)
	})
}

// listenGet sends a GET without following redirects.
func listenGet(t *testing.T, client *http.Client, target string) (status int, body, location, overTLS string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data), resp.Header.Get("Location"), resp.Header.Get("X-Over-TLS")
}

// listenMainGet asks the main listener's mux for a path.
func listenMainGet(mux *http.ServeMux, path string) int {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody))
	return rec.Code
}

// listenCert writes a self-signed certificate for 127.0.0.1 and its key
// into dir and returns the file names and the certificate.
func listenCert(t *testing.T, dir, name string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "page.crt"), filepath.Join(dir, "page.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

// TestServeCredentialsPage_MainListener pins the default: without a listener
// of its own the page is served on the main listener, as an instance that
// is reached directly or behind the operator's own proxy wants it.
func TestServeCredentialsPage_MainListener(t *testing.T) {
	mainMux := http.NewServeMux()
	l, err := serveCredentialsPage(context.Background(), &config.Config{}, mainMux, listenPage(), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if l.describe() != listenMain || l.srv != nil {
		t.Errorf("listener = %q, want the main one and no server started", l.describe())
	}
	for _, path := range []string{enroll.Path, enroll.Path + "/login"} {
		if code := listenMainGet(mainMux, path); code != http.StatusOK {
			t.Errorf("main listener, GET %s = %d, want the page", path, code)
		}
	}
	if err := l.shutdown(context.Background()); err != nil {
		t.Errorf("shutdown = %v", err)
	}
	var none *credentialsListener
	if err := none.shutdown(context.Background()); err != nil || none.describe() != listenMain {
		t.Errorf("a missing listener: shutdown %v, describe %q", err, none.describe())
	}
}

// TestServeCredentialsPage_OwnListener pins what the page's own listener is
// for: the page is there, and the main listener, which may stand behind
// someone else's proxy, does not serve it at all.
func TestServeCredentialsPage_OwnListener(t *testing.T) {
	// The main listener has a handler for everything it does not know, as
	// the real one has: the page's path has to end there, not at the page.
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nothing here", http.StatusNotFound)
	})
	cfg := &config.Config{CredentialsBind: listenLoopback, CredentialsURL: listenPageAddr}
	l, err := serveCredentialsPage(context.Background(), cfg, mainMux, listenPage(), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.shutdown(context.Background()) })

	for _, path := range []string{enroll.Path, enroll.Path + "/", enroll.Path + "/login"} {
		rec := httptest.NewRecorder()
		mainMux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody))
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), listenPageBody) {
			t.Errorf("main listener, GET %s = %d %q, want 404 and no page: the page has its own listener", path, rec.Code, rec.Body.String())
		}
	}
	if !strings.HasSuffix(l.describe(), " (http)") {
		t.Errorf("describe = %q", l.describe())
	}
	base := "http://" + l.addr
	client := &http.Client{Timeout: 5 * time.Second}
	if status, body, _, overTLS := listenGet(t, client, base+enroll.Path); status != http.StatusOK || body != listenPageBody || overTLS != "" {
		t.Errorf("GET the page = %d %q (TLS %q)", status, body, overTLS)
	}
	if status, body, _, _ := listenGet(t, client, base+enroll.Path+"/login"); status != http.StatusOK || body != listenPageBody {
		t.Errorf("GET below the page = %d %q", status, body)
	}
	if status, _, location, _ := listenGet(t, client, base+"/"); status != http.StatusSeeOther || location != enroll.Path {
		t.Errorf("GET / = %d to %q, want a redirect to the page", status, location)
	}
	for _, path := range []string{"/mcp", "/authorize", "/metrics", "/health"} {
		if status, _, _, _ := listenGet(t, client, base+path); status != http.StatusNotFound {
			t.Errorf("GET %s on the page's listener = %d, want 404: it serves the page and nothing else", path, status)
		}
	}

	if err := l.shutdown(context.Background()); err != nil {
		t.Errorf("shutdown = %v", err)
	}
	if conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", l.addr); err == nil {
		_ = conn.Close()
		t.Error("the listener still accepts connections after shutdown")
	}
}

func TestServeCredentialsPage_OwnListenerWithCertificate(t *testing.T) {
	certFile, keyFile, cert := listenCert(t, t.TempDir(), "first")
	cfg := &config.Config{CredentialsBind: listenLoopback, CredentialsURL: listenPageAddr, CredentialsTLSCert: certFile, CredentialsTLSKey: keyFile}
	l, err := serveCredentialsPage(context.Background(), cfg, http.NewServeMux(), listenPage(), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.shutdown(context.Background()) })
	if !strings.HasSuffix(l.describe(), " (https)") {
		t.Errorf("describe = %q", l.describe())
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	if status, body, _, overTLS := listenGet(t, client, "https://"+l.addr+enroll.Path); status != http.StatusOK || body != listenPageBody || overTLS != "yes" {
		t.Errorf("GET the page over https = %d %q (TLS %q)", status, body, overTLS)
	}
	// The listener speaks TLS only: a plain request gets no page.
	plain := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+l.addr+enroll.Path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := plain.Do(req); err == nil {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK || strings.Contains(string(data), listenPageBody) {
			t.Errorf("plain http on the https listener got the page: %d", resp.StatusCode)
		}
	}
}

// TestServeCredentialsPage_StartFails pins that an address that cannot be
// bound and a certificate that does not load stop the start: messages send
// users to the page, so it must not be silently missing.
func TestServeCredentialsPage_StartFails(t *testing.T) {
	taken, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenLoopback)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = taken.Close() })
	cfg := &config.Config{CredentialsBind: taken.Addr().String(), CredentialsURL: listenPageAddr}
	if l, err := serveCredentialsPage(context.Background(), cfg, http.NewServeMux(), listenPage(), quietLogger()); err == nil {
		_ = l.shutdown(context.Background())
		t.Error("an address in use did not fail the start")
	}

	dir := t.TempDir()
	missing := &config.Config{CredentialsBind: listenLoopback, CredentialsURL: listenPageAddr, CredentialsTLSCert: filepath.Join(dir, "none.crt"), CredentialsTLSKey: filepath.Join(dir, "none.key")}
	if l, err := serveCredentialsPage(context.Background(), missing, http.NewServeMux(), listenPage(), quietLogger()); err == nil {
		_ = l.shutdown(context.Background())
		t.Error("missing certificate files did not fail the start")
	}
}

// TestCertReloader pins that a renewed certificate is picked up without a
// restart, and that files which do not load, as in the middle of a renewal,
// leave the certificate in use.
func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, first := listenCert(t, dir, "first")
	var logs bytes.Buffer
	c, err := newCertReloader(certOfCredentialsPage, certFile, keyFile, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.now = func() time.Time { return now }
	c.checked = now
	served := func() string {
		t.Helper()
		cert, err := c.certificate(nil)
		if err != nil || cert == nil || len(cert.Certificate) == 0 {
			t.Fatalf("certificate() = %v, %v", cert, err)
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Subject.CommonName
	}
	// touch gives the files a later modification time, whatever the clock
	// resolution of the file system.
	stamp := time.Now()
	touch := func() {
		t.Helper()
		stamp = stamp.Add(2 * time.Second)
		for _, f := range []string{certFile, keyFile} {
			if err := os.Chtimes(f, stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
	}

	if got := served(); got != first.Subject.CommonName {
		t.Fatalf("serving %q at the start", got)
	}
	listenCert(t, dir, listenRenewed)
	touch()
	if got := served(); got != "first" {
		t.Errorf("serving %q before the next look at the files, want the certificate in use", got)
	}
	now = now.Add(certReloadInterval)
	if got := served(); got != listenRenewed {
		t.Errorf("serving %q after the files changed, want the renewed certificate", got)
	}

	// Half-written files: the certificate in use stays.
	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nnot yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	touch()
	now = now.Add(certReloadInterval)
	if got := served(); got != listenRenewed {
		t.Errorf("serving %q while the files do not load", got)
	}
	if !strings.Contains(logs.String(), "do not load") {
		t.Errorf("no warning about files that do not load:\n%s", logs.String())
	}
	// Files that are gone: the same.
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	now = now.Add(certReloadInterval)
	if got := served(); got != listenRenewed {
		t.Errorf("serving %q while the files are missing", got)
	}
	// And a good pair again is picked up.
	listenCert(t, dir, "third")
	touch()
	now = now.Add(certReloadInterval)
	if got := served(); got != "third" {
		t.Errorf("serving %q after the files were repaired", got)
	}
}

// TestCredentialsPage_OwnAddress pins the address side of the page's own
// listener, with the real page: messages send users to that address, and
// the page takes forms from that address only, not from the address of the
// MCP endpoint.
func TestCredentialsPage_OwnAddress(t *testing.T) {
	// Nothing listens in this test; the settings only have to load.
	t.Setenv("TOOLMESH_CREDENTIALS_BIND", "127.0.0.1:8444")
	t.Setenv("TOOLMESH_CREDENTIALS_URL", listenPageAddr+"/")
	setup, reg, cfg := loadUserBackend(t)
	if want := listenPageAddr + enroll.Path; setup.enrollURL != want {
		t.Errorf("address in messages = %q, want %q", setup.enrollURL, want)
	}
	if got := credentialsPageBase(cfg); got != listenPageAddr {
		t.Errorf("credentialsPageBase = %q", got)
	}
	users := pageUsers{pageUserAlice: true}
	page, err := newCredentialsPage(cfg, setup, reg, users, &toolGrants{off: true}, nil, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	// login sends the sign-in form to the page at target, as a browser on
	// an https page does: with its verdict and the origin it used.
	login := func(target, origin string) int {
		form := url.Values{pageFieldUser: {pageUserAlice}, pageFieldPass: {pageUserPass}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target+pageLoginPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(pageFetchSite, pageSameOrigin)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		page.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := login(listenPageAddr, listenPageAddr); code != http.StatusSeeOther {
		t.Errorf("login at and from the page's own address = %d, want it accepted", code)
	}
	if code := login(listenPageAddr, pageOrigin); code != http.StatusForbidden {
		t.Errorf("login from the MCP endpoint's address = %d, want 403", code)
	}
	// The page reached under the MCP endpoint's name, for instance through
	// a route somebody added in the proxy in front of it: no page, no login.
	if code := login(pageOrigin, pageOrigin); code != http.StatusMisdirectedRequest {
		t.Errorf("login under the MCP endpoint's host name = %d, want 421", code)
	}
	rec := httptest.NewRecorder()
	page.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, pageOrigin+enroll.Path, http.NoBody))
	if rec.Code != http.StatusMisdirectedRequest || strings.Contains(rec.Body.String(), "<form") {
		t.Errorf("GET under the MCP endpoint's host name = %d, want 421 and no form", rec.Code)
	}
}

// TestCredentialsPageSharesHost pins the warning's condition: a page with a
// listener of its own under the host name of the main listener.
func TestCredentialsPageSharesHost(t *testing.T) {
	const (
		issuer = "https://toolmesh.example.com/"
		bind   = ":8444"
	)
	cases := []struct {
		name            string
		bind, page, iss string
		want            bool
	}{
		{"no own listener", "", "", issuer, false},
		{"a host name of its own", bind, listenPageAddr, issuer, false},
		{"the main listener's host name, another port", bind, "https://toolmesh.example.com:8444", issuer, true},
		{"the same in another case", bind, "https://TOOLMESH.example.com:8444", issuer, true},
		{"placeholder issuer", bind, "https://toolmesh.invalid:8444", "https://toolmesh.invalid/", false},
	}
	for _, tc := range cases {
		cfg := &config.Config{CredentialsBind: tc.bind, CredentialsURL: tc.page, Issuer: tc.iss}
		if got := credentialsPageSharesHost(cfg); got != tc.want {
			t.Errorf("%s: shares the host = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCredentialsPageBase pins which address the page counts as its own
// when it stays on the main listener.
func TestCredentialsPageBase(t *testing.T) {
	if got := credentialsPageBase(&config.Config{Issuer: "https://toolmesh.example.com/"}); got != "https://toolmesh.example.com" {
		t.Errorf("on the main listener = %q, want the public address", got)
	}
	if got := credentialsPageBase(&config.Config{Issuer: "https://toolmesh.invalid/"}); got != "" {
		t.Errorf("with the placeholder issuer = %q, want none", got)
	}
}
