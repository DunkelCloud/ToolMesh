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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

const (
	tlsHost   = "toolmesh.example.com" // the host name of the instance in these tests
	tlsIssuer = "https://" + tlsHost + "/"
	tlsNonce  = "Replay-Nonce"
	tlsStatus = "status"
	tlsReady  = "TLS certificate ready"
	// tlsFinalize is the member of an ACME order that holds the address
	// its certificate is requested at.
	tlsFinalize = "finalize"
)

// tlsServe serves the stand-in page on a loopback listener the way main
// serves the main listener, and returns the listener's address. The server
// is shut down with the test.
func tlsServe(t *testing.T, mt *mainTLS, logger *slog.Logger) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenLoopback)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &http.Server{Handler: listenPage(), ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- mt.serve(ctx, srv, ln, logger) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Shutdown(context.Background())
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve returned %v, want the server closed", err)
		}
	})
	return ln.Addr().String()
}

// tlsClient is an https client that trusts root and asks for the
// certificate of serverName, whatever address it connects to.
func tlsClient(root *x509.Certificate, serverName string) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}},
	}
}

// TestNewMainTLS_Off pins the default: without a certificate the main
// listener speaks plain http, as an instance behind a reverse proxy needs it.
func TestNewMainTLS_Off(t *testing.T) {
	mt, err := newMainTLS(&config.Config{DataDir: t.TempDir()}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if mt.mode != tlsModeOff || mt.config != nil || mt.acme != nil {
		t.Fatalf("mode %q, TLS config %v: want plain http", mt.mode, mt.config)
	}
	addr := tlsServe(t, mt, quietLogger())
	client := &http.Client{Timeout: 5 * time.Second}
	if status, body, _, overTLS := listenGet(t, client, "http://"+addr+"/"); status != http.StatusOK || body != listenPageBody || overTLS != "" {
		t.Errorf("GET over plain http = %d %q (TLS %q)", status, body, overTLS)
	}
}

// TestMainTLS_Files pins https with a certificate from files: the page is
// served over TLS 1.2 or later, and over nothing else.
func TestMainTLS_Files(t *testing.T) {
	certFile, keyFile, cert := listenCert(t, t.TempDir(), "main")
	mt, err := newMainTLS(&config.Config{TLSCert: certFile, TLSKey: keyFile}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if mt.mode != tlsModeFiles || mt.config == nil || mt.config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("mode %q, TLS config %+v", mt.mode, mt.config)
	}
	addr := tlsServe(t, mt, quietLogger())

	client := tlsClient(cert, "")
	if status, body, _, overTLS := listenGet(t, client, "https://"+addr+"/"); status != http.StatusOK || body != listenPageBody || overTLS != "yes" {
		t.Errorf("GET over https = %d %q (TLS %q)", status, body, overTLS)
	}

	// A client that speaks nothing newer than TLS 1.1 is refused.
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	old := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11} //nolint:gosec // G402: the old version is what the test offers
	conn, err := (&tls.Dialer{Config: old, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}).DialContext(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Error("a TLS 1.1 client was accepted")
	}

	// Plain http on the https listener gets no page.
	plain := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", http.NoBody)
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

// TestNewMainTLS_StartFails pins that a certificate that does not load and
// a place for the ACME certificate that cannot be written stop the start.
// The first would leave the listener without https; the second would
// request a new certificate at every start.
func TestNewMainTLS_StartFails(t *testing.T) {
	dir := t.TempDir()
	missing := &config.Config{TLSCert: filepath.Join(dir, "none.crt"), TLSKey: filepath.Join(dir, "none.key")}
	if _, err := newMainTLS(missing, quietLogger()); err == nil || !strings.Contains(err.Error(), certOfMainListener) {
		t.Errorf("missing certificate files: error %v, want one that names the main listener", err)
	}

	// The data directory is a file: nothing can be kept below it.
	file := filepath.Join(dir, "data")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unwritable := &config.Config{TLSACME: true, TLSACMEHost: tlsHost, TLSACMEDirectory: config.DefaultACMEDirectory, DataDir: file}
	if _, err := newMainTLS(unwritable, quietLogger()); err == nil || !strings.Contains(err.Error(), "cannot be written") {
		t.Errorf("unwritable certificate directory: error %v, want one that says so", err)
	}
}

// fakeCA is an ACME certificate authority for tests. It issues what is
// asked for without validating anything: orders are ready at once, as with
// an authority that still holds a valid authorization for the name.
type fakeCA struct {
	t      *testing.T
	srv    *httptest.Server
	key    *ecdsa.PrivateKey
	root   *x509.Certificate
	refuse bool          // answer new orders with an error
	async  bool          // answer the finalize request the way Pebble does
	life   time.Duration // lifetime of issued certificates

	mu     sync.Mutex
	issued int
	chain  []byte // PEM of the certificate issued last
	agent  string // User-Agent of the last new order
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &fakeCA{t: t, key: key, root: root, life: 90 * 24 * time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", ca.directory)
	mux.HandleFunc("/nonce", ca.nonce)
	mux.HandleFunc("/account", ca.account)
	mux.HandleFunc("/order", ca.order)
	mux.HandleFunc("/order/1", ca.orderState)
	mux.HandleFunc("/"+tlsFinalize, ca.finalize)
	mux.HandleFunc("/cert", ca.certificate)
	ca.srv = httptest.NewServer(mux)
	t.Cleanup(ca.srv.Close)
	return ca
}

// config is the configuration of an instance that takes its certificate
// from this authority and keeps it below dataDir.
func (ca *fakeCA) config(dataDir string) *config.Config {
	return &config.Config{TLSACME: true, TLSACMEHost: tlsHost, TLSACMEDirectory: ca.srv.URL + "/dir", TLSACMEEmail: "admin@example.com", DataDir: dataDir, Issuer: tlsIssuer}
}

// finalizeURL is the address certificates of this authority's orders are
// requested at.
func (ca *fakeCA) finalizeURL() string {
	return ca.srv.URL + "/" + tlsFinalize
}

// count is the number of certificates issued so far.
func (ca *fakeCA) count() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.issued
}

// reply answers an ACME request with JSON. Every answer carries a nonce
// for the client's next request.
func (ca *fakeCA) reply(w http.ResponseWriter, status int, location string, body any) {
	w.Header().Set(tlsNonce, "nonce")
	if location != "" {
		w.Header().Set("Location", ca.srv.URL+location)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		ca.t.Errorf("fake CA: %v", err)
	}
}

// payload returns the payload of a signed ACME request. The signature is
// not looked at.
func (ca *fakeCA) payload(r *http.Request, into any) {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		ca.t.Errorf("fake CA: request body: %v", err)
		return
	}
	data, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		ca.t.Errorf("fake CA: payload: %v", err)
		return
	}
	if err := json.Unmarshal(data, into); err != nil {
		ca.t.Errorf("fake CA: payload: %v", err)
	}
}

func (ca *fakeCA) directory(w http.ResponseWriter, _ *http.Request) {
	ca.reply(w, http.StatusOK, "", map[string]string{
		"newNonce":   ca.srv.URL + "/nonce",
		"newAccount": ca.srv.URL + "/account",
		"newOrder":   ca.srv.URL + "/order",
	})
}

func (ca *fakeCA) nonce(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(tlsNonce, "nonce")
	w.WriteHeader(http.StatusNoContent)
}

func (ca *fakeCA) account(w http.ResponseWriter, _ *http.Request) {
	ca.reply(w, http.StatusCreated, "/account/1", map[string]string{tlsStatus: "valid"})
}

func (ca *fakeCA) order(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	ca.agent = r.UserAgent()
	ca.mu.Unlock()
	if ca.refuse {
		ca.reply(w, http.StatusForbidden, "", map[string]any{
			"type":    "urn:ietf:params:acme:error:rejectedIdentifier",
			"detail":  "this authority issues nothing",
			tlsStatus: http.StatusForbidden,
		})
		return
	}
	var req struct {
		Identifiers []map[string]string `json:"identifiers"`
	}
	ca.payload(r, &req)
	ca.reply(w, http.StatusCreated, "/order/1", map[string]any{
		tlsStatus:        acme.StatusReady,
		"identifiers":    req.Identifiers,
		"authorizations": []string{},
		tlsFinalize:      ca.finalizeURL(),
	})
}

func (ca *fakeCA) finalize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSR string `json:"csr"`
	}
	ca.payload(r, &req)
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		ca.t.Errorf("fake CA: CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		ca.t.Errorf("fake CA: CSR: %v", err)
		http.Error(w, "no CSR", http.StatusBadRequest)
		return
	}
	ca.mu.Lock()
	ca.issued++
	serial := int64(ca.issued) + 1
	ca.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: tlsHost},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ca.life),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, csr.PublicKey, ca.key)
	if err != nil {
		ca.t.Errorf("fake CA: %v", err)
	}
	var chain bytes.Buffer
	for _, c := range [][]byte{leaf, ca.root.Raw} {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	ca.mu.Lock()
	ca.chain = chain.Bytes()
	ca.mu.Unlock()
	if ca.async {
		// As Pebble answers: the order is still being processed, and the
		// answer names no address to ask at for the outcome.
		ca.reply(w, http.StatusOK, "", map[string]any{
			tlsStatus:   acme.StatusProcessing,
			tlsFinalize: ca.finalizeURL(),
		})
		return
	}
	ca.orderState(w, r)
}

// orderState answers with the order once its certificate is issued.
func (ca *fakeCA) orderState(w http.ResponseWriter, _ *http.Request) {
	ca.reply(w, http.StatusOK, "/order/1", map[string]any{
		tlsStatus:     acme.StatusValid,
		tlsFinalize:   ca.finalizeURL(),
		"certificate": ca.srv.URL + "/cert",
	})
}

func (ca *fakeCA) certificate(w http.ResponseWriter, _ *http.Request) {
	ca.mu.Lock()
	chain := ca.chain
	ca.mu.Unlock()
	w.Header().Set(tlsNonce, "nonce")
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(chain)
}

// syncBuffer is a log buffer that the test and a goroutine may use at the
// same time.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor waits until the log holds text.
func (b *syncBuffer) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(b.String(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("the log never said %q:\n%s", text, b.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// tlsSerial asks the listener at addr for the page as host and returns the
// serial number of the certificate it presented.
func tlsSerial(t *testing.T, root *x509.Certificate, addr, host string) string {
	t.Helper()
	client := tlsClient(root, host)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET as %s: %v", host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(data) != listenPageBody || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("GET as %s = %d %q", host, resp.StatusCode, data)
	}
	return resp.TLS.PeerCertificates[0].SerialNumber.String()
}

// TestMainTLS_ACME pins https with a certificate from an ACME certificate
// authority: ToolMesh obtains it at the start, serves it for the host name
// of the instance and no other, and keeps it, so that a restart asks the
// authority for nothing.
func TestMainTLS_ACME(t *testing.T) {
	ca := newFakeCA(t)
	// The authority answers the finalize request without the order's
	// address, as Pebble does; the certificate arrives all the same.
	ca.async = true
	dataDir := t.TempDir()

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	mt, err := newMainTLS(ca.config(dataDir), logger)
	if err != nil {
		t.Fatal(err)
	}
	if mt.mode != tlsModeACME || mt.config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("mode %q, minimum version %x", mt.mode, mt.config.MinVersion)
	}
	if !strings.Contains(strings.Join(mt.config.NextProtos, " "), acme.ALPNProto) {
		t.Errorf("protocols %v: the listener does not answer TLS-ALPN-01 challenges", mt.config.NextProtos)
	}
	addr := tlsServe(t, mt, logger)

	// The certificate is there before any client asked for it.
	logs.waitFor(t, tlsReady)
	if ca.count() != 1 {
		t.Fatalf("%d certificates issued at the start, want 1", ca.count())
	}
	first := tlsSerial(t, ca.root, addr, tlsHost)
	if ca.count() != 1 {
		t.Errorf("%d certificates issued after the first client, want the one from the start", ca.count())
	}
	ca.mu.Lock()
	agent := ca.agent
	ca.mu.Unlock()
	if !strings.HasPrefix(agent, "ToolMesh/") {
		t.Errorf("User-Agent at the authority = %q, want it to name ToolMesh", agent)
	}

	// Another host name gets no certificate, and no order at the authority.
	other := tlsClient(ca.root, "other.example.com")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+addr+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := other.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("a host name that is not the instance's was served a certificate")
	}
	if ca.count() != 1 {
		t.Errorf("%d certificates issued after a request for another host name", ca.count())
	}

	// The account key and the certificate are kept below the data
	// directory, in the directory of this authority.
	entries, err := os.ReadDir(acmeDir(dataDir, ca.srv.URL+"/dir"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if kept := strings.Join(names, " "); !strings.Contains(kept, tlsHost) || !strings.Contains(kept, "acme_account") {
		t.Errorf("kept below the data directory: %q, want the certificate and the account key", kept)
	}

	// A second instance on the same data directory, as after a restart,
	// serves the same certificate. The authority is gone by then.
	ca.srv.Close()
	var logs2 syncBuffer
	logger2 := slog.New(slog.NewTextHandler(&logs2, nil))
	again, err := newMainTLS(ca.config(dataDir), logger2)
	if err != nil {
		t.Fatal(err)
	}
	addr2 := tlsServe(t, again, logger2)
	logs2.waitFor(t, tlsReady)
	if second := tlsSerial(t, ca.root, addr2, tlsHost); second != first {
		t.Errorf("after a restart the certificate has serial %s, want the kept one, %s", second, first)
	}
}

// TestMainTLS_ACME_AuthorityChange pins that each certificate authority has
// its own place below the data directory: after a change of the directory
// URL, say from a staging environment to the real one, the certificate
// comes from the new authority instead of the kept one being served on, and
// a change back finds the first one again.
func TestMainTLS_ACME_AuthorityChange(t *testing.T) {
	staging, prod := newFakeCA(t), newFakeCA(t)
	dataDir := t.TempDir()
	obtain := func(ca *fakeCA) string {
		t.Helper()
		mt, err := newMainTLS(ca.config(dataDir), quietLogger())
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := mt.certificate()
		if err != nil {
			t.Fatal(err)
		}
		if err := leaf.CheckSignatureFrom(ca.root); err != nil {
			t.Errorf("the certificate served is not from the configured authority: %v", err)
		}
		return leaf.SerialNumber.String() + " of " + ca.srv.URL
	}
	first := obtain(staging)
	if staging.count() != 1 || prod.count() != 0 {
		t.Fatalf("certificates issued: %d and %d, want 1 and 0", staging.count(), prod.count())
	}
	obtain(prod)
	if staging.count() != 1 || prod.count() != 1 {
		t.Errorf("after the change of authority: %d and %d certificates issued, want one each", staging.count(), prod.count())
	}
	if again := obtain(staging); again != first || staging.count() != 1 {
		t.Errorf("back at the first authority: certificate %s, %d issued; want the kept one, %s", again, staging.count(), first)
	}
	if a, b := acmeDir(dataDir, "https://ca.example.com/acme/one/directory"), acmeDir(dataDir, "https://ca.example.com/acme/two/directory"); a == b || !strings.Contains(a, "ca.example.com-") {
		t.Errorf("two directories of one host are kept in %q and %q", a, b)
	}
	if dir := acmeDir(dataDir, "https://[2001:db8::5]:14000/dir"); strings.ContainsAny(filepath.Base(dir), ":[]") {
		t.Errorf("directory name %q holds characters of an address", filepath.Base(dir))
	}
}

// TestLookAtCertificate pins what the log says about the certificate of an
// ACME certificate authority: an authority that issues none is an error
// with growing waits between the attempts, a certificate that was renewed
// is named, and one that nears its end without a renewal is a warning.
func TestLookAtCertificate(t *testing.T) {
	ca := newFakeCA(t)
	ca.refuse = true
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	dataDir := t.TempDir()
	mt, err := newMainTLS(ca.config(dataDir), logger)
	if err != nil {
		t.Fatal(err)
	}
	var watch certWatch
	now := time.Now()
	for i, want := range []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour} {
		if wait := mt.lookAtCertificate(&watch, now, logger); wait != want {
			t.Errorf("attempt %d without a certificate: next try in %s, want %s", i+1, wait, want)
		}
	}
	if out := logs.String(); !strings.Contains(out, "issued none") || !strings.Contains(out, "this authority issues nothing") || !strings.Contains(out, tlsHost) {
		t.Errorf("the log does not say what the authority answered:\n%s", out)
	}

	// The authority issues: the certificate is reported once. The ACME
	// client keeps a failure for a minute before it asks again, so the
	// certificate arrives at a new instance, as after a restart.
	ca.refuse = false
	mt, err = newMainTLS(ca.config(dataDir), logger)
	if err != nil {
		t.Fatal(err)
	}
	watch = certWatch{}
	if wait := mt.lookAtCertificate(&watch, now, logger); wait != acmeCheckInterval {
		t.Errorf("with a certificate: next look in %s, want %s", wait, acmeCheckInterval)
	}
	if watch.failures != 0 || watch.notAfter.IsZero() {
		t.Errorf("after the certificate arrived: %+v", watch)
	}
	mt.lookAtCertificate(&watch, now, logger)
	if n := strings.Count(logs.String(), tlsReady); n != 1 {
		t.Errorf("the certificate was reported %d times, want once", n)
	}
	if strings.Contains(logs.String(), "not renewed yet") {
		t.Errorf("a fresh certificate was reported as close to its end:\n%s", logs.String())
	}

	// Ten days before the end of a 90-day certificate the renewal is
	// overdue.
	mt.lookAtCertificate(&watch, watch.notAfter.Add(-10*24*time.Hour), logger)
	if !strings.Contains(logs.String(), "not renewed yet") {
		t.Errorf("no warning about a certificate close to its end:\n%s", logs.String())
	}

	// A certificate with another end than the one reported last is a
	// renewed one.
	watch.notAfter = watch.notAfter.Add(-time.Hour)
	mt.lookAtCertificate(&watch, now, logger)
	if !strings.Contains(logs.String(), "TLS certificate renewed") {
		t.Errorf("a renewed certificate was not reported:\n%s", logs.String())
	}
}

// TestServeHTTPRedirect pins the plain http listener next to an https main
// listener: it sends browsers to the https address of the instance, serves
// nothing itself, and with ACME answers the authority's HTTP-01 challenges.
func TestServeHTTPRedirect(t *testing.T) {
	const (
		issuer = "https://" + tlsHost + ":8443/"
		target = "https://" + tlsHost + ":8443"
	)
	// Not configured: no listener.
	none, err := serveHTTPRedirect(context.Background(), &config.Config{Issuer: issuer}, &mainTLS{mode: tlsModeFiles}, quietLogger())
	if err != nil || none.srv != nil {
		t.Fatalf("without the setting: %v, server %v", err, none.srv)
	}
	if err := none.shutdown(context.Background()); err != nil {
		t.Errorf("shutdown without a listener = %v", err)
	}
	var missing *redirectListener
	if err := missing.shutdown(context.Background()); err != nil {
		t.Errorf("shutdown of a missing listener = %v", err)
	}

	cfg := &config.Config{Issuer: issuer, HTTPRedirectBind: listenLoopback}
	l, err := serveHTTPRedirect(context.Background(), cfg, &mainTLS{mode: tlsModeFiles}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.shutdown(context.Background()) })
	base := "http://" + l.addr
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/", "/mcp", "/credentials/login?next=%2Fx&a=b", "/a%2Fb"} {
		status, body, location, _ := listenGet(t, client, base+path)
		if status != http.StatusPermanentRedirect || location != target+path || strings.Contains(body, listenPageBody) {
			t.Errorf("GET %s = %d to %q, want a redirect to %s", path, status, location, target+path)
		}
	}
	// A path that looks like another host stays on this one.
	if _, _, location, _ := listenGet(t, client, base+"//other.example.com/x"); !strings.HasPrefix(location, target+"/") {
		t.Errorf("GET //other.example.com/x redirects to %q, want an address at %s", location, target)
	}
	// Without ACME the challenge path is a path like any other.
	if status, _, _, _ := listenGet(t, client, base+"/.well-known/acme-challenge/token"); status != http.StatusPermanentRedirect {
		t.Errorf("GET of a challenge path without ACME = %d, want the redirect", status)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/mcp", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), target) {
		t.Errorf("POST = %d %q, want 400 and the https address", resp.StatusCode, data)
	}

	// An address in use stops the start.
	taken := &config.Config{Issuer: issuer, HTTPRedirectBind: l.addr}
	if second, err := serveHTTPRedirect(context.Background(), taken, &mainTLS{mode: tlsModeFiles}, quietLogger()); err == nil {
		_ = second.shutdown(context.Background())
		t.Error("an address in use did not fail the start")
	}

	// With ACME the listener answers challenges for the instance's host
	// name: an unknown token is not found, and not redirected.
	ca := newFakeCA(t)
	acmeCfg := ca.config(t.TempDir())
	acmeCfg.HTTPRedirectBind = listenLoopback
	mt, err := newMainTLS(acmeCfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	al, err := serveHTTPRedirect(context.Background(), acmeCfg, mt, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.shutdown(context.Background()) })
	challenge := func(host string) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+al.addr+"/.well-known/acme-challenge/token", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if status := challenge(tlsHost); status != http.StatusNotFound {
		t.Errorf("unknown challenge for the instance's host name = %d, want 404", status)
	}
	// An authority that validates on another port than 80 names the port.
	if status := challenge(tlsHost + ":8081"); status != http.StatusNotFound {
		t.Errorf("unknown challenge for the instance's host name with a port = %d, want 404", status)
	}
	if status := challenge("other.example.com:8081"); status != http.StatusForbidden {
		t.Errorf("challenge for another host name with a port = %d, want 403", status)
	}
	if status := challenge("other.example.com"); status != http.StatusForbidden {
		t.Errorf("challenge for another host name = %d, want 403", status)
	}
	if status, _, location, _ := listenGet(t, client, "http://"+al.addr+"/mcp"); status != http.StatusPermanentRedirect || location != "https://"+tlsHost+"/mcp" {
		t.Errorf("GET /mcp with ACME = %d to %q, want the redirect", status, location)
	}
}

// TestServerLogWriter pins where the reports of an https server go: failed
// handshakes, which a listener on the internet sees all day, to the debug
// level, everything else to a warning.
func TestServerLogWriter(t *testing.T) {
	var logs bytes.Buffer
	w := serverLogWriter{logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	for _, line := range []string{
		"http: TLS handshake error from 203.0.113.7:51234: EOF\n",
		"http: Accept error: too many open files; retrying in 5ms\n",
	} {
		if n, err := w.Write([]byte(line)); err != nil || n != len(line) {
			t.Errorf("Write = %d, %v", n, err)
		}
	}
	out := logs.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "handshake error from 203.0.113.7") {
		t.Errorf("a failed handshake is not at the debug level:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "Accept error") {
		t.Errorf("another error is not a warning:\n%s", out)
	}
}
