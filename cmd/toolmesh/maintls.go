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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
	"github.com/DunkelCloud/ToolMesh/internal/version"
)

// The ways the main listener is served.
const (
	tlsModeOff   = "off"   // plain http, for a reverse proxy that ends TLS
	tlsModeFiles = "files" // https with the certificate in two PEM files
	tlsModeACME  = "acme"  // https with a certificate from an ACME certificate authority
)

// acmeDirName is the directory below TOOLMESH_DATA_DIR that holds the ACME
// account key and the certificate.
const acmeDirName = "acme"

// mainTLS is how the main listener serves https, when it does.
type mainTLS struct {
	mode   string
	config *tls.Config       // nil in tlsModeOff
	acme   *autocert.Manager // set in tlsModeACME
	host   string            // the host name of the ACME certificate
}

// newMainTLS sets up TLS for the main listener as configured. Without a
// certificate the listener stays on plain http. Certificate files that do
// not load and a directory for the ACME certificate that cannot be written
// are errors: the first would leave the listener without https, the second
// would request a new certificate at every start until the authority
// refuses.
func newMainTLS(cfg *config.Config, logger *slog.Logger) (*mainTLS, error) {
	switch {
	case cfg.TLSCert != "":
		certs, err := newCertReloader(certOfMainListener, cfg.TLSCert, cfg.TLSKey, logger)
		if err != nil {
			return nil, err
		}
		return &mainTLS{
			mode:   tlsModeFiles,
			config: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.certificate},
		}, nil
	case cfg.TLSACME:
		dir := filepath.Join(cfg.DataDir, acmeDirName)
		if err := writableDir(dir); err != nil {
			return nil, fmt.Errorf("TOOLMESH_TLS_ACME: the certificate is kept in %s, which cannot be written: %w", dir, err)
		}
		allowed := autocert.HostWhitelist(cfg.TLSACMEHost)
		manager := &autocert.Manager{
			// Turning ACME on is the operator's agreement to the
			// authority's terms; the documentation says so.
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(dir),
			HostPolicy: func(ctx context.Context, host string) error {
				// An HTTP-01 challenge names the host as the request
				// did, with the port when that is not 80.
				if name, _, err := net.SplitHostPort(host); err == nil {
					host = name
				}
				return allowed(ctx, host)
			},
			Email: cfg.TLSACMEEmail,
			Client: &acme.Client{
				DirectoryURL: cfg.TLSACMEDirectory,
				UserAgent:    "ToolMesh/" + version.Version,
				HTTPClient:   &http.Client{Transport: &orderLocations{next: http.DefaultTransport, urls: map[string]string{}}},
			},
		}
		tlsConfig := manager.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS12
		return &mainTLS{mode: tlsModeACME, config: tlsConfig, acme: manager, host: cfg.TLSACMEHost}, nil
	}
	return &mainTLS{mode: tlsModeOff}, nil
}

// maxACMEAnswer bounds the JSON answer of an ACME certificate authority that
// orderLocations reads; answers about orders are a few hundred bytes.
const maxACMEAnswer = 1 << 20

// orderLocations is the transport of the ACME client. An authority answers
// the request that finalizes an order with the order, and the client takes
// the order's address from the Location header of that answer to ask there
// for the certificate. RFC 8555 shows the header in that answer without
// requiring it, and some authorities leave it out, Pebble among them; the
// client then has no address to ask at and gives up. This transport
// remembers the address each order was created under and adds it to an
// answer about the same order that carries none.
type orderLocations struct {
	next http.RoundTripper

	mu   sync.Mutex
	urls map[string]string // finalize URL of an order -> the order's address
}

// RoundTrip sends req and completes an answer about a known order that
// lacks its Location header.
func (o *orderLocations) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := o.next.RoundTrip(req)
	if err != nil || req.Method != http.MethodPost || !strings.Contains(res.Header.Get("Content-Type"), "json") {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxACMEAnswer+1))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maxACMEAnswer {
		return nil, fmt.Errorf("answer of the ACME certificate authority to %s is larger than %d bytes", req.URL.Path, maxACMEAnswer)
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	// Orders are told apart by their finalize URL, which every answer
	// about an order carries.
	var order struct {
		Finalize string `json:"finalize"`
	}
	if json.Unmarshal(body, &order) != nil || order.Finalize == "" {
		return res, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if location := res.Header.Get("Location"); location != "" {
		// An instance orders a certificate every few weeks; the table is
		// emptied long before it matters.
		if len(o.urls) >= 64 {
			clear(o.urls)
		}
		o.urls[order.Finalize] = location
	} else if location, ok := o.urls[order.Finalize]; ok {
		res.Header.Set("Location", location)
	}
	return res, nil
}

// writableDir makes sure that dir exists and that files can be created in
// it.
func writableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}

// serve serves srv on ln until the server is shut down: plain http, or
// https with the certificate of this mainTLS. With ACME it also obtains
// the certificate now and keeps an eye on it.
func (t *mainTLS) serve(ctx context.Context, srv *http.Server, ln net.Listener, logger *slog.Logger) error {
	if t.config == nil {
		return srv.Serve(ln)
	}
	srv.TLSConfig = t.config
	srv.ErrorLog = log.New(serverLogWriter{logger: logger}, "", 0)
	if t.acme != nil {
		go t.keepCertificate(ctx, logger)
	}
	return srv.ServeTLS(ln, "", "")
}

// serverLogWriter takes what an http.Server that serves https reports. A
// listener that is reached directly sees failed TLS handshakes all day:
// scanners, clients that speak plain http, names it has no certificate
// for. They go to the debug level; everything else is a warning.
type serverLogWriter struct {
	logger *slog.Logger
}

// Write logs one line of the server's error log.
func (w serverLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if strings.Contains(line, "TLS handshake error") {
		w.logger.Debug("http server: TLS handshake failed", "detail", line)
	} else {
		w.logger.Warn("http server reported an error", "detail", line)
	}
	return len(p), nil
}

// acmeRetryDelays are the waits between attempts to obtain the certificate
// while the authority issues none; the last one repeats. They grow, because
// authorities count failed validations per hour, and they stay above the
// minute for which the ACME client keeps a failure and answers without
// asking the authority again.
var acmeRetryDelays = []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// acmeCheckInterval is how often the certificate in use is looked at.
const acmeCheckInterval = 12 * time.Hour

// certWatch is what keepCertificate remembers between two looks at the
// certificate.
type certWatch struct {
	notAfter time.Time // the end of the certificate reported last; zero: none yet
	failures int       // attempts in a row in which the authority issued none
}

// keepCertificate obtains the certificate when ToolMesh starts, instead of
// with the first client that connects, and reports what became of it. The
// ACME client renews the certificate by itself and says nothing either way,
// so this is where the log tells of a renewal, and of a certificate that
// nears its end without one.
func (t *mainTLS) keepCertificate(ctx context.Context, logger *slog.Logger) {
	var watch certWatch
	for {
		wait := t.lookAtCertificate(&watch, time.Now(), logger)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// lookAtCertificate is one round of keepCertificate: it asks for the
// certificate, which obtains it when there is none, logs what changed
// since the last round and returns the time to wait until the next.
func (t *mainTLS) lookAtCertificate(watch *certWatch, now time.Time, logger *slog.Logger) time.Duration {
	leaf, err := t.certificate()
	if err != nil {
		wait := acmeRetryDelays[min(watch.failures, len(acmeRetryDelays)-1)]
		watch.failures++
		logger.Error("TLS certificate: the ACME certificate authority issued none. Until it does, clients cannot connect over https. The authority has to reach this instance under the host name on port 443, or on port 80 with TOOLMESH_HTTP_REDIRECT_BIND",
			"host", t.host, "directory", t.acme.Client.DirectoryURL, "error", err, "nextTry", wait.String())
		return wait
	}
	watch.failures = 0
	switch {
	case watch.notAfter.IsZero():
		logger.Info("TLS certificate ready", "host", t.host, "issuer", leaf.Issuer.CommonName, "validUntil", leaf.NotAfter.UTC().Format(time.RFC3339))
	case !leaf.NotAfter.Equal(watch.notAfter):
		logger.Info("TLS certificate renewed", "host", t.host, "issuer", leaf.Issuer.CommonName, "validUntil", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	watch.notAfter = leaf.NotAfter

	// The ACME client renews 30 days before the end, or in the last third
	// of a shorter lifetime. A certificate that is halfway through that
	// time without a renewal is worth a warning.
	renewWindow := min(30*24*time.Hour, leaf.NotAfter.Sub(leaf.NotBefore)/3)
	if leaf.NotAfter.Sub(now) < renewWindow/2 {
		logger.Warn("TLS certificate: not renewed yet and close to its end. The authority has to reach this instance under the host name on port 443, or on port 80 with TOOLMESH_HTTP_REDIRECT_BIND",
			"host", t.host, "validUntil", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return min(acmeCheckInterval, max(renewWindow/4, time.Minute))
}

// certificate returns the certificate the ACME client serves for the host,
// and has the client obtain it when there is none. The hello is that of a
// current client, so that it is the certificate such clients get.
func (t *mainTLS) certificate() (*x509.Certificate, error) {
	cert, err := t.acme.GetCertificate(&tls.ClientHelloInfo{
		ServerName:       t.host,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		return nil, err
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("the ACME client returned an empty certificate")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// redirectListener is the plain http listener next to a main listener that
// serves https.
type redirectListener struct {
	srv  *http.Server // nil when there is no such listener
	addr string
}

// serveHTTPRedirect starts the plain http listener of
// TOOLMESH_HTTP_REDIRECT_BIND, if it is set. The listener sends GET and
// HEAD requests to the https address of TOOLMESH_ISSUER and refuses the
// rest; it serves nothing of ToolMesh itself. With ACME it also answers
// the authority's HTTP-01 challenges, which lets the authority validate
// over port 80 where it does not reach the main listener on port 443.
func serveHTTPRedirect(ctx context.Context, cfg *config.Config, t *mainTLS, logger *slog.Logger) (*redirectListener, error) {
	if cfg.HTTPRedirectBind == "" {
		return &redirectListener{}, nil
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Host == "" {
		return nil, fmt.Errorf("TOOLMESH_HTTP_REDIRECT_BIND: TOOLMESH_ISSUER %q names no host to redirect to", cfg.Issuer)
	}
	handler := redirectToHTTPS(issuer.Host)
	if t.acme != nil {
		// HTTPHandler also tells the ACME client that it may offer the
		// authority an HTTP-01 challenge.
		handler = t.acme.HTTPHandler(handler)
	}
	l := &redirectListener{
		srv: &http.Server{
			Handler:           mcp.PanicRecovery(logger)(mcp.SecurityHeaders(handler)),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 << 10,
		},
	}
	// Listening happens here, not in the goroutine: an address that cannot
	// be bound stops the start instead of leaving an ACME setup without
	// the port its authority validates on.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.HTTPRedirectBind)
	if err != nil {
		return nil, fmt.Errorf("TOOLMESH_HTTP_REDIRECT_BIND: %w", err)
	}
	l.addr = ln.Addr().String()
	go func() {
		if err := l.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http redirect listener error", "error", err)
		}
	}()
	logger.Info("http redirect listener started", "addr", l.addr, "to", "https://"+issuer.Host, "acmeHTTP01", t.acme != nil)
	return l, nil
}

// redirectToHTTPS sends GET and HEAD requests to the same path of the https
// address at host. Other requests are refused instead of redirected: a
// client that posts to the plain http address has sent its request, and
// what it carries, in the clear, and should be told so instead of being
// kept working.
func redirectToHTTPS(host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "This address only redirects to https://"+host+". Use the https address.", http.StatusBadRequest)
			return
		}
		target := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
	})
}

// shutdown stops the listener; it does nothing when there is none.
func (l *redirectListener) shutdown(ctx context.Context) error {
	if l == nil || l.srv == nil {
		return nil
	}
	return l.srv.Shutdown(ctx)
}
