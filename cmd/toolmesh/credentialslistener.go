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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/enroll"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
)

// credentialsListener is where the credentials page is served: on the main
// listener, or on a listener of its own.
type credentialsListener struct {
	srv   *http.Server // nil when the page is on the main listener
	addr  string
	https bool
}

// serveCredentialsPage puts the credentials page where the configuration
// wants it. Without TOOLMESH_CREDENTIALS_BIND that is the main listener:
// the page is mounted on mainMux. With it the page gets a listener of its
// own, which is started here, and the main listener does not serve the page
// at all. A password typed into the page then never passes whatever stands
// in front of the main listener.
func serveCredentialsPage(ctx context.Context, cfg *config.Config, mainMux *http.ServeMux, page http.Handler, logger *slog.Logger) (*credentialsListener, error) {
	if cfg.CredentialsBind == "" {
		mainMux.Handle(enroll.Path, page)
		mainMux.Handle(enroll.Path+"/", page)
		return &credentialsListener{}, nil
	}

	mux := http.NewServeMux()
	mux.Handle(enroll.Path, page)
	mux.Handle(enroll.Path+"/", page)
	// The listener has nothing but the page, so its root leads there.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, enroll.Path, http.StatusSeeOther)
	})
	l := &credentialsListener{
		srv: &http.Server{
			Handler:     mcp.PanicRecovery(logger)(mcp.SecurityHeaders(mcp.RequestLogging(logger)(mux))),
			ReadTimeout: 30 * time.Second,
			// Storing an account includes a check against the backend's API.
			WriteTimeout: 120 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
	if cfg.CredentialsTLSCert != "" {
		certs, err := newCertReloader(cfg.CredentialsTLSCert, cfg.CredentialsTLSKey, logger)
		if err != nil {
			return nil, err
		}
		l.srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.certificate}
		l.https = true
	}

	// Listening happens here, not in the goroutine: an address that cannot
	// be bound stops the start instead of leaving ToolMesh without the page
	// its messages send users to.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.CredentialsBind)
	if err != nil {
		return nil, fmt.Errorf("TOOLMESH_CREDENTIALS_BIND: %w", err)
	}
	l.addr = ln.Addr().String()
	go func() {
		var err error
		if l.https {
			err = l.srv.ServeTLS(ln, "", "")
		} else {
			err = l.srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("credentials page listener error", "error", err)
		}
	}()
	return l, nil
}

// describe says where the page is served, for the log.
func (l *credentialsListener) describe() string {
	switch {
	case l == nil || l.srv == nil:
		return "main"
	case l.https:
		return l.addr + " (https)"
	default:
		return l.addr + " (http)"
	}
}

// shutdown stops the page's own listener; it does nothing when the page is
// on the main listener or does not exist.
func (l *credentialsListener) shutdown(ctx context.Context) error {
	if l == nil || l.srv == nil {
		return nil
	}
	return l.srv.Shutdown(ctx)
}

// certReloadInterval is how often the certificate files are looked at.
const certReloadInterval = time.Minute

// certReloader serves the certificate in two PEM files and reads the files
// again once they changed, so that a renewed certificate is used without a
// restart.
type certReloader struct {
	certFile, keyFile string
	logger            *slog.Logger
	now               func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	stamp   [2]fileStamp
	checked time.Time
}

// fileStamp tells one state of a file from the next.
type fileStamp struct {
	modTime time.Time
	size    int64
}

// newCertReloader loads the certificate; files that do not hold a
// certificate and its key are an error.
func newCertReloader(certFile, keyFile string, logger *slog.Logger) (*certReloader, error) {
	c := &certReloader{certFile: certFile, keyFile: keyFile, logger: logger, now: time.Now}
	stamp, err := c.stamps()
	if err != nil {
		return nil, fmt.Errorf("certificate of the credentials page: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("certificate of the credentials page: %w", err)
	}
	c.cert, c.stamp, c.checked = &cert, stamp, c.now()
	return c, nil
}

// stamps returns the state of both files.
func (c *certReloader) stamps() ([2]fileStamp, error) {
	var out [2]fileStamp
	for i, name := range []string{c.certFile, c.keyFile} {
		info, err := os.Stat(name)
		if err != nil {
			return out, err
		}
		out[i] = fileStamp{modTime: info.ModTime(), size: info.Size()}
	}
	return out, nil
}

// certificate is the tls.Config.GetCertificate of the page's listener. When
// the files changed it loads them; files that cannot be loaded, as in the
// middle of a renewal, leave the certificate in use and are tried again at
// the next look.
func (c *certReloader) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); now.Sub(c.checked) >= certReloadInterval {
		c.checked = now
		stamp, err := c.stamps()
		switch {
		case err != nil:
			c.logger.Warn("certificate of the credentials page: the files cannot be read, keeping the one in use", "error", err)
		case stamp != c.stamp:
			cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
			if err != nil {
				c.logger.Warn("certificate of the credentials page: the changed files do not load, keeping the one in use", "error", err)
				break
			}
			c.cert, c.stamp = &cert, stamp
			c.logger.Info("certificate of the credentials page reloaded")
		}
	}
	return c.cert, nil
}
