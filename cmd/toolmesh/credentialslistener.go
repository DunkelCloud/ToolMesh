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
	"log"
	"log/slog"
	"net"
	"net/http"
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
		certs, err := newCertReloader(certOfCredentialsPage, cfg.CredentialsTLSCert, cfg.CredentialsTLSKey, logger)
		if err != nil {
			return nil, err
		}
		l.srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.certificate}
		l.srv.ErrorLog = log.New(serverLogWriter{logger: logger}, "", 0)
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
