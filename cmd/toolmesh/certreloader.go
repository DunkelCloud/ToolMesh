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
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// The listeners that serve a certificate from files, as the messages of
// certReloader name them.
const (
	certOfMainListener    = "main listener"
	certOfCredentialsPage = "credentials page"
)

// certReloadInterval is how often the certificate files are looked at.
const certReloadInterval = time.Minute

// certReloader serves the certificate in two PEM files and reads the files
// again once they changed, so that a renewed certificate is used without a
// restart.
type certReloader struct {
	what              string // the listener the certificate is for, for messages
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

// newCertReloader loads the certificate of the listener named by what;
// files that do not hold a certificate and its key are an error.
func newCertReloader(what, certFile, keyFile string, logger *slog.Logger) (*certReloader, error) {
	c := &certReloader{what: what, certFile: certFile, keyFile: keyFile, logger: logger, now: time.Now}
	stamp, err := c.stamps()
	if err != nil {
		return nil, fmt.Errorf("certificate of the %s: %w", what, err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("certificate of the %s: %w", what, err)
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

// certificate is the tls.Config.GetCertificate of the listener. When the
// files changed it loads them; files that cannot be loaded, as in the
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
			c.logger.Warn("certificate files cannot be read, keeping the certificate in use", "listener", c.what, "error", err)
		case stamp != c.stamp:
			cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
			if err != nil {
				c.logger.Warn("changed certificate files do not load, keeping the certificate in use", "listener", c.what, "error", err)
				break
			}
			c.cert, c.stamp = &cert, stamp
			c.logger.Info("certificate reloaded", "listener", c.what)
		}
	}
	return c.cert, nil
}
