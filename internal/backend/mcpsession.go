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
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// One connection to a backend has one context, its scope: the attempt to
// connect runs under it, and so does what the connection keeps open
// afterwards. The transports of the SDK do not agree on this. One ties the
// stream it keeps open to the context of the connect, so a connect that is
// given a deadline ends its own stream when it returns. Another detaches
// its stream from that context, and sends the subscription of the stateless
// revision under no context at all, so neither a deadline nor Close reaches
// a request that a backend leaves unanswered. The scope is given to the
// connect and laid over every HTTP request (sessionTransport), which makes
// both behave alike:
//
//   - while the connection is made, the scope ends with the caller's
//     context, with the timeout of the attempt and when Close begins;
//   - once it is made, the scope ends with the session, or when Close stops
//     waiting for what is still running.

// mcpMethodHeader names the method of a request of the stateless revision,
// and mcpMethodListen the request a client opens its stream of notifications
// with.
const (
	mcpMethodHeader = "Mcp-Method"
	mcpMethodListen = "subscriptions/listen"
)

// sessionScope is the context of one connection to a backend.
type sessionScope struct {
	ctx    context.Context
	cancel context.CancelFunc
	// timedOut says that the timeout of the attempt ended the scope.
	timedOut atomic.Bool
	// settle ends the attempt: the scope of a connection that was made
	// lives on, that of one that was not ends.
	settle func(connected bool)
}

// newSessionScope starts the scope of an attempt to connect.
func (a *MCPAdapter) newSessionScope(caller context.Context, timeout time.Duration) *sessionScope {
	s := &sessionScope{}
	s.ctx, s.cancel = context.WithCancel(a.untilStopped())
	timer := time.AfterFunc(timeout, func() {
		s.timedOut.Store(true)
		s.cancel()
	})
	stopCaller := context.AfterFunc(caller, s.cancel)
	stopLife := context.AfterFunc(a.lifetime(), s.cancel)
	s.settle = func(connected bool) {
		timer.Stop()
		stopCaller()
		stopLife()
		if !connected {
			s.cancel()
		}
	}
	return s
}

// transportSetupError is the error of a transport that could not be built,
// as opposed to a backend that could not be reached with it: no second
// attempt changes it.
type transportSetupError struct{ err error }

func (e *transportSetupError) Error() string { return "create transport: " + e.err.Error() }

func (e *transportSetupError) Unwrap() error { return e.err }

// connectOnce makes one attempt to connect to a backend and gives up after
// timeout. It returns the session and the function that releases the scope
// of the session, to be called once the session has ended.
func (a *MCPAdapter) connectOnce(ctx context.Context, client *mcp.Client, entry BackendEntry, timeout time.Duration, opts *mcp.ClientSessionOptions) (*mcp.ClientSession, context.CancelFunc, error) {
	scope := a.newSessionScope(ctx, timeout)
	transport, err := a.createTransport(scope.ctx, entry)
	if err != nil {
		scope.settle(false)
		return nil, nil, &transportSetupError{err: err}
	}

	session, err := client.Connect(scope.ctx, transport, opts)
	if err == nil && scope.ctx.Err() != nil {
		// Given up in the moment the connection was made.
		_ = session.Close()
		err = scope.ctx.Err()
	}
	scope.settle(err == nil)
	if err != nil {
		if scope.timedOut.Load() {
			return nil, nil, fmt.Errorf("no connection within %s: %w", timeout, err)
		}
		return nil, nil, err
	}
	return session, scope.cancel, nil
}

// sessionTransport sends the HTTP requests of one connection to a backend.
// Every request ends with the scope of the connection, whatever context the
// SDK sends it under.
//
// A request is also bounded by timeout, the setting TOOLMESH_MCP_TIMEOUT,
// from the moment it is sent until its answer has been read. The streams a
// server sends its notifications on are not: they are meant to stay open.
// The timeout of an http.Client bounds every request alike, which ended
// these streams after that time, and with them, for a server that keeps
// sessions, in the end the session.
type sessionTransport struct {
	base    http.RoundTripper
	scope   context.Context
	timeout time.Duration
}

// RoundTrip implements http.RoundTripper.
func (t *sessionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if t.timeout > 0 && !isNotificationStream(req) {
		ctx, cancel = context.WithTimeout(req.Context(), t.timeout)
	} else {
		ctx, cancel = context.WithCancel(req.Context())
	}
	stop := context.AfterFunc(t.scope, cancel)
	release := func() {
		stop()
		cancel()
	}

	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		release()
		return nil, err
	}
	// The request lasts until its answer has been read: reading the body is
	// part of it, and of what the timeout bounds.
	resp.Body = &releasingBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// isNotificationStream reports whether a request opens a stream a server
// sends notifications on: the GET of a server that keeps sessions (and of
// the HTTP+SSE transport), or the subscription of the stateless revision.
func isNotificationStream(req *http.Request) bool {
	return req.Method == http.MethodGet || req.Header.Get(mcpMethodHeader) == mcpMethodListen
}

// releasingBody is a response body that releases what its request holds
// when it is closed.
type releasingBody struct {
	io.ReadCloser
	release func()
}

// Close implements io.Closer.
func (b *releasingBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}
