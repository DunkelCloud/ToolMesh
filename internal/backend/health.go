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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Transport failure codes of a health result (DADL spec §4.6 error_code):
// set when no HTTP response was received.
const (
	HealthErrDNS               = "dns_error"
	HealthErrTLS               = "tls_error"
	HealthErrConnectionRefused = "connection_refused"
	HealthErrTimeout           = "timeout"
	HealthErrProtocol          = "protocol_error"
)

// maxHealthBodyBytes caps how much of a check response is read. A check
// should hit the cheapest endpoint an API has; the cap only bounds a badly
// chosen one, and expect_path / auth_expires_path see at most this much.
const maxHealthBodyBytes = 1 << 20

// maxHealthMessageLen caps the provider message carried in a health error.
const maxHealthMessageLen = 200

// HealthResult is the standardized outcome of a backend health check (DADL
// spec §4.6). It is produced by the check layer, never copied from the API:
// the raw response body does not appear in it.
type HealthResult struct {
	// OK reports whether the check passed its status and expect_path rules.
	OK bool
	// HTTPStatus is the raw response status; 0 when no response arrived.
	HTTPStatus int
	// ErrorCode names the transport failure when no response arrived.
	ErrorCode string
	// Latency is the wall time of the check, re-authentication included.
	Latency time.Duration
	// CheckedAt is when the check started.
	CheckedAt time.Time
	// AuthExpiresAt is when the backend credential expires, from the check
	// response or the operator's backends.yaml; zero when unknown.
	AuthExpiresAt time.Time
	// Error describes the failure when OK is false: the spec §8.2 semantic
	// code with status and provider message for HTTP errors.
	Error string
	// Reason is a short summary of a failure — semantic code and status,
	// transport error code, or the missed expectation. It never carries
	// response content, so it is safe for logs and unauthenticated status
	// endpoints. Empty when OK is true.
	Reason string
}

// healthResultWire is the spec §4.6 wire shape of a HealthResult.
type healthResultWire struct {
	OK            bool   `json:"ok"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	LatencyMS     int64  `json:"latency_ms"`
	CheckedAt     string `json:"checked_at"`
	AuthExpiresAt string `json:"auth_expires_at,omitempty"`
	Error         string `json:"error,omitempty"`
}

// MarshalJSON renders the spec §4.6 result shape.
func (r HealthResult) MarshalJSON() ([]byte, error) {
	w := healthResultWire{
		OK:         r.OK,
		HTTPStatus: r.HTTPStatus,
		ErrorCode:  r.ErrorCode,
		LatencyMS:  r.Latency.Milliseconds(),
		CheckedAt:  r.CheckedAt.UTC().Format(time.RFC3339),
		Error:      r.Error,
	}
	if !r.AuthExpiresAt.IsZero() {
		w.AuthExpiresAt = r.AuthExpiresAt.UTC().Format(time.RFC3339)
	}
	return json.Marshal(w)
}

// HealthChecker is implemented by backends that can run a DADL-declared
// health check (spec §4.6).
type HealthChecker interface {
	// HasHealthCheck reports whether the backend declares a check.
	HasHealthCheck() bool
	// CheckHealth runs the check once. It never fails: every outcome,
	// transport failures included, is reported in the result.
	CheckHealth(ctx context.Context) HealthResult
}

// HealthObserver receives the result of a check that ran on demand through
// the synthetic health tool, so monitoring sees it as well. backendName is
// the backend's configured name.
type HealthObserver func(backendName string, result HealthResult)

// HasHealthCheck reports whether the backend's DADL declares a health check.
func (a *RESTAdapter) HasHealthCheck() bool {
	return a.spec.Backend.Health != nil
}

// SetHealthObserver installs the receiver of on-demand check results; nil
// removes it. Safe to call while the adapter serves calls.
func (a *RESTAdapter) SetHealthObserver(o HealthObserver) {
	if o == nil {
		a.healthObserver.Store(nil)
		return
	}
	a.healthObserver.Store(&o)
}

// CheckHealth runs the declared health check once (spec §4.6). Auth is
// injected exactly as for a regular call, so a pass verifies reachability
// and the credential in one request. A 401 gets the same single
// re-authentication a regular call gets, for credentials that can be
// renewed. expect_path and auth_expires_path see the raw response body; a
// referenced tool's response pipeline does not apply.
func (a *RESTAdapter) CheckHealth(ctx context.Context) HealthResult {
	start := time.Now()
	res := HealthResult{CheckedAt: start.UTC()}
	tool, ok := a.spec.Backend.HealthToolDef()
	if !ok {
		res.ErrorCode = HealthErrProtocol
		res.Error = "the backend declares no health check"
		res.Reason = res.Error
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, a.spec.Backend.Health.CheckTimeout())
	defer cancel()

	at := a.healthAttempt(ctx, &tool)
	if at.err == nil && at.status == http.StatusUnauthorized && a.auth.CanReauthenticate() {
		if err := a.auth.HandleUnauthorized(ctx); err == nil {
			at = a.healthAttempt(ctx, &tool)
		}
	}
	res.Latency = time.Since(start)

	if at.err != nil {
		res.ErrorCode = classifyTransportError(at.err)
		if at.setup {
			res.Error = "request could not be prepared: " + transportErrorMessage(at.err)
			res.Reason = fmt.Sprintf("request setup failed (%s)", res.ErrorCode)
		} else {
			res.Error = transportErrorMessage(at.err)
			res.Reason = fmt.Sprintf("no response (%s)", res.ErrorCode)
		}
	} else {
		res.HTTPStatus = at.status
		a.evaluateHealth(&res, &tool, at)
	}
	if res.AuthExpiresAt.IsZero() {
		res.AuthExpiresAt = a.authExpiresAt
	}
	return res
}

// healthAttempt is one HTTP exchange of a health check.
type healthAttempt struct {
	status    int
	body      []byte
	truncated bool
	err       error
	// setup marks an error raised while building the request, auth
	// injection included — before anything was sent.
	setup bool
}

// healthAttempt sends the check request once and reads at most
// maxHealthBodyBytes of the response.
func (a *RESTAdapter) healthAttempt(ctx context.Context, tool *dadl.ToolDef) healthAttempt {
	req, err := a.buildHTTPRequest(ctx, tool, map[string]any{})
	if err != nil {
		return healthAttempt{err: err, setup: true}
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return healthAttempt{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthBodyBytes+1))
	if err != nil {
		return healthAttempt{err: fmt.Errorf("read response: %w", err)}
	}
	at := healthAttempt{status: resp.StatusCode, body: body}
	if len(body) > maxHealthBodyBytes {
		at.body, at.truncated = body[:maxHealthBodyBytes], true
	}
	return at
}

// evaluateHealth applies the status and expect_path rules to a received
// response and extracts auth_expires_path.
func (a *RESTAdapter) evaluateHealth(res *HealthResult, tool *dadl.ToolDef, at healthAttempt) {
	h := a.spec.Backend.Health
	passed := at.status >= 200 && at.status < 300
	if h.ExpectStatus != 0 {
		passed = at.status == h.ExpectStatus
	}

	switch {
	case !passed:
		res.Error, res.Reason = a.healthStatusError(tool, at, h.ExpectStatus)
	case h.ExpectPath != "":
		if _, ok := dadl.JSONPathValue(at.body, h.ExpectPath); !ok {
			passed = false
			res.Error = fmt.Sprintf("the response has no value at %s (expect_path)", h.ExpectPath)
			if at.truncated {
				res.Error += fmt.Sprintf("; only the first %d bytes were read", maxHealthBodyBytes)
			}
			res.Reason = fmt.Sprintf("expect_path %s missing (HTTP %d)", h.ExpectPath, at.status)
		}
	}
	res.OK = passed

	if h.AuthExpiresPath != "" {
		if v, ok := dadl.JSONPathValue(at.body, h.AuthExpiresPath); ok {
			if t, ok := dadl.ParseExpiry(v); ok {
				res.AuthExpiresAt = t
			}
		}
	}
}

// healthStatusError describes a status that did not pass, mapped per spec
// §8.2: the semantic code from the tool's (or the backend's default)
// errors block, the status, and the provider message only when
// errors.message_path finds one — the raw body never becomes the message.
func (a *RESTAdapter) healthStatusError(tool *dadl.ToolDef, at healthAttempt, expect int) (detail, reason string) {
	cfg := dadl.ErrorConfig{}
	if ec := a.effectiveErrorConfig(tool); ec != nil {
		cfg = *ec
	}
	code := dadl.ErrCodeUnexpectedStatus
	providerCode := ""
	if err, _ := dadl.NewErrorMapper(cfg).CheckResponse(at.status, at.body); err != nil {
		var apiErr *dadl.APIError
		if errors.As(err, &apiErr) {
			code, providerCode = apiErr.Code, apiErr.ProviderCode
		}
	}

	detail = fmt.Sprintf("[%s] HTTP %d", code, at.status)
	if cfg.MessagePath != "" {
		if v, ok := dadl.JSONPathValue(at.body, cfg.MessagePath); ok && v != nil {
			msg := fmt.Sprintf("%v", v)
			if len(msg) > maxHealthMessageLen {
				msg = msg[:maxHealthMessageLen] + "..."
			}
			detail += ": " + msg
		}
	}
	if providerCode != "" {
		detail += fmt.Sprintf(" (provider_code=%s)", providerCode)
	}
	if expect != 0 {
		detail += fmt.Sprintf("; expected HTTP %d", expect)
	}
	return detail, fmt.Sprintf("%s (HTTP %d)", code, at.status)
}

// classifyTransportError maps an error that left no HTTP response to the
// spec §4.6 error_code values.
func classifyTransportError(err error) string {
	var (
		dnsErr      *net.DNSError
		verifyErr   *tls.CertificateVerificationError
		authorityEr x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		invalidErr  x509.CertificateInvalidError
		recordErr   tls.RecordHeaderError
		alertErr    tls.AlertError
		netErr      net.Error
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return HealthErrTimeout
	case errors.As(err, &dnsErr):
		return HealthErrDNS
	case errors.As(err, &verifyErr), errors.As(err, &authorityEr), errors.As(err, &hostnameErr),
		errors.As(err, &invalidErr), errors.As(err, &recordErr), errors.As(err, &alertErr):
		return HealthErrTLS
	case isConnectionRefused(err):
		return HealthErrConnectionRefused
	case errors.As(err, &netErr) && netErr.Timeout():
		return HealthErrTimeout
	}
	return HealthErrProtocol
}

// wsaeConnRefused is the Windows socket error for a refused connection,
// which syscall.ECONNREFUSED does not match there.
const wsaeConnRefused = syscall.Errno(10061)

// isConnectionRefused reports a refused TCP connection on any platform.
func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeConnRefused)
}

// transportErrorMessage renders a transport error without the request URL:
// with auth.inject_into: query the URL carries the credential.
func transportErrorMessage(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	return strings.TrimSpace(err.Error())
}

// healthToolDescriptor describes the synthetic health tool (spec §4.6).
// It is classified read — the check is side-effect-free by rule — and kept
// out of ranked discovery.
func (a *RESTAdapter) healthToolDescriptor() ToolDescriptor {
	return ToolDescriptor{
		Name:        dadl.HealthToolName,
		Description: dadl.HealthToolDescription + " Returns: " + dadl.HealthResultTS,
		InputSchema: map[string]any{
			schemaKeyType:                 schemaTypeObject,
			schemaKeyProperties:           map[string]any{},
			schemaKeyAdditionalProperties: false,
		},
		Backend:  "rest:" + a.spec.Backend.Name,
		Access:   accessRead,
		Unranked: true,
	}
}

// executeHealthTool serves a call to the synthetic health tool: it runs the
// check, hands the result to the observer, and returns the standardized
// result as the tool result. A failed check is a successful call — the
// script branches on ok, not on an error (spec §4.6).
func (a *RESTAdapter) executeHealthTool(ctx context.Context, params map[string]any) (*ToolResult, error) {
	if err := dadl.ValidateParams(dadl.HealthToolName, nil, params); err != nil {
		return a.paramErrorResult(ctx, dadl.HealthToolName, err), nil
	}
	res := a.CheckHealth(ctx)
	if o := a.healthObserver.Load(); o != nil {
		(*o)(a.spec.Backend.Name, res)
	}
	payload, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("marshal health result: %w", err)
	}
	meta := map[string]any{
		metadataKeyBackend:   a.spec.Backend.Name,
		metadataKeyTransport: transportTypeREST,
	}
	if res.HTTPStatus != 0 {
		meta[metadataKeyStatusCode] = res.HTTPStatus
	}
	return &ToolResult{
		Content:  []any{textContent(string(payload))},
		Metadata: meta,
	}, nil
}
