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

package dadl

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"
)

// APIError is the structured error a failed REST call produces (DADL spec
// §8.2): a stable semantic code for branching, the raw HTTP status, the
// extracted message, and the API's own error code when errors.code_path
// names one.
type APIError struct {
	// Code is the semantic error code from errors.map, falling back to the
	// spec §8.2 default mapping. Never empty.
	Code string
	// HTTPStatus is the raw HTTP status code.
	HTTPStatus int
	// Message is the human-readable message extracted via errors.message_path.
	Message string
	// ProviderCode is the API's own error code extracted via errors.code_path
	// (e.g. Stripe's "resource_missing"). Empty when undeclared or absent.
	ProviderCode string
}

// Error renders the stable text form: "[<code>] HTTP <status>: <message>",
// with the provider code appended when present.
func (e *APIError) Error() string {
	if e.ProviderCode != "" {
		return fmt.Sprintf("[%s] HTTP %d: %s (provider_code=%s)", e.Code, e.HTTPStatus, e.Message, e.ProviderCode)
	}
	return fmt.Sprintf("[%s] HTTP %d: %s", e.Code, e.HTTPStatus, e.Message)
}

// Well-known semantic error codes (DADL spec §8.2). errors.map values are
// opaque strings and may go beyond this set; these are the defaults every
// non-2xx status resolves to.
const (
	ErrCodeInvalidInput     = "invalid_input"
	ErrCodeUnauthorized     = "unauthorized"
	ErrCodeForbidden        = "forbidden"
	ErrCodeNotFound         = "not_found"
	ErrCodeConflict         = "conflict"
	ErrCodeTimeout          = "timeout"
	ErrCodeRateLimited      = "rate_limited"
	ErrCodeInternal         = "internal"
	ErrCodeUnavailable      = "unavailable"
	ErrCodeClientError      = "client_error"
	ErrCodeServerError      = "server_error"
	ErrCodeUnexpectedStatus = "unexpected_status"
)

// DefaultSemanticCode returns the spec §8.2 well-known semantic code for an
// HTTP status. The catch-alls client_error / server_error / unexpected_status
// guarantee every non-2xx status maps to some code.
func DefaultSemanticCode(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return ErrCodeInvalidInput
	case http.StatusUnauthorized:
		return ErrCodeUnauthorized
	case http.StatusForbidden:
		return ErrCodeForbidden
	case http.StatusNotFound, http.StatusGone:
		return ErrCodeNotFound
	case http.StatusConflict:
		return ErrCodeConflict
	case http.StatusRequestTimeout:
		return ErrCodeTimeout
	case http.StatusTooManyRequests:
		return ErrCodeRateLimited
	case http.StatusInternalServerError:
		return ErrCodeInternal
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return ErrCodeUnavailable
	}
	switch {
	case status >= 400 && status < 500:
		return ErrCodeClientError
	case status >= 500 && status < 600:
		return ErrCodeServerError
	default:
		return ErrCodeUnexpectedStatus
	}
}

// ErrorMapper checks HTTP responses against error configuration and extracts error messages.
type ErrorMapper struct {
	config ErrorConfig
}

// NewErrorMapper creates an ErrorMapper from an ErrorConfig.
func NewErrorMapper(config ErrorConfig) *ErrorMapper {
	return &ErrorMapper{config: config}
}

// semanticCode resolves the §8.2 semantic code for a status: errors.map
// wins, the well-known default mapping fills the rest.
func (m *ErrorMapper) semanticCode(statusCode int) string {
	if code, ok := m.config.Map[statusCode]; ok {
		return code
	}
	return DefaultSemanticCode(statusCode)
}

// CheckResponse examines the HTTP status code and returns:
// - (nil, false) if the response is successful
// - (*APIError, true) if the error is retryable (status in retry_on)
// - (*APIError, false) if the error is terminal (status in terminal, or default for 4xx)
func (m *ErrorMapper) CheckResponse(statusCode int, body []byte) (err error, retryable bool) {
	if statusCode >= 200 && statusCode < 300 {
		return nil, false
	}

	apiErr := &APIError{
		Code:         m.semanticCode(statusCode),
		HTTPStatus:   statusCode,
		Message:      m.extractMessage(body),
		ProviderCode: m.extractProviderCode(body),
	}

	// Check retryable
	for _, code := range m.config.RetryOn {
		if statusCode == code {
			return apiErr, true
		}
	}

	// Check terminal
	for _, code := range m.config.Terminal {
		if statusCode == code {
			return apiErr, false
		}
	}

	// Default: 4xx = terminal, 5xx = retryable
	return apiErr, statusCode >= 500 || statusCode < 400
}

// maxErrorMessageLen is the maximum length of error messages passed to clients (M-16).
const maxErrorMessageLen = 1024

func (m *ErrorMapper) extractMessage(body []byte) string {
	if len(body) == 0 || m.config.MessagePath == "" {
		return "(no message)"
	}
	val, ok := extractPathValue(body, m.config.MessagePath)
	if !ok {
		return truncateMessage(string(body))
	}
	return truncateMessage(fmt.Sprintf("%v", val))
}

// extractProviderCode pulls the API's own error code via errors.code_path
// (spec §8.2). Absent path or non-matching data yields "".
func (m *ErrorMapper) extractProviderCode(body []byte) string {
	if len(body) == 0 || m.config.CodePath == "" {
		return ""
	}
	val, ok := extractPathValue(body, m.config.CodePath)
	if !ok || val == nil {
		return ""
	}
	return truncateMessage(fmt.Sprintf("%v", val))
}

// extractPathValue applies a JSONPath to a JSON body, reporting ok=false
// when the path does not parse, the body is not JSON, or nothing matches.
func extractPathValue(body []byte, path string) (any, bool) {
	jp, err := NewJSONPath(path)
	if err != nil {
		return nil, false
	}
	var data any
	if err := jsonUnmarshal(body, &data); err != nil {
		return nil, false
	}
	val, err := jp.Extract(data)
	if err != nil {
		return nil, false
	}
	return val, true
}

func truncateMessage(s string) string {
	if len(s) > maxErrorMessageLen {
		return s[:maxErrorMessageLen] + "... (truncated)"
	}
	return s
}

// Retryer executes HTTP requests with retry logic.
type Retryer struct {
	strategy RetryStrategyConfig
	logger   *slog.Logger
}

// NewRetryer creates a Retryer from a RetryStrategyConfig.
func NewRetryer(strategy RetryStrategyConfig, logger *slog.Logger) *Retryer {
	return &Retryer{strategy: strategy, logger: logger}
}

// Do executes fn with retries on retryable errors. Respects max_retries and backoff.
func (r *Retryer) Do(ctx context.Context, fn func() (*http.Response, error)) (*http.Response, error) {
	maxRetries := r.strategy.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	initialDelay := parseDelayOrDefault(r.strategy.InitialDelay, time.Second)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := r.calcDelay(attempt, initialDelay)
			r.logger.Info("retrying request", "attempt", attempt, "delay", delay)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		resp, err := fn()
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, lastErr)
}

// Retry backoff strategy values used in DADL error_handling specs.
const (
	backoffExponential = "exponential"
	backoffLinear      = "linear"
	backoffFixed       = "fixed"
)

func (r *Retryer) calcDelay(attempt int, initial time.Duration) time.Duration {
	switch r.strategy.Backoff {
	case backoffExponential:
		return initial * time.Duration(math.Pow(2, float64(attempt-1)))
	case backoffLinear:
		return initial * time.Duration(attempt)
	case backoffFixed:
		return initial
	default:
		return initial * time.Duration(math.Pow(2, float64(attempt-1)))
	}
}

func parseDelayOrDefault(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
