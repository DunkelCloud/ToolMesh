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

// ErrorMapper checks HTTP responses against error configuration and extracts error messages.
type ErrorMapper struct {
	config ErrorConfig
}

// NewErrorMapper creates an ErrorMapper from an ErrorConfig.
func NewErrorMapper(config ErrorConfig) *ErrorMapper {
	return &ErrorMapper{config: config}
}

// CheckResponse examines the HTTP status code and returns:
// - (nil, false) if the response is successful
// - (error, true) if the error is retryable (status in retry_on)
// - (error, false) if the error is terminal (status in terminal, or default for 4xx)
func (m *ErrorMapper) CheckResponse(statusCode int, body []byte) (err error, retryable bool) {
	if statusCode >= 200 && statusCode < 300 {
		return nil, false
	}

	msg := m.extractMessage(body)

	// Check retryable
	for _, code := range m.config.RetryOn {
		if statusCode == code {
			return fmt.Errorf("HTTP %d: %s", statusCode, msg), true
		}
	}

	// Check terminal
	for _, code := range m.config.Terminal {
		if statusCode == code {
			return fmt.Errorf("HTTP %d: %s", statusCode, msg), false
		}
	}

	// Default: 4xx = terminal, 5xx = retryable
	if statusCode >= 400 && statusCode < 500 {
		return fmt.Errorf("HTTP %d: %s", statusCode, msg), false
	}
	return fmt.Errorf("HTTP %d: %s", statusCode, msg), true
}

func (m *ErrorMapper) extractMessage(body []byte) string {
	if len(body) == 0 || m.config.MessagePath == "" {
		return "(no message)"
	}

	jp, err := NewJSONPath(m.config.MessagePath)
	if err != nil {
		return string(body)
	}

	var data any
	if err := jsonUnmarshal(body, &data); err != nil {
		return string(body)
	}

	val, err := jp.Extract(data)
	if err != nil {
		return string(body)
	}

	return fmt.Sprintf("%v", val)
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

func (r *Retryer) calcDelay(attempt int, initial time.Duration) time.Duration {
	switch r.strategy.Backoff {
	case "exponential":
		return initial * time.Duration(math.Pow(2, float64(attempt-1)))
	case "linear":
		return initial * time.Duration(attempt)
	case "fixed":
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
