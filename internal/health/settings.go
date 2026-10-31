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

// Package health monitors the health checks DADL backends declare (DADL
// spec §4.6) and folds their results into ToolMesh's own status: a check at
// startup, polling, a degraded state after consecutive failures and a
// warning state before a known credential expiry.
package health

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// DefaultInterval is how often a declared check is polled unless
// health_check.interval says otherwise. The check exists to report a broken
// credential before an agent needs the backend, not at the next restart.
const DefaultInterval = 15 * time.Minute

// DefaultWarnBefore is the window before a known credential expiry in which
// a backend is reported with a warning, unless warn_before says otherwise.
const DefaultWarnBefore = 7 * 24 * time.Hour

// MinInterval is the shortest polling interval health_check.interval
// accepts. Checks are real API calls, often rate-limited or metered.
const MinInterval = 30 * time.Second

// Policy is how the monitor treats one backend's check results.
type Policy struct {
	// Interval polls the check periodically; 0 means no polling — the
	// check runs at startup, after a reload and when the health tool is
	// called.
	Interval time.Duration
	// DegradeAfter is the number of consecutive failures after which the
	// backend counts as degraded. Values below 1 mean 1.
	DegradeAfter int
	// WarnBefore is the warning window before a known credential expiry.
	WarnBefore time.Duration
}

// degradeAfter returns DegradeAfter with its floor of 1 applied.
func (p Policy) degradeAfter() int {
	if p.DegradeAfter < 1 {
		return 1
	}
	return p.DegradeAfter
}

// Settings are the parsed backends.yaml health_check block of one backend.
type Settings struct {
	// Enabled is false when the operator turned monitoring off.
	Enabled bool
	// Policy drives polling and the degraded / warning states.
	Policy Policy
	// AuthExpiresAt is the operator-recorded credential expiry; zero when
	// none is configured.
	AuthExpiresAt time.Time
}

// ParseSettings reads a health_check block; nil yields the defaults: on,
// polling every DefaultInterval, degraded after one failure, warning seven
// days before a known expiry. An interval of 0 turns polling off. A
// malformed field falls back to its default and is reported in the
// returned error, so a typo costs the setting, not the backend.
func ParseSettings(c *backend.HealthCheckConfig) (Settings, error) {
	s := Settings{
		Enabled: true,
		Policy:  Policy{Interval: DefaultInterval, DegradeAfter: 1, WarnBefore: DefaultWarnBefore},
	}
	if c == nil {
		return s, nil
	}
	if c.Enabled != nil {
		s.Enabled = *c.Enabled
	}

	var errs []error
	if c.Interval != "" {
		d, err := ParseDuration(c.Interval)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("interval: %w", err))
		case d == 0:
			s.Policy.Interval = 0
		case d < MinInterval:
			errs = append(errs, fmt.Errorf("interval %q is shorter than the minimum %s; polling every %s instead", c.Interval, MinInterval, DefaultInterval))
		default:
			s.Policy.Interval = d
		}
	}
	switch {
	case c.DegradeAfter < 0:
		errs = append(errs, fmt.Errorf("degrade_after must not be negative, got %d", c.DegradeAfter))
	case c.DegradeAfter > 0:
		s.Policy.DegradeAfter = c.DegradeAfter
	}
	if c.WarnBefore != "" {
		d, err := ParseDuration(c.WarnBefore)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("warn_before: %w", err))
		case d < 0:
			errs = append(errs, fmt.Errorf("warn_before must not be negative, got %q", c.WarnBefore))
		default:
			s.Policy.WarnBefore = d
		}
	}
	if c.AuthExpiresAt != "" {
		t, ok := dadl.ParseExpiry(c.AuthExpiresAt)
		if !ok {
			errs = append(errs, fmt.Errorf("auth_expires_at %q is neither an ISO 8601 date or timestamp nor Unix epoch seconds", c.AuthExpiresAt))
		} else {
			s.AuthExpiresAt = t
		}
	}
	return s, errors.Join(errs...)
}

// ParseDuration parses a Go duration ("15m", "1h30m") or a number of days
// with the suffix d ("7d", "1.5d"), the unit expiry windows are thought in.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration (e.g. \"15m\", \"12h\", \"7d\")", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (e.g. \"15m\", \"12h\", \"7d\")", s)
	}
	return d, nil
}
