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

package health

import (
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "15m", want: 15 * time.Minute},
		{in: "1h30m", want: 90 * time.Minute},
		{in: "7d", want: 7 * 24 * time.Hour},
		{in: "1.5d", want: 36 * time.Hour},
		{in: " 2d ", want: 48 * time.Hour},
		{in: "d", wantErr: true},
		{in: "7 days", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseDuration(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseDuration(%q) = %s, %v; want %s, error %v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestParseSettings(t *testing.T) {
	off := false
	defaults := Settings{Enabled: true, Policy: Policy{DegradeAfter: 1, WarnBefore: DefaultWarnBefore}}

	t.Run("nil block yields the defaults", func(t *testing.T) {
		got, err := ParseSettings(nil)
		if err != nil || got != defaults {
			t.Errorf("ParseSettings(nil) = %+v, %v; want %+v", got, err, defaults)
		}
	})

	t.Run("every field", func(t *testing.T) {
		got, err := ParseSettings(&backend.HealthCheckConfig{
			Enabled:       &off,
			Interval:      "15m",
			DegradeAfter:  2,
			WarnBefore:    "14d",
			AuthExpiresAt: "2026-10-16",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := Settings{
			Enabled:       false,
			Policy:        Policy{Interval: 15 * time.Minute, DegradeAfter: 2, WarnBefore: 14 * 24 * time.Hour},
			AuthExpiresAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC),
		}
		if got != want {
			t.Errorf("ParseSettings = %+v, want %+v", got, want)
		}
	})

	t.Run("malformed fields fall back and are reported", func(t *testing.T) {
		got, err := ParseSettings(&backend.HealthCheckConfig{
			Interval:      "5s",
			DegradeAfter:  -1,
			WarnBefore:    "a week",
			AuthExpiresAt: "someday",
		})
		if got != defaults {
			t.Errorf("ParseSettings = %+v, want the defaults %+v", got, defaults)
		}
		if err == nil {
			t.Fatal("want an error naming the malformed fields")
		}
		for _, want := range []string{"shorter than the minimum", "degrade_after", "warn_before", "auth_expires_at"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})
}

// Unquoted YAML dates are resolved as timestamps; the strict backends.yaml
// decoder must still hand them to the string field as written.
func TestHealthCheckConfig_YAMLDate(t *testing.T) {
	doc := []byte(`backends:
  - name: tailscale
    transport: rest
    dadl: tailscale.dadl
    health_check:
      interval: 15m
      degrade_after: 2
      warn_before: 7d
      auth_expires_at: 2026-10-16
`)
	var cfg backend.BackendConfig
	if err := backend.UnmarshalBackendConfig(doc, &cfg); err != nil {
		t.Fatalf("strict decode rejected health_check: %v", err)
	}
	hc := cfg.Backends[0].HealthCheck
	if hc == nil || hc.AuthExpiresAt != "2026-10-16" || hc.DegradeAfter != 2 {
		t.Fatalf("health_check = %+v", hc)
	}
	s, err := ParseSettings(hc)
	if err != nil || !s.AuthExpiresAt.Equal(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("ParseSettings = %+v, %v", s, err)
	}

	typo := []byte("backends:\n  - name: x\n    transport: rest\n    health_check:\n      intervall: 15m\n")
	if err := backend.UnmarshalBackendConfig(typo, &cfg); err == nil {
		t.Error("a misspelled health_check key must fail the strict decode")
	}
}
