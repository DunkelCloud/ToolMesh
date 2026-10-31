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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/health"
)

// testHealthDADL declares an inline health check against a closed local
// port, so a check fails fast without leaving the machine.
const testHealthDADL = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: checked
  type: rest
  base_url: "http://127.0.0.1:1"
  health:
    path: /status
  tools:
    get_ping:
      method: GET
      path: /ping
`

func TestLoadRESTBackends_HealthTargets(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"checked.dadl": testHealthDADL, "plain.dadl": testDADLContent} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	yaml := []byte(`
backends:
  - name: polled
    transport: rest
    dadl: checked.dadl
    health_check:
      interval: 1h
      degrade_after: 2
      auth_expires_at: 2026-10-16
  - name: defaults
    transport: rest
    dadl: checked.dadl
  - name: unpolled
    transport: rest
    dadl: checked.dadl
    health_check:
      interval: 0
  - name: silenced
    transport: rest
    dadl: checked.dadl
    health_check:
      enabled: false
  - name: undeclared
    transport: rest
    dadl: plain.dadl
    health_check:
      interval: 15m
  - name: typo
    transport: rest
    dadl: checked.dadl
    health_check:
      interval: soon
`)
	if err := os.WriteFile(backendsPath, yaml, 0o600); err != nil {
		t.Fatal(err)
	}

	buf := &capturedWriter{}
	logger := slog.New(slog.NewTextHandler(buf, nil))
	named := make(map[string]backend.ToolBackend)
	targets := loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, logger, nil, nil, nil)

	if len(named) != 6 {
		t.Fatalf("loaded %d backends, want all 6: a health_check problem must not cost the backend", len(named))
	}
	byName := map[string]health.Target{}
	for _, tg := range targets {
		byName[tg.Name] = tg
	}
	if len(byName) != 4 {
		t.Fatalf("targets = %v, want polled, defaults, unpolled and typo", targets)
	}
	if p := byName["polled"].Policy; p.Interval != time.Hour || p.DegradeAfter != 2 {
		t.Errorf("polled policy = %+v", p)
	}
	if p := byName["defaults"].Policy; p.Interval != health.DefaultInterval || p.WarnBefore != health.DefaultWarnBefore {
		t.Errorf("defaults policy = %+v, want the default interval and window", p)
	}
	if p := byName["unpolled"].Policy; p.Interval != 0 {
		t.Errorf("unpolled policy = %+v, want polling off for interval 0", p)
	}
	if p := byName["typo"].Policy; p.Interval != health.DefaultInterval {
		t.Errorf("typo policy = %+v, want the default interval", p)
	}
	logs := string(buf.data)
	for _, want := range []string{"DADL declares no health check", "invalid health_check settings"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
	// The load line names the poll interval only for monitored backends.
	wantInterval := map[string]string{"defaults": "15m0s", "polled": "1h0m0s", "unpolled": "0s", "silenced": "0s", "undeclared": "0s"}
	seen := 0
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, "REST proxy backend loaded") {
			continue
		}
		for name, interval := range wantInterval {
			if !strings.Contains(line, " name="+name+" ") {
				continue
			}
			seen++
			if !strings.Contains(line, "health_poll_interval="+interval) {
				t.Errorf("load line for %s lacks health_poll_interval=%s: %s", name, interval, line)
			}
		}
	}
	if seen != len(wantInterval) {
		t.Errorf("found %d load lines for %d backends:\n%s", seen, len(wantInterval), logs)
	}

	res := byName["polled"].Checker.CheckHealth(t.Context())
	if want := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC); !res.AuthExpiresAt.Equal(want) {
		t.Errorf("auth_expires_at = %s, want the backends.yaml value %s", res.AuthExpiresAt, want)
	}
}
