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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const testSSHCommands = `backend:
  type: ssh
  description: Host status
  tools:
    uptime:
      description: How long the host has been up
      access: read
      argv: [uptime]
    service_restart:
      description: Restart a service
      access: write
      argv: [sudo, -n, systemctl, restart, "{unit}"]
      params:
        unit: {enum: [caddy]}
`

// sshEntry is a complete transport: ssh entry with the given name; extra
// lines are appended to it.
func sshEntry(name string, extra ...string) string {
	lines := make([]string, 0, 8+len(extra))
	lines = append(lines,
		"  - name: "+name,
		"    transport: ssh",
		"    commands: ssh/host.yaml",
		"    ssh:",
		"      user: ops",
		"      hosts: [web1.example.com]",
		"      known_hosts: ssh/known_hosts",
		"      key_credential: "+name+"_ssh_key",
	)
	return strings.Join(append(lines, extra...), "\n") + "\n"
}

// writeSSHConfig writes backends.yaml with the given entries and the command
// file they name, and returns the path of backends.yaml.
func writeSSHConfig(t *testing.T, entries ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "ssh"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh", "host.yaml"), []byte(testSSHCommands), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "backends.yaml")
	if err := os.WriteFile(path, []byte("backends:\n"+strings.Join(entries, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSSHBackends(t *testing.T) {
	path := writeSSHConfig(t,
		sshEntry("web"),
		sshEntry("readonly", "    include_tools: [uptime]", "    hint: Ask before a restart.", "    hint_required_for: [write]"),
		sshEntry("unpolled", "    health_check:", "      interval: 0"),
		sshEntry("silenced", "    health_check:", "      enabled: false"),
		"  - name: rest-entry\n    transport: rest\n    dadl: absent.dadl\n",
	)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	named := map[string]backend.ToolBackend{}
	targets := loadSSHBackendsInto(named, path, credentials.NewEmbeddedStore(), logger, nil, nil, nil)

	names := make([]string, 0, len(named))
	for name := range named {
		names = append(names, name)
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "readonly,silenced,unpolled,web" {
		t.Fatalf("loaded backends = %s\n%s", got, logs.String())
	}

	tools, err := named["web"].ListTools(context.Background())
	if err != nil || len(tools) != 2 {
		t.Fatalf("web: tools = %+v, err %v", tools, err)
	}
	if tools[0].Name != "service_restart" || tools[0].Access != "write" || tools[0].Backend != "ssh:web" {
		t.Errorf("web: first tool = %+v", tools[0])
	}
	readonly := named["readonly"].(*backend.SSHAdapter)
	if readonly.ToolCount() != 1 {
		t.Errorf("readonly offers %d tools, want 1", readonly.ToolCount())
	}
	if info := readonly.BackendSummaries()[0]; info.Hint != "Ask before a restart." || len(info.HintRequiredFor) != 1 {
		t.Errorf("readonly: summary = %+v", info)
	}

	intervals := map[string]time.Duration{}
	for _, target := range targets {
		intervals[target.Name] = target.Policy.Interval
	}
	if len(intervals) != 3 || intervals["web"] != 15*time.Minute || intervals["unpolled"] != 0 {
		t.Errorf("health targets = %v", intervals)
	}
	if _, monitored := intervals["silenced"]; monitored {
		t.Error("a backend with health_check.enabled: false is monitored")
	}
}

func TestLoadSSHBackends_RelativePaths(t *testing.T) {
	path := writeSSHConfig(t, sshEntry("web"))
	dir := filepath.Dir(path)
	// The key file and known_hosts are found next to backends.yaml: a call
	// gets as far as the key file, which holds no key.
	entry := strings.Replace(sshEntry("web"), "key_credential: web_ssh_key", "key_file: ssh/id_web", 1)
	if err := os.WriteFile(path, []byte("backends:\n"+entry), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh", "id_web"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	named := map[string]backend.ToolBackend{}
	loadSSHBackendsInto(named, path, credentials.NewEmbeddedStore(), slog.New(slog.NewJSONHandler(&logs, nil)), nil, nil, nil)
	if named["web"] == nil {
		t.Fatal("web was not loaded")
	}
	// The call fails on the key, and the log names the file it read: the
	// one below the directory of backends.yaml. The caller is not told.
	keyFile := filepath.Join(dir, "ssh", "id_web")
	_, err := named["web"].Execute(context.Background(), "uptime", nil)
	if err == nil || strings.Contains(err.Error(), "id_web") {
		t.Errorf("err = %v, want a failure that does not name the key file", err)
	}
	found := false
	for _, line := range strings.Split(logs.String(), "\n") {
		var entry struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && strings.Contains(entry.Error, keyFile) {
			found = true
		}
	}
	if !found {
		t.Errorf("the log does not name %s:\n%s", keyFile, logs.String())
	}
}

func TestLoadSSHBackends_Refused(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string
	}{
		{"no commands", strings.Replace(sshEntry("web"), "    commands: ssh/host.yaml\n", "", 1), "commands is missing"},
		{"no ssh block", "  - name: web\n    transport: ssh\n    commands: ssh/host.yaml\n", "the ssh block is missing"},
		{"missing command file", strings.Replace(sshEntry("web"), "ssh/host.yaml", "ssh/absent.yaml", 1), "command file ssh/absent.yaml"},
		{"dadl", sshEntry("web", "    dadl: x.dadl"), "dadl is for transport: rest"},
		{"url", sshEntry("web", `    url: "ssh://web1.example.com"`), "names its hosts in ssh.hosts"},
		{"user credentials", sshEntry("web", "    user_credentials: [web_ssh_key]"), "user_credentials is supported for transport: rest only"},
		{"no user", strings.Replace(sshEntry("web"), "      user: ops\n", "", 1), "ssh.user is missing"},
		{"no name", strings.Replace(sshEntry("web"), "  - name: web\n", "  - hint: unnamed\n", 1), "the entry has no name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSSHConfig(t, tt.entry, sshEntry("other"))
			var logs bytes.Buffer
			named := map[string]backend.ToolBackend{}
			targets := loadSSHBackendsInto(named, path, credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(&logs, nil)), nil, nil, nil)
			if len(named) != 1 || named["other"] == nil || len(targets) != 1 {
				t.Errorf("loaded %d backends and %d targets, want the other entry only", len(named), len(targets))
			}
			if !strings.Contains(logs.String(), "SSH backend refused") || !strings.Contains(logs.String(), tt.want) {
				t.Errorf("log misses %q:\n%s", tt.want, logs.String())
			}
		})
	}
}

func TestLoadSSHBackends_NameTaken(t *testing.T) {
	path := writeSSHConfig(t, sshEntry("web"))
	var logs bytes.Buffer
	taken := &backend.EchoBackend{}
	named := map[string]backend.ToolBackend{"web": taken}
	loadSSHBackendsInto(named, path, credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(&logs, nil)), nil, nil, nil)
	if named["web"] != backend.ToolBackend(taken) {
		t.Error("an SSH entry replaced a backend of the same name")
	}
	if !strings.Contains(logs.String(), "another backend has the same name") {
		t.Errorf("log = %s", logs.String())
	}
}

func TestLoadSSHBackends_ExposeToolsIgnored(t *testing.T) {
	path := writeSSHConfig(t, sshEntry("web", "    expose_tools: [uptime]"))
	var logs bytes.Buffer
	named := map[string]backend.ToolBackend{}
	loadSSHBackendsInto(named, path, credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(&logs, nil)), nil, nil, nil)
	if named["web"] == nil || !strings.Contains(logs.String(), "expose_tools is not honored for transport ssh") {
		t.Errorf("loaded %v, log:\n%s", named, logs.String())
	}
}

func TestLoadSSHBackends_NoConfig(t *testing.T) {
	named := map[string]backend.ToolBackend{}
	if targets := loadSSHBackendsInto(named, filepath.Join(t.TempDir(), "absent.yaml"), credentials.NewEmbeddedStore(), slog.New(slog.DiscardHandler), nil, nil, nil); len(targets) != 0 || len(named) != 0 {
		t.Errorf("loaded %v and %v without a config", named, targets)
	}
}
