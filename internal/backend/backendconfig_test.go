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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Regression: "tools_filter" was never a ToolMesh field. Lenient parsing
// dropped it without a word, so a backend an operator believed to be
// restricted quietly exposed its full tool surface.
func TestUnmarshalBackendConfig_RejectsUnknownKey(t *testing.T) {
	data := []byte(`backends:
  - name: fetch_url
    transport: http
    url: "http://127.0.0.1:3000/mcp"
    tools_filter: ["fetch_url", "fetch_urls"]
`)

	var cfg BackendConfig
	err := UnmarshalBackendConfig(data, &cfg)
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "tools_filter") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

// Every documented key must still parse — a strict decoder that rejects valid
// config would be worse than the lenient one it replaces.
func TestUnmarshalBackendConfig_AcceptsKnownKeys(t *testing.T) {
	data := []byte(`backends:
  - name: fetch_url
    transport: http
    url: "http://127.0.0.1:3000/mcp"
    api_key_env: "FETCH_URL_KEY"
    hint: "renders JS-heavy pages"
    tls_skip_verify: false
    include_tools: ["fetch_url", "fetch_urls"]
    expose_tools: ["fetch_url"]
    options:
      blob_ttl: "1h"
    env:
      TOKEN: "OTHER_TOKEN"
  - name: local-tools
    transport: stdio
    command: "./my-mcp-server"
    args: ["--port", "0"]
  - name: hackernews
    transport: rest
    dadl: hackernews.dadl
    allow_private_url: true
    allow_private_file_url: false
    file_url_allowed_hosts: ["blobstore.internal"]
`)

	var cfg BackendConfig
	if err := UnmarshalBackendConfig(data, &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Backends) != 3 {
		t.Fatalf("expected 3 backends, got %d", len(cfg.Backends))
	}
	if got := cfg.Backends[0].IncludeTools; len(got) != 2 {
		t.Errorf("expected include_tools to survive the round trip, got %v", got)
	}
}

// An empty or fully commented-out file means "no backends", not a boot failure.
func TestUnmarshalBackendConfig_AcceptsEmptyDocument(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     {},
		"commented": []byte("# nothing configured yet\n"),
	} {
		t.Run(name, func(t *testing.T) {
			var cfg BackendConfig
			if err := UnmarshalBackendConfig(data, &cfg); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.Backends) != 0 {
				t.Errorf("expected no backends, got %d", len(cfg.Backends))
			}
		})
	}
}

// The adapter refuses to start on a config it cannot fully honor, rather than
// coming up with a surface the operator did not ask for.
func TestNewMCPAdapter_RejectsUnknownKey(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "backends.yaml")
	data := []byte(`backends:
  - name: fetch_url
    transport: http
    url: "http://127.0.0.1:3000/mcp"
    tools_filter: ["fetch_url"]
`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := NewMCPAdapter(configPath, credentials.NewEmbeddedStore(), slog.Default())
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
}
