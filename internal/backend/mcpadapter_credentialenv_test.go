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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// envPrinterVar switches TestHelperPrintEnv from a skipped test into a child
// process that prints its environment.
const envPrinterVar = "TOOLMESH_TEST_PRINT_ENV"

const (
	testChildTokenVar = "GITHUB_PERSONAL_ACCESS_TOKEN"
	testStoreTokenKey = "CREDENTIAL_GITHUB_TOKEN" //nolint:gosec // key name, not a credential
	testStdioSecret   = "stdio-secret-named"      //nolint:gosec // test fixture, not a credential
	testTokenVar      = "TOKEN"
)

// keyStore holds its values outside the environment, like the command store.
type keyStore struct{ vals map[string]string }

func (k keyStore) Get(_ context.Context, name string, _ credentials.TenantInfo) (string, error) {
	if v := k.vals["CREDENTIAL_"+strings.ToUpper(name)]; v != "" {
		return v, nil
	}
	return "", credentials.ErrCredentialNotFound
}

func (k keyStore) Healthy(context.Context) error { return nil }

func (k keyStore) LookupKey(key string) (string, bool) {
	v, ok := k.vals[key]
	return v, ok
}

func TestHelperPrintEnv(t *testing.T) {
	if os.Getenv(envPrinterVar) != "1" {
		t.Skip("child process for TestCreateSTDIOTransport_CredentialEnv")
	}
	for _, kv := range os.Environ() {
		fmt.Println(kv)
	}
	os.Exit(0)
}

// stdioEntry returns a stdio backend whose child is the env-printing helper.
func stdioEntry(t *testing.T, credEnv map[string]string) BackendEntry {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return BackendEntry{
		Name:          "github",
		Transport:     transportTypeSTDIO,
		Command:       exe,
		Args:          []string{"-test.run=^TestHelperPrintEnv$"},
		CredentialEnv: credEnv,
	}
}

func commandOf(t *testing.T, tr mcp.Transport) *mcp.CommandTransport {
	t.Helper()
	ct, ok := tr.(*mcp.CommandTransport)
	if !ok {
		t.Fatalf("transport is %T, want *mcp.CommandTransport", tr)
	}
	return ct
}

// TestCreateSTDIOTransport_CredentialEnv starts a real child and checks that
// it sees the named store value under its own name and nothing else from
// the store.
func TestCreateSTDIOTransport_CredentialEnv(t *testing.T) {
	t.Setenv(envPrinterVar, "1")
	store := keyStore{vals: map[string]string{ //nolint:gosec // test fixtures, not credentials
		testStoreTokenKey:  testStdioSecret,
		"CREDENTIAL_OTHER": "stdio-secret-other",
		"UNRELATED_SECRET": "stdio-secret-unrelated",
	}}
	a := &MCPAdapter{logger: slog.Default(), creds: store}

	tr, err := a.createSTDIOTransport(context.Background(), stdioEntry(t, map[string]string{testChildTokenVar: testStoreTokenKey}))
	if err != nil {
		t.Fatalf("createSTDIOTransport: %v", err)
	}
	out, err := commandOf(t, tr).Command.Output()
	if err != nil {
		t.Fatalf("run child: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	if !slices.Contains(lines, testChildTokenVar+"="+testStdioSecret) {
		t.Errorf("child does not see %s:\n%s", testChildTokenVar, out)
	}
	for _, leaked := range []string{"stdio-secret-other", "stdio-secret-unrelated", testStoreTokenKey + "="} {
		if strings.Contains(string(out), leaked) {
			t.Errorf("child sees %q", leaked)
		}
	}
	if !slices.Contains(lines, envPrinterVar+"=1") {
		t.Error("child did not inherit ToolMesh's environment")
	}
}

func TestCreateSTDIOTransport_CredentialEnvEmbedded(t *testing.T) {
	t.Setenv("CREDENTIAL_EMBEDDED_TOKEN", "from-environment")
	a := &MCPAdapter{logger: slog.Default(), creds: credentials.NewEmbeddedStore()}
	tr, err := a.createSTDIOTransport(context.Background(), stdioEntry(t, map[string]string{"CHILD_TOKEN": "CREDENTIAL_EMBEDDED_TOKEN"})) //nolint:gosec // key names, not credentials
	if err != nil {
		t.Fatalf("createSTDIOTransport: %v", err)
	}
	if env := commandOf(t, tr).Command.Env; !slices.Contains(env, "CHILD_TOKEN=from-environment") {
		t.Error("credential_env with the embedded store must read the environment")
	}
}

func TestCreateSTDIOTransport_NoCredentialEnvInherits(t *testing.T) {
	a := &MCPAdapter{logger: slog.Default(), creds: keyStore{}}
	tr, err := a.createSTDIOTransport(context.Background(), stdioEntry(t, nil))
	if err != nil {
		t.Fatalf("createSTDIOTransport: %v", err)
	}
	if env := commandOf(t, tr).Command.Env; env != nil {
		t.Errorf("without credential_env the child must inherit unchanged, got an explicit env of %d entries", len(env))
	}
}

func TestCreateSTDIOTransport_CredentialEnvErrors(t *testing.T) {
	store := keyStore{vals: map[string]string{testStoreTokenKey: testStdioSecret, "EMPTY": ""}}
	a := &MCPAdapter{logger: slog.Default(), creds: store}
	tests := []struct {
		name    string
		credEnv map[string]string
		want    string
	}{
		{"missing key", map[string]string{testTokenVar: "CREDENTIAL_MISSING"}, `key "CREDENTIAL_MISSING" not found`}, //nolint:gosec // key names, not credentials
		{"empty value", map[string]string{testTokenVar: "EMPTY"}, `key "EMPTY" not found`},
		{"invalid name", map[string]string{"A=B": testStoreTokenKey}, "invalid variable name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.createSTDIOTransport(context.Background(), stdioEntry(t, tt.credEnv))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
			if strings.Contains(err.Error(), testStdioSecret) {
				t.Errorf("error leaks a value: %v", err)
			}
		})
	}
}

func TestNewMCPAdapterFromEntries_CredentialEnvOnHTTPWarns(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	NewMCPAdapterFromEntries([]BackendEntry{{
		Name:          "remote",
		Transport:     transportTypeHTTP,
		URL:           "http://127.0.0.1:1/mcp",
		CredentialEnv: map[string]string{testTokenVar: testStoreTokenKey},
	}}, keyStore{}, logger)
	if !strings.Contains(logs.String(), "credential_env is honored for transport stdio only") {
		t.Errorf("no warning for credential_env on an HTTP backend:\n%s", logs.String())
	}
}

func TestBackendConfig_CredentialEnvParses(t *testing.T) {
	var cfg BackendConfig
	err := UnmarshalBackendConfig([]byte(`
backends:
  - name: github
    transport: stdio
    command: /usr/local/bin/github-mcp-server
    args: ["stdio"]
    credential_env:
      GITHUB_PERSONAL_ACCESS_TOKEN: CREDENTIAL_GITHUB_TOKEN
`), &cfg)
	if err != nil {
		t.Fatalf("UnmarshalBackendConfig: %v", err)
	}
	if got := cfg.Backends[0].CredentialEnv[testChildTokenVar]; got != testStoreTokenKey {
		t.Errorf("credential_env = %q", cfg.Backends[0].CredentialEnv)
	}
}
