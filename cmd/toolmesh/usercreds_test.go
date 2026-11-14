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
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// testUserDADL is a bearer-auth API with a health check against a closed
// local port.
const testUserDADL = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mail
  type: rest
  base_url: "http://127.0.0.1:1"
  description: "A mail API"
  auth:
    type: bearer
    credential: mail_login
  health:
    path: /status
  tools:
    list_messages:
      method: GET
      path: /messages
`

const (
	testUserBackends = `
backends:
  - name: mail
    transport: rest
    dadl: mail.dadl
    user_credentials:
      - name: mail_login
        label: Mailbox login
  - name: shared
    transport: rest
    dadl: mail.dadl
    credentials: [mail_login]
`
	testUserKeyEnv = "TOOLMESH_USER_CREDENTIALS_KEY"
)

func testUserKey() string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", credentials.UserCredentialsKeyBytes)))
}

// TestLoadRESTBackends_UserCredentials pins what the loader does with an
// entry that declares user_credentials: without the user credential store
// the backend is not loaded, with it the backend runs and is not monitored
// in the background, where no user and so no credential exists.
func TestLoadRESTBackends_UserCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mail.dadl"), []byte(testUserDADL), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	if err := os.WriteFile(backendsPath, []byte(testUserBackends), 0o600); err != nil {
		t.Fatal(err)
	}

	// The store is off: the per-user backend stays out, the other loads.
	buf := &capturedWriter{}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, slog.New(slog.NewTextHandler(buf, nil)), nil, nil, nil, nil)
	if _, loaded := named["mail"]; loaded || len(named) != 1 {
		t.Fatalf("without the user credential store: loaded %d backends, want only the one without user_credentials", len(named))
	}
	if !strings.Contains(string(buf.data), testUserKeyEnv) {
		t.Errorf("the log does not name the setting that turns the store on:\n%s", buf.data)
	}

	// The store is on.
	t.Setenv(testUserKeyEnv, testUserKey())
	t.Setenv("TOOLMESH_DATA_DIR", t.TempDir())
	t.Setenv("TOOLMESH_ISSUER", "https://toolmesh.example.com/")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	users, err := newUserCredentialSetup(cfg, quietLogger())
	if err != nil || users == nil {
		t.Fatalf("newUserCredentialSetup = %v, %v", users, err)
	}
	if users.enrollURL != "https://toolmesh.example.com/credentials" {
		t.Errorf("enrollURL = %q", users.enrollURL)
	}
	named = make(map[string]backend.ToolBackend)
	targets, _ := loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, quietLogger(), nil, nil, nil, users)
	if len(named) != 2 {
		t.Fatalf("with the user credential store: loaded %d backends, want both", len(named))
	}
	if len(targets) != 1 || targets[0].Name != "shared" {
		t.Errorf("health targets = %+v, want only the backend with instance credentials", targets)
	}

	reg := &userBackendRegistry{}
	if got := reg.list(); got != nil {
		t.Errorf("empty registry lists %v", got)
	}
	reg.set(named)
	listed := reg.list()
	if len(listed) != 1 || listed[0].Name != "mail" || listed[0].Description != "A mail API" ||
		len(listed[0].Credentials) != 1 || listed[0].Credentials[0].Label != "Mailbox login" {
		t.Errorf("registry = %+v", listed)
	}
	if _, ok := reg.get("shared"); ok {
		t.Error("the registry holds a backend without user credentials")
	}
	if _, ok := reg.get("mail"); !ok {
		t.Error("the registry does not hold the per-user backend")
	}
}

func TestNewUserCredentialSetup(t *testing.T) {
	t.Setenv("TOOLMESH_DATA_DIR", t.TempDir())

	// Off by default.
	t.Setenv(testUserKeyEnv, "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if users, err := newUserCredentialSetup(cfg, quietLogger()); users != nil || err != nil {
		t.Errorf("without a key: %v, %v, want the store off", users, err)
	}
	if b := (*userCredentialSetup)(nil).binding([]backend.UserCredential{{Name: "x"}}); b == nil || b.Store != nil {
		t.Errorf("binding without a store = %+v, want one that makes the backend refuse", b)
	}
	if b := (*userCredentialSetup)(nil).binding(nil); b != nil {
		t.Errorf("binding of an entry without user_credentials = %+v", b)
	}

	// A key that is none stops the start instead of running unencrypted.
	t.Setenv(testUserKeyEnv, "not-a-key")
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newUserCredentialSetup(cfg, quietLogger()); err == nil || !strings.Contains(err.Error(), testUserKeyEnv) {
		t.Errorf("bad key: err = %v", err)
	}

	// Without a public address the messages name the path only.
	t.Setenv(testUserKeyEnv, testUserKey())
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	users, err := newUserCredentialSetup(cfg, quietLogger())
	if err != nil || users == nil || users.enrollURL != "" {
		t.Errorf("placeholder issuer: %+v, %v", users, err)
	}
}
