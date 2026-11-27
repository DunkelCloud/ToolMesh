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

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

// testOtherAPIKey is a second key of apikeys.yaml in these tests.
const testOtherAPIKey = "tm-test-other-api-key-value" //nolint:gosec // test fixture

// approverKeyCheck reports the SHA-256 of key as an approver key, as main
// wires it from the approvers in force.
func approverKeyCheck(key string) func(string) bool {
	sum := sha256.Sum256([]byte(key))
	want := hex.EncodeToString(sum[:])
	return func(keySHA256 string) bool { return keySHA256 == want }
}

// TestBearer_ApproverKeyRefused pins that the key of an approver never
// connects as an MCP caller, also when apikeys.yaml holds it only as a bcrypt
// key_hash, which no check at load time can compare with the approver's
// key_sha256, and also when it is TOOLMESH_API_KEY.
func TestBearer_ApproverKeyRefused(t *testing.T) {
	t.Run("bcrypt-only apikeys.yaml entry", func(t *testing.T) {
		ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{apiKeys: []string{testLoginAPIKey, testOtherAPIKey}})
		if w := ts.mcpCall("Bearer " + testLoginAPIKey); w.Code != http.StatusOK {
			t.Fatalf("API key before it is an approver's key: status %d, want 200", w.Code)
		}
		ts.srv.SetApproverKeyCheck(approverKeyCheck(testLoginAPIKey))
		if w := ts.mcpCall("Bearer " + testLoginAPIKey); w.Code != http.StatusUnauthorized {
			t.Errorf("approver's key as MCP credential: status %d, want 401", w.Code)
		}
		if !strings.Contains(ts.logs.String(), "it is the key of an approver") {
			t.Error("the refusal of an approver's key is not logged")
		}
		if w := ts.mcpCall("Bearer " + testOtherAPIKey); w.Code != http.StatusOK {
			t.Errorf("another API key: status %d, want 200", w.Code)
		}
	})

	t.Run("TOOLMESH_API_KEY", func(t *testing.T) {
		cfg := loginTestConfig()
		cfg.APIKey = testLoginAPIKey
		ts := newLoginTestServer(t, cfg, loginTestOptions{})
		ts.srv.SetApproverKeyCheck(approverKeyCheck(testLoginAPIKey))
		if w := ts.mcpCall("Bearer " + testLoginAPIKey); w.Code != http.StatusUnauthorized {
			t.Errorf("approver's key as TOOLMESH_API_KEY: status %d, want 401", w.Code)
		}
	})
}

// TestBearer_APIKeysFileReplacesEnvKey pins that an apikeys.yaml put in force
// while ToolMesh runs ends TOOLMESH_API_KEY, as one present at startup does.
func TestBearer_APIKeysFileReplacesEnvKey(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKey = testLoginAPIKey
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	if w := ts.mcpCall("Bearer " + testLoginAPIKey); w.Code != http.StatusOK {
		t.Fatalf("TOOLMESH_API_KEY without apikeys.yaml: status %d, want 200", w.Code)
	}

	sum := sha256.Sum256([]byte(testOtherAPIKey))
	keys, err := auth.ParseAPIKeyStore([]byte("keys:\n  - user_id: ci\n    key_sha256: "+hex.EncodeToString(sum[:])+"\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ts.srv.SetAPIKeyStore(keys)
	if w := ts.mcpCall("Bearer " + testLoginAPIKey); w.Code != http.StatusUnauthorized {
		t.Errorf("TOOLMESH_API_KEY with apikeys.yaml in force: status %d, want 401", w.Code)
	}
	if w := ts.mcpCall("Bearer " + testOtherAPIKey); w.Code != http.StatusOK {
		t.Errorf("key of apikeys.yaml: status %d, want 200", w.Code)
	}
}
