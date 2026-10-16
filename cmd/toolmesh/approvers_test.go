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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

// Keys of the approver tests.
const (
	testApproverKey = "approver-key-of-its-own"    //nolint:gosec // test fixture, not a credential
	testMCPKey      = "key-an-agent-connects-with" //nolint:gosec // test fixture, not a credential
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// approverFile is a grants file with the approver alice holding key.
func approverFile(key string) string {
	return "preset: single-user\napprovers:\n  - name: alice\n    key_sha256: " + sha256Hex(key) + "\n"
}

func TestSetupAuthz_RefusesApproverWithMCPKey(t *testing.T) {
	tests := []struct {
		name  string
		setup func(cfg *config.Config)
		want  string
	}{
		{envAPIKey, func(cfg *config.Config) { cfg.APIKey = testMCPKey }, envAPIKey},
		{envAuthPassword, func(cfg *config.Config) { cfg.AuthPassword = testMCPKey }, envAuthPassword},
		{"apikeys.yaml", func(cfg *config.Config) {
			writeFile(t, cfg.APIKeysConfigPath, "keys:\n  - user_id: bob\n    key_sha256: "+strings.ToUpper(sha256Hex(testMCPKey))+"\n")
		}, `key 1 (user_id "bob")`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authzTestConfig(t)
			tc.setup(cfg)
			writeFile(t, cfg.AuthzConfigPath, approverFile(testMCPKey))
			_, err := setupAuthz(context.Background(), cfg, false, quietLogger())
			if err == nil || !strings.Contains(err.Error(), "alice") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want alice refused, naming %s", err, tc.want)
			}
		})
	}
}

// On a reload, a colliding approver is refused and the approvers in force
// stay.
func TestApplyAuthzPolicy_KeepsApproversOnCollision(t *testing.T) {
	cfg := authzTestConfig(t)
	cfg.APIKey = testMCPKey
	writeFile(t, cfg.AuthzConfigPath, approverFile(testApproverKey))
	s := mustSetup(t, cfg, false)
	if got := s.embedded.Approvers(); len(got) != 1 || got[0].KeySHA256 != sha256Hex(testApproverKey) {
		t.Fatalf("approvers = %+v", got)
	}

	writeFile(t, cfg.AuthzConfigPath, approverFile(testMCPKey))
	if _, err := applyAuthzPolicy(context.Background(), cfg, s.embedded, quietLogger()); err == nil {
		t.Fatal("a reload with an approver holding the API key was applied")
	}
	if got := s.embedded.Approvers(); len(got) != 1 || got[0].KeySHA256 != sha256Hex(testApproverKey) {
		t.Errorf("approvers after the refused reload = %+v, want the previous ones", got)
	}
}
