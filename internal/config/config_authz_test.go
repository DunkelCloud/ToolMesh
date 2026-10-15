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

package config

import (
	"strings"
	"testing"
)

func TestLoad_AuthzMode(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		legacy     string
		storeID    string
		wantMode   string
		wantSource string
		wantErr    string
	}{
		{name: "default is embedded", wantMode: AuthzModeEmbedded, wantSource: AuthzSourceDefault},
		{name: "explicit embedded", mode: AuthzModeEmbedded, wantMode: AuthzModeEmbedded, wantSource: AuthzSourceEnv},
		{name: "explicit disabled", mode: AuthzModeDisabled, wantMode: AuthzModeDisabled, wantSource: AuthzSourceEnv},
		{name: "explicit external", mode: AuthzModeExternal, storeID: "01ABC", wantMode: AuthzModeExternal, wantSource: AuthzSourceEnv},
		{name: "external needs a store", mode: AuthzModeExternal, wantErr: "requires OPENFGA_STORE_ID"},
		{name: "legacy restrict is external", legacy: OpenFGAModeRestrict, storeID: "01ABC", wantMode: AuthzModeExternal, wantSource: AuthzSourceLegacy},
		{name: "legacy restrict needs a store", legacy: OpenFGAModeRestrict, wantErr: "requires OPENFGA_STORE_ID"},
		// The old default without checks becomes the embedded engine; the
		// upgrade keeps behavior through the "open" preset (see setupAuthz).
		{name: "legacy bypass is embedded", legacy: OpenFGAModeBypass, wantMode: AuthzModeEmbedded, wantSource: AuthzSourceLegacy},
		{name: "new setting wins over legacy", mode: AuthzModeEmbedded, legacy: OpenFGAModeRestrict, wantMode: AuthzModeEmbedded, wantSource: AuthzSourceEnv},
		{name: "invalid mode", mode: OpenFGAModeBypass, wantErr: "invalid TOOLMESH_AUTHZ_MODE"},
		{name: "invalid legacy mode", legacy: "off", wantErr: "invalid OPENFGA_MODE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TOOLMESH_AUTHZ_MODE", tc.mode)
			t.Setenv("OPENFGA_MODE", tc.legacy)
			t.Setenv("OPENFGA_STORE_ID", tc.storeID)

			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.AuthzMode != tc.wantMode || cfg.AuthzModeSource != tc.wantSource {
				t.Errorf("mode/source = %s/%s, want %s/%s", cfg.AuthzMode, cfg.AuthzModeSource, tc.wantMode, tc.wantSource)
			}
			if cfg.LegacyOpenFGAMode != tc.legacy {
				t.Errorf("LegacyOpenFGAMode = %q, want %q", cfg.LegacyOpenFGAMode, tc.legacy)
			}
		})
	}
}
