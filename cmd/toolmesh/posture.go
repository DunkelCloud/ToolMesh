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

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

// relaxedControl is one security control that is currently in a relaxed state,
// together with the environment variable an operator sets to harden it.
type relaxedControl struct {
	summary     string // what is relaxed, in plain language
	remediation string // how to harden it
}

// logSecurityPosture emits a single consolidated security-posture summary at
// startup, replacing the scattered per-feature warnings with one place to look.
//
// The reported facts are identical regardless of mode — ToolMesh is
// secure-by-default and TOOLMESH_DEV relaxes nothing on its own. The mode only
// sets the tone: in the production posture (TOOLMESH_DEV unset) every relaxed
// control is logged at WARN with a remediation hint; with TOOLMESH_DEV=true the
// same items are reported once at INFO as an expected local-development state so
// they do not become background noise on a developer's machine.
func logSecurityPosture(cfg *config.Config, authConfigured bool, logger *slog.Logger) {
	var relaxed []relaxedControl

	if !authConfigured {
		relaxed = append(relaxed, relaxedControl{
			summary:     "authentication has no credential configured — every request is rejected until one is set",
			remediation: "set TOOLMESH_AUTH_PASSWORD or TOOLMESH_API_KEY (or configure config/users.yaml / config/apikeys.yaml)",
		})
	}
	if cfg.OpenFGAMode != config.OpenFGAModeRestrict {
		relaxed = append(relaxed, relaxedControl{
			summary:     "authorization is BYPASSED — any authenticated caller may invoke every tool (authentication still applies; fine-grained access control does not)",
			remediation: "set OPENFGA_MODE=restrict to enforce user→plan→tool checks",
		})
	}
	if len(cfg.CORSAllowedOrigins) == 0 {
		relaxed = append(relaxed, relaxedControl{
			summary:     "CORS reflects any origin — any website may call this instance from a browser",
			remediation: "set TOOLMESH_CORS_ORIGINS to an explicit allowlist before exposing a browser-reachable deployment",
		})
	}
	if cfg.DebugTools {
		relaxed = append(relaxed, relaxedControl{
			summary:     "debug tools are exposed on the MCP surface (debug_echo, debug_generate)",
			remediation: "set TOOLMESH_DEBUG_TOOLS=false outside development",
		})
	}

	if len(relaxed) == 0 {
		logger.Info("security posture: all checked controls are hardened")
		return
	}

	// Method values so the same loop reports at WARN (production) or INFO (dev).
	logAt := logger.Warn
	if cfg.DevMode {
		logAt = logger.Info
		logger.Info("security posture: TOOLMESH_DEV=true — relaxed local-development posture; do NOT expose this instance publicly",
			"relaxed_controls", len(relaxed))
	} else {
		logger.Warn("SECURITY POSTURE: relaxed controls detected — review before exposing this instance publicly (set TOOLMESH_DEV=true to silence on a local-dev machine)",
			"relaxed_controls", len(relaxed))
	}
	for _, c := range relaxed {
		logAt("security posture: relaxed control", "what", c.summary, "harden", c.remediation)
	}
}
