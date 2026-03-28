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

package dadl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SpecManifestURL is the endpoint that returns the current DADL spec versions.
const SpecManifestURL = "https://dadl.ai/spec/latest.json"

// SpecManifest represents the remote spec version manifest from dadl.ai.
type SpecManifest struct {
	Latest    string            `json:"latest"`
	LatestURL string            `json:"latest_url"`
	Supported []SpecVersionInfo `json:"supported"`
	Generated string            `json:"generated"`
}

// SpecVersionInfo describes a single supported spec version.
type SpecVersionInfo struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

// FetchSpecManifest retrieves the current spec manifest from dadl.ai.
// Uses a short timeout to avoid blocking startup if the network is unavailable.
func FetchSpecManifest(ctx context.Context) (*SpecManifest, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, SpecManifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "ToolMesh/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", SpecManifestURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", SpecManifestURL, resp.StatusCode)
	}

	var manifest SpecManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode spec manifest: %w", err)
	}

	return &manifest, nil
}

// CheckSpecVersion compares a local spec URL against the remote manifest.
// Returns a warning message if a newer version is available, or empty string if up to date.
// Returns an error only if the spec URL format is invalid.
func CheckSpecVersion(specURL string, manifest *SpecManifest) (warning string, err error) {
	localMatch := specVersionRe.FindStringSubmatch(specURL)
	if localMatch == nil {
		return "", fmt.Errorf("spec URL %q does not match expected format", specURL)
	}
	localVersion := localMatch[1]

	if localVersion == manifest.Latest {
		return "", nil
	}

	return fmt.Sprintf(
		"DADL spec v%s is available (this file uses v%s) — see %s",
		manifest.Latest, localVersion, manifest.LatestURL,
	), nil
}
