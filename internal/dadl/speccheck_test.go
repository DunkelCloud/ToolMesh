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
	"strings"
	"testing"
)

func TestCheckSpecVersion(t *testing.T) {
	manifest := &SpecManifest{
		Latest:    "0.2",
		LatestURL: "https://dadl.ai/spec/dadl-spec-v0.2.md",
	}

	// Older version → warning.
	warning, err := CheckSpecVersion("https://dadl.ai/spec/dadl-spec-v0.1.md", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warning, "v0.2 is available") {
		t.Errorf("warning = %q", warning)
	}

	// Current version → no warning.
	warning, err = CheckSpecVersion("https://dadl.ai/spec/dadl-spec-v0.2.md", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if warning != "" {
		t.Errorf("expected empty warning, got %q", warning)
	}

	// Malformed URL → error.
	if _, err := CheckSpecVersion("not a valid spec url", manifest); err == nil {
		t.Error("expected parse error")
	}
}
