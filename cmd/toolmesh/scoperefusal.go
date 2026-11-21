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
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Attributes of the "backend refused" log line that carry backends.yaml
// lines.
const (
	// logKeyFixLines holds the lines an operator can add to the entry as
	// they are: they give the backend a credential of its own.
	logKeyFixLines = "add_to_backends_yaml_entry"
	// logKeyCautionLines holds the lines that give the DADL what it names:
	// a variable outside the entry's namespace, or a further destination
	// for the backend's credentials.
	logKeyCautionLines = "check_before_adding"
	// logKeyCaution says what the lines of logKeyCautionLines do.
	logKeyCaution = "warning"
)

// scopeCaution accompanies the lines of logKeyCautionLines.
const scopeCaution = "the DADL names credentials outside this entry's namespace, or destinations beyond its base_url. " +
	"The lines under check_before_adding give it what it names: a variable that other entries may own or list, " +
	"or a further host or port that receives this backend's credentials. " +
	"Add one only after checking that the credential or the destination belongs to this API"

// scopeRefusalAttrs returns the attributes of the "backend refused" log
// line for a backend whose DADL breaks its credential or host binding: the
// lines that resolve it within the binding (logKeyFixLines) and, apart from
// them and under a warning, the lines that widen it (logKeyCautionLines).
// The DADL chose the hosts and names in those lines, so they must not read
// like the fix to copy.
func scopeRefusalAttrs(name, dadlFile string, scopeErr *dadl.ScopeError) []any {
	attrs := []any{"name", name, "dadl", dadlFile, "error", scopeErr}
	if lines := scopeErr.FixLines(); len(lines) > 0 {
		attrs = append(attrs, logKeyFixLines, lines)
	}
	if lines := scopeErr.CautionLines(); len(lines) > 0 {
		attrs = append(attrs, logKeyCaution, scopeCaution, logKeyCautionLines, lines)
	}
	return attrs
}
