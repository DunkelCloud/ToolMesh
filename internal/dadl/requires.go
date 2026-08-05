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
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// implementedFeatures lists the DADL feature identifiers (spec §15.3) this
// ToolMesh build implements. checkRequires matches requires.features entries
// against this set at load time — extend it as features land in the runtime.
var implementedFeatures = map[string]bool{
	"refresh_token": true, // §5.3: oauth2 flow refresh_token
	"composites":    true, // §12: composite tools
	"file_url":      true, // §6.2: file handling (input params + response type)
	"redact":        true, // §9.3: response.redact masking
}

// checkRequires enforces the file's requires block (DADL spec §15.3,
// ADR-0003): a runtime that cannot satisfy every entry refuses to load the
// file, naming the missing capability. Feature identifiers are matched
// against implementedFeatures; the toolmesh clause is matched against
// runtimeVersion.
//
// A runtimeVersion that is not a semver literal (e.g. the default "dev" of
// a build without ldflags) cannot be compared: the version clause is then
// skipped with a warning instead of refusing every requires-carrying file
// in development builds. The range syntax is still validated.
//
// The gate applies regardless of the declared spec URL — honoring a load
// restriction is always safe, even from a file claiming spec v0.1.
func checkRequires(spec *Spec, runtimeVersion string) error {
	req := spec.Requires
	if req == nil {
		return nil
	}

	for _, feature := range req.Features {
		if feature == "" {
			return fmt.Errorf("requires.features contains an empty feature identifier")
		}
		if !implementedFeatures[feature] {
			return fmt.Errorf("file requires feature %q, which this ToolMesh build does not implement (implemented: %s)",
				feature, strings.Join(slices.Sorted(maps.Keys(implementedFeatures)), ", "))
		}
	}

	if req.ToolMesh == "" {
		return nil
	}
	clauses, err := parseVersionRange(req.ToolMesh)
	if err != nil {
		return fmt.Errorf("requires.toolmesh: %w", err)
	}
	current, ok := parseVersion(runtimeVersion)
	if !ok {
		spec.Warnings = append(spec.Warnings, fmt.Sprintf(
			"requires.toolmesh %q not checked: running version %q is not a semver literal",
			req.ToolMesh, runtimeVersion))
		return nil
	}
	for _, c := range clauses {
		if !c.satisfiedBy(current) {
			return fmt.Errorf("file requires toolmesh %q, running version is %s", req.ToolMesh, runtimeVersion)
		}
	}
	return nil
}

// versionLiteralRe matches a version literal: optional v prefix,
// MAJOR.MINOR with optional .PATCH.
var versionLiteralRe = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?$`)

// parseVersion parses a semver literal into a comparable [major, minor,
// patch] triple. A missing patch component defaults to 0. Prerelease and
// build suffixes are not supported and report ok=false.
func parseVersion(s string) (v [3]int, ok bool) {
	m := versionLiteralRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return v, false
	}
	for i, part := range m[1:] {
		if part == "" {
			continue // optional patch
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return v, false // digits only per regexp; guards absurd lengths
		}
		v[i] = n
	}
	return v, true
}

// compareVersions returns -1, 0, or 1 as a is less than, equal to, or
// greater than b.
func compareVersions(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// versionClause is one comparison of a requires.toolmesh range.
type versionClause struct {
	op string // ">=", ">", "<=", "<", "="
	v  [3]int
}

// satisfiedBy reports whether version cur fulfills the clause.
func (c versionClause) satisfiedBy(cur [3]int) bool {
	cmp := compareVersions(cur, c.v)
	switch c.op {
	case ">=":
		return cmp >= 0
	case ">":
		return cmp > 0
	case "<=":
		return cmp <= 0
	case "<":
		return cmp < 0
	default: // "="
		return cmp == 0
	}
}

// rangeOperators in match order — two-character operators first so ">=" is
// not consumed as ">".
var rangeOperators = []string{">=", "<=", ">", "<", "="}

// parseVersionRange parses a requires.toolmesh range (spec §15.3):
// comma-separated AND clauses, each a comparison operator followed by a
// version literal. A bare version means exact match.
func parseVersionRange(rangeExpr string) ([]versionClause, error) {
	parts := strings.Split(rangeExpr, ",")
	clauses := make([]versionClause, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty clause in version range %q", rangeExpr)
		}
		op := "="
		rest := part
		for _, candidate := range rangeOperators {
			if strings.HasPrefix(part, candidate) {
				op = candidate
				rest = strings.TrimSpace(part[len(candidate):])
				break
			}
		}
		v, ok := parseVersion(rest)
		if !ok {
			return nil, fmt.Errorf("invalid version %q in range %q (expected MAJOR.MINOR[.PATCH])", rest, rangeExpr)
		}
		clauses = append(clauses, versionClause{op: op, v: v})
	}
	return clauses, nil
}
