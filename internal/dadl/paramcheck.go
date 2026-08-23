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
	"net/http"
	"sort"
	"strings"
)

// maxDeclaredParamsListed bounds how many declared parameter names a
// ParamError message spells out. Tools with very wide parameter sets exist
// (OPNsense set_* endpoints reach several dozen); listing all of them would
// bury the actual complaint. The size of the remainder is still reported so
// the caller knows the list was cut.
const maxDeclaredParamsListed = 40

// ParamError reports a tool call whose arguments do not match the tool's
// declared parameters (DADL spec §6.1) — an argument the tool does not
// declare, a required parameter left out, or both.
//
// Before this check existed, both faults were silent: request building
// iterates the *declared* parameters, so an undeclared argument was dropped
// on the floor and a missing one simply never appeared in the request. The
// call still went out, meaning something other than what the caller wrote,
// and whatever came back looked like a genuine answer. A caller that guessed
// `range` for a parameter actually named `time_range` could not tell the
// result from an API that genuinely held no data.
//
// It unwraps to an [APIError] with code invalid_input and HTTP status 400, so
// the failure reaches composite JavaScript and Code Mode through the same
// §8.2 fields (e.code, e.http_status) as a 400 from the API itself.
type ParamError struct {
	// Tool is the tool or composite the call was made against.
	Tool string
	// Unknown lists the supplied arguments the tool does not declare, sorted.
	Unknown []string
	// MissingRequired lists declared required parameters the call left out,
	// sorted. A parameter carrying a `default:` is never listed here — the
	// runtime supplies the value.
	MissingRequired []string
	// Suggestions maps an unknown argument to the closest declared parameter
	// name, where one is close enough to be worth naming. Not every entry in
	// Unknown has one.
	Suggestions map[string]string

	// declared renders the tool's full parameter set into the message.
	declared []string
}

// Error renders the full complaint: what was wrong, the likely intended name
// where one is identifiable, and the declared parameter set to correct
// against. The declared set is part of the message on purpose — a caller that
// guessed a name recovers in one round trip instead of guessing again.
func (e *ParamError) Error() string {
	parts := make([]string, 0, len(e.Unknown)+len(e.MissingRequired))
	for _, name := range e.Unknown {
		if suggestion := e.Suggestions[name]; suggestion != "" {
			parts = append(parts, fmt.Sprintf("unknown parameter %q (did you mean %q?)", name, suggestion))
			continue
		}
		parts = append(parts, fmt.Sprintf("unknown parameter %q", name))
	}
	for _, name := range e.MissingRequired {
		parts = append(parts, fmt.Sprintf("missing required parameter %q", name))
	}

	msg := fmt.Sprintf("tool %q: %s", e.Tool, strings.Join(parts, "; "))
	if len(e.declared) == 0 {
		return msg + "; this tool declares no parameters"
	}
	listed, suffix := e.declared, ""
	if len(listed) > maxDeclaredParamsListed {
		suffix = fmt.Sprintf(" and %d more", len(listed)-maxDeclaredParamsListed)
		listed = listed[:maxDeclaredParamsListed]
	}
	return msg + "; declared parameters: " + strings.Join(listed, ", ") + suffix
}

// Unwrap exposes the §8.2 structured form so callers reach the semantic code
// and HTTP status through errors.As, exactly as they do for an error the API
// itself returned.
func (e *ParamError) Unwrap() error {
	return &APIError{
		Code:       ErrCodeInvalidInput,
		HTTPStatus: http.StatusBadRequest,
		Message:    e.Error(),
	}
}

// ValidateParams checks caller-supplied arguments against a tool's declared
// parameters (DADL spec §6.1) and returns a [ParamError] when they disagree.
// It serves tools and composites alike: a composite's parameters carry no
// `in:`, so only the explicit `required:` flag applies to them.
//
// Two rules:
//
//   - Every supplied argument must be declared. Undeclared arguments never
//     reach the API — request building reads the declared set — so accepting
//     one silently means executing a different call than the caller wrote.
//   - Every required parameter must be supplied. `in: path` counts as
//     required (the URL cannot be built without it), matching the input
//     schema advertised to clients.
//
// A parameter counts as supplied when the key is present; an explicit nil
// counts only for `in: body`, where JSON null is a distinct instruction
// ("clear this field") rather than an omission. A declared `default:`
// satisfies required on its own — the runtime fills the value in, so the
// caller need not.
func ValidateParams(toolName string, declared map[string]ParamDef, params map[string]any) error {
	var unknown []string
	for name := range params {
		if _, ok := declared[name]; !ok {
			unknown = append(unknown, name)
		}
	}

	var missing []string
	for name, def := range declared {
		if !def.Required && def.In != paramInPath {
			continue
		}
		if !paramSupplied(name, def, params) {
			missing = append(missing, name)
		}
	}

	if len(unknown) == 0 && len(missing) == 0 {
		return nil
	}
	sort.Strings(unknown)
	sort.Strings(missing)

	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)

	suggestions := make(map[string]string, len(unknown))
	for _, name := range unknown {
		if s := suggestParam(name, names); s != "" {
			suggestions[name] = s
		}
	}

	return &ParamError{
		Tool:            toolName,
		Unknown:         unknown,
		MissingRequired: missing,
		Suggestions:     suggestions,
		declared:        describeParams(declared, names),
	}
}

// paramSupplied reports whether a required parameter has a value the request
// builder will actually use. See [ValidateParams] for the nil and default
// rules this encodes.
func paramSupplied(name string, def ParamDef, params map[string]any) bool {
	if def.Default != nil {
		return true
	}
	val, ok := params[name]
	if !ok {
		return false
	}
	return val != nil || def.In == paramInBody
}

// describeParams renders each declared parameter as "name (type, in: …,
// required)" so the error message carries enough to rewrite the call without
// a second discovery round trip. names must already be sorted.
func describeParams(declared map[string]ParamDef, names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		def := declared[name]
		var attrs []string
		if def.Type != "" {
			attrs = append(attrs, def.Type)
		}
		if def.In != "" {
			attrs = append(attrs, "in: "+def.In)
		}
		if def.Required || def.In == paramInPath {
			attrs = append(attrs, "required")
		}
		if len(attrs) == 0 {
			out = append(out, name)
			continue
		}
		out = append(out, name+" ("+strings.Join(attrs, ", ")+")")
	}
	return out
}

// suggestParam finds the declared parameter a caller most plausibly meant by
// unknown, or "" when nothing is close enough to name without misleading them.
//
// Three passes, strongest signal first. Case and separators are stripped
// before comparing, so time_range / timeRange / TIME-RANGE collapse together.
// Then containment, which catches the truncation and prefix-drop mistakes
// that dominate in practice (range → time_range, id → project_id) and that
// edit distance scores as far apart. Only then edit distance, bounded by a
// third of the name's length so one short name cannot match an unrelated one.
func suggestParam(unknown string, declared []string) string {
	target := normalizeParamName(unknown)
	if target == "" {
		return ""
	}

	var (
		containsBest string
		containsDiff int
	)
	for _, name := range declared {
		candidate := normalizeParamName(name)
		if candidate == target {
			return name
		}
		if !strings.Contains(candidate, target) && !strings.Contains(target, candidate) {
			continue
		}
		diff := len(candidate) - len(target)
		if diff < 0 {
			diff = -diff
		}
		if containsBest == "" || diff < containsDiff {
			containsBest, containsDiff = name, diff
		}
	}
	if containsBest != "" {
		return containsBest
	}

	budget := len(target) / 3
	if budget < 1 {
		budget = 1
	}
	best, bestDist := "", budget+1
	for _, name := range declared {
		if d := editDistance(target, normalizeParamName(name)); d <= budget && d < bestDist {
			best, bestDist = name, d
		}
	}
	return best
}

// normalizeParamName folds the spelling differences that carry no meaning —
// case, and the separators that distinguish snake_case from kebab-case from
// camelCase — so name comparison sees only the letters.
func normalizeParamName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToLower(name) {
		switch r {
		case '_', '-', '.', ' ':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// editDistance is the Levenshtein distance between two short strings, kept on
// two rolling rows. Parameter names are a few dozen bytes at most, so the
// quadratic bound does not matter here.
func editDistance(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}
