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
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strconv"
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
	// WrongType maps a supplied argument to the declared type its value does
	// not have (see [ValidateParams] for which types are checked).
	WrongType map[string]string
	// gotType names the JSON type each WrongType value actually has.
	gotType map[string]string

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
	wrong := make([]string, 0, len(e.WrongType))
	for name := range e.WrongType {
		wrong = append(wrong, name)
	}
	sort.Strings(wrong)
	for _, name := range wrong {
		parts = append(parts, fmt.Sprintf("parameter %q must be %s, got %s", name, e.WrongType[name], e.gotType[name]))
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
//   - A supplied, non-null value must fit its declared type where the JSON
//     form is unambiguous: boolean takes only true or false, integer a
//     whole JSON number or a string of decimal digits (large IDs), number a
//     JSON number or a numeric string, array a JSON array and object a JSON
//     object. string takes a string, number or boolean (the request carries
//     all three as text, see [NormalizeParams]), but no array or object. The
//     file types are passed as given. The check runs before the gate, so a
//     policy that tests a boolean for false cannot be passed with the string
//     "false".
//
// A parameter counts as supplied when the key is present; an explicit nil
// counts only for `in: body`, where JSON null is a distinct instruction
// ("clear this field") rather than an omission. A declared `default:`
// satisfies required on its own — the runtime fills the value in, so the
// caller need not.
func ValidateParams(toolName string, declared map[string]ParamDef, params map[string]any) error {
	return validateParams(toolName, declared, params, true)
}

// ValidateRequiredParams is [ValidateParams] for a declaration that leaves
// its parameter set open — an MCP input schema that admits additional
// properties — where a name outside the declared ones is legitimate. Only
// the required rule applies; an undeclared argument passes through.
func ValidateRequiredParams(toolName string, declared map[string]ParamDef, params map[string]any) error {
	return validateParams(toolName, declared, params, false)
}

// validateParams applies both rules of [ValidateParams], or only the
// required rule when rejectUnknown is false.
func validateParams(toolName string, declared map[string]ParamDef, params map[string]any, rejectUnknown bool) error {
	var unknown []string
	if rejectUnknown {
		for name := range params {
			if _, ok := declared[name]; !ok {
				unknown = append(unknown, name)
			}
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

	wrongType := map[string]string{}
	gotType := map[string]string{}
	for name, val := range params {
		def, ok := declared[name]
		if !ok || val == nil {
			continue
		}
		if want := strings.ToLower(def.Type); !valueFitsType(want, val) {
			wrongType[name] = want
			gotType[name] = jsonTypeName(val)
		}
	}

	if len(unknown) == 0 && len(missing) == 0 && len(wrongType) == 0 {
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
		WrongType:       wrongType,
		gotType:         gotType,
		declared:        describeParams(declared, names),
	}
}

// maxExactInteger is the largest integer a float64, and so a JavaScript
// number, holds exactly (2^53).
const maxExactInteger = 1 << 53

// NormalizeParams returns the arguments a call takes effect with, for
// params that passed ValidateParams: declared defaults are filled in for
// omitted parameters (and for null values outside the body, as the request
// builder does), numeric strings of integer and number parameters become
// numbers, and numbers and booleans of string parameters become the text
// the request carries ([FormatScalar]: 42 becomes "42", true "true"). A gate
// policy then sees the values the API receives: a default it would
// otherwise never see, 0 rather than "0", and "42" rather than 42. An
// integer string beyond 2^53 stays a string, since a number could not hold
// it exactly. Other values pass unchanged; params itself is not modified.
func NormalizeParams(declared map[string]ParamDef, params map[string]any) map[string]any {
	out := make(map[string]any, len(params)+len(declared))
	for name, val := range params {
		out[name] = val
	}
	for name, def := range declared {
		val, present := out[name]
		if def.Default != nil && (!present || (val == nil && def.In != paramInBody)) {
			out[name] = def.Default
			continue
		}
		if !present || val == nil {
			continue
		}
		if want := strings.ToLower(def.Type); want == jsTypeString {
			out[name] = normalizeString(val)
		} else {
			out[name] = normalizeNumeric(want, val)
		}
	}
	return out
}

// normalizeString converts a number or boolean of a string parameter to the
// text the request builder sends for it. Path, query, header and form
// parameters are sent as that text anyway; a JSON body carries the string
// too, as the declaration says.
func normalizeString(val any) any {
	if isScalarNonString(val) {
		return FormatScalar(val)
	}
	return val
}

// isScalarNonString reports whether val is a boolean or a number, the
// scalar values other than a string that a string parameter takes.
func isScalarNonString(val any) bool {
	switch val.(type) {
	case bool, json.Number:
		return true
	}
	return isNumeric(val)
}

// FormatScalar renders a scalar parameter value as the text a request
// carries for it in a URL path, query string, header or form field, and as
// the string a string parameter's number or boolean becomes before the
// gate ([NormalizeParams]). Both use this one function so that a policy
// sees exactly the text the API receives.
//
// JSON unmarshalling decodes every numeric value into float64. Formatting
// that float64 with fmt.Sprintf("%v", ...) routes through %g, which switches
// to scientific notation once the value reaches ~1e6, so an integer ID like
// 1234567 would become "1.234567e+06". strconv.FormatFloat with verb 'f'
// and precision -1 always produces the shortest exact decimal
// representation without exponents.
func FormatScalar(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case bool:
		return strconv.FormatBool(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32)
	case int:
		return strconv.Itoa(val)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case json.Number:
		return string(val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// normalizeNumeric converts a numeric string (or json.Number) of an integer
// or number parameter to a float64 where that is exact.
func normalizeNumeric(declared string, val any) any {
	var s string
	switch v := val.(type) {
	case string:
		s = v
	case json.Number:
		s = string(v)
	default:
		return val
	}
	switch declared {
	case jsTypeInteger:
		if !isIntegerLiteral(s) {
			return val
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxExactInteger || n < -maxExactInteger {
			return val
		}
		return float64(n)
	case jsTypeNumber:
		if !isDecimalLiteral(s) {
			return val
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return val
		}
		return f
	}
	return val
}

// valueFitsType reports whether val, a decoded JSON value, fits the declared
// DADL type. Types without an unambiguous JSON form always fit.
func valueFitsType(declared string, val any) bool {
	switch declared {
	case jsTypeString:
		// A number or boolean is taken and becomes text before the gate
		// (NormalizeParams). An array, object or any other value has no
		// text form the API would expect.
		_, isString := val.(string)
		return isString || isScalarNonString(val)
	case jsTypeBoolean:
		_, ok := val.(bool)
		return ok
	case jsTypeInteger:
		switch v := val.(type) {
		case string:
			return isIntegerLiteral(v)
		case json.Number:
			return isIntegerLiteral(string(v))
		}
		return isWholeNumber(val)
	case jsTypeNumber:
		switch v := val.(type) {
		case string:
			return isDecimalLiteral(v)
		case json.Number:
			return isDecimalLiteral(string(v))
		}
		return isNumeric(val)
	case jsTypeArray:
		return isList(val)
	case jsTypeObject:
		return isMap(val)
	}
	return true
}

// integerLiteral and decimalLiteral are the only string forms accepted for
// integer and number parameters: one optional sign and plain decimal
// digits (RE2's \d is ASCII only), no surrounding space, no hex, no digit
// separators, no Inf or NaN.
// Anything looser would pass the check and reach the API as written.
var (
	integerLiteral = regexp.MustCompile(`^[+-]?\d+$`)
	decimalLiteral = regexp.MustCompile(`^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$`)
)

// isIntegerLiteral reports whether s is an optionally signed run of decimal
// digits.
func isIntegerLiteral(s string) bool {
	return integerLiteral.MatchString(s)
}

// isDecimalLiteral reports whether s is a plain decimal number that fits a
// float64.
func isDecimalLiteral(s string) bool {
	if !decimalLiteral.MatchString(s) {
		return false
	}
	f, err := strconv.ParseFloat(s, 64)
	return err == nil && !math.IsInf(f, 0)
}

// isNumeric reports whether val is a Go numeric value.
func isNumeric(val any) bool {
	switch val.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	}
	return false
}

// isWholeNumber reports whether val is a numeric value without a fraction.
func isWholeNumber(val any) bool {
	var f float64
	switch v := val.(type) {
	case float64:
		f = v
	case float32:
		f = float64(v)
	default:
		return isNumeric(val)
	}
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

// isList reports whether val is a slice or array.
func isList(val any) bool {
	k := reflect.ValueOf(val).Kind()
	return k == reflect.Slice || k == reflect.Array
}

// isMap reports whether val is a map.
func isMap(val any) bool {
	return reflect.ValueOf(val).Kind() == reflect.Map
}

// jsonTypeName names the JSON type of a decoded value for error messages.
func jsonTypeName(val any) string {
	switch val.(type) {
	case bool:
		return jsTypeBoolean
	case string:
		return jsTypeString
	case json.Number:
		return jsTypeNumber
	}
	switch {
	case isNumeric(val):
		return jsTypeNumber
	case isList(val):
		return jsTypeArray
	case isMap(val):
		return jsTypeObject
	}
	return fmt.Sprintf("%T", val)
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
