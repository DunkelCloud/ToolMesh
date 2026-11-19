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

package sshcmd

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// maxExactInteger is the largest integer a JSON number holds exactly (2^53).
const maxExactInteger = 1 << 53

// ValueError reports an argument that has the declared type and is outside
// the limits of its parameter: not in the list of values, not matching the
// pattern, out of range, too long, or shaped like an option.
//
// It unwraps to a [dadl.APIError] with code invalid_input, like the generic
// argument check, so a caller branches on one code for every rejected
// argument.
type ValueError struct {
	// Tool is the command the call was made against.
	Tool string
	// Param is the parameter whose value was refused; empty when the
	// values are refused together.
	Param string
	// Problem says what is wrong with the value, as the rest of a sentence
	// that starts with the parameter's name.
	Problem string
}

// Error renders the complaint.
func (e *ValueError) Error() string {
	if e.Param == "" {
		return fmt.Sprintf("tool %q: %s", e.Tool, e.Problem)
	}
	return fmt.Sprintf("tool %q: parameter %q %s", e.Tool, e.Param, e.Problem)
}

// Unwrap exposes the structured form of the error.
func (e *ValueError) Unwrap() error {
	return &dadl.APIError{
		Code:       dadl.ErrCodeInvalidInput,
		HTTPStatus: http.StatusBadRequest,
		Message:    e.Error(),
	}
}

// Declared returns the command's parameters in the form the generic
// argument check reads. The map is shared; callers do not modify it.
func (t *Tool) Declared() map[string]dadl.ParamDef {
	return t.declared
}

// Check validates the arguments of a call and returns them as the command
// uses them: defaults filled in, numeric strings as numbers. extra declares
// parameters the caller of Check consumes itself (the host of a backend
// that serves several); they pass the generic check and are returned as
// given.
func (t *Tool) Check(params map[string]any, extra map[string]dadl.ParamDef) (map[string]any, error) {
	declared := t.declared
	if len(extra) > 0 {
		declared = make(map[string]dadl.ParamDef, len(t.declared)+len(extra))
		for name, def := range t.declared {
			declared[name] = def
		}
		for name, def := range extra {
			declared[name] = def
		}
	}
	if err := dadl.ValidateParams(t.Name, declared, params); err != nil {
		return nil, err
	}
	out := dadl.NormalizeParams(declared, params)
	for _, name := range t.paramNames() {
		if _, problem := t.Params[name].text(out[name], false); problem != "" {
			return nil, &ValueError{Tool: t.Name, Param: name, Problem: problem}
		}
	}
	return out, nil
}

// Command renders the command line for arguments that passed Check. Every
// argv item becomes one argument in single quotes, so the shell of the host
// reads each as one literal word: a value cannot add an argument, start a
// second command or expand to anything.
//
// The limits of every parameter are applied again here, so that a command
// line never exists for a value Check would have refused.
func (t *Tool) Command(params map[string]any) (string, error) {
	var line strings.Builder
	for i, segs := range t.argv {
		var arg strings.Builder
		for _, s := range segs {
			if s.param == "" {
				arg.WriteString(s.literal)
				continue
			}
			text, problem := t.Params[s.param].text(params[s.param], false)
			if problem != "" {
				return "", &ValueError{Tool: t.Name, Param: s.param, Problem: problem}
			}
			arg.WriteString(text)
		}
		if i > 0 {
			line.WriteByte(' ')
		}
		line.WriteString(Quote(arg.String()))
	}
	if line.Len() > MaxCommandLength {
		return "", &ValueError{Tool: t.Name, Problem: fmt.Sprintf("the values make the command line longer than %d bytes", MaxCommandLength)}
	}
	return line.String(), nil
}

// Succeeded reports whether a run that ended with the given exit code
// counts as a success: code 0, or one of success_exit_codes when the
// command declares them. A command such as "systemctl is-active" answers
// with its exit code, and its author says which codes are answers.
func (t *Tool) Succeeded(code int) bool {
	for _, c := range t.successCodes {
		if c == code {
			return true
		}
	}
	return false
}

// Quote puts s in single quotes for the shell of the host. Inside single
// quotes a POSIX shell takes every character literally; a single quote in s
// closes the quoting, is written escaped, and opens it again.
//
// A backslash is written the same way, outside the quotes. A POSIX shell
// would take it literally inside them as well, but fish reads a backslash
// before a backslash or a quote as an escape there: a value with two
// backslashes would arrive with one, and a value that ends in a backslash
// would swallow the closing quote and let the rest of the line out of the
// quoting. Written this way, sh, bash, dash, ksh, zsh and fish all read the
// same word.
func Quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			b.WriteString(`'\''`)
		case '\\':
			b.WriteString(`'\\'`)
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// Usage returns the command as the file writes it, placeholders included,
// for a description: journalctl -u {unit} -n {lines} --no-pager.
func (t *Tool) Usage() string {
	parts := make([]string, len(t.source))
	for i, item := range t.source {
		if item == "" || strings.ContainsAny(item, " \t\n'\"") {
			parts[i] = Quote(item)
			continue
		}
		parts[i] = item
	}
	return strings.Join(parts, " ")
}

// Doc returns the description a caller reads: what the command does, the
// command it runs and the limits of its parameters. The limits are part of
// the text because a generated signature carries types only.
func (t *Tool) Doc() string {
	var b strings.Builder
	b.WriteString(t.Description)
	if !strings.HasSuffix(t.Description, ".") {
		b.WriteByte('.')
	}
	b.WriteString(" Runs `")
	b.WriteString(t.Usage())
	b.WriteString("`.")
	if names := t.paramNames(); len(names) > 0 {
		notes := make([]string, len(names))
		for i, name := range names {
			notes[i] = name + ": " + t.Params[name].limits()
		}
		b.WriteString(" Parameters: ")
		b.WriteString(strings.Join(notes, "; "))
		b.WriteByte('.')
	}
	return b.String()
}

// InputSchema returns the JSON Schema of the command's arguments, with the
// limits of every parameter. The schema is closed: an argument the command
// does not declare is refused.
func (t *Tool) InputSchema() map[string]any {
	props := make(map[string]any, len(t.Params))
	var required []string
	for _, name := range t.paramNames() {
		p := t.Params[name]
		props[name] = p.schema()
		if p.Default == nil {
			required = append(required, name)
		}
	}
	schema := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// paramNames returns the names of the command's parameters, sorted.
func (t *Tool) paramNames() []string {
	names := make([]string, 0, len(t.Params))
	for name := range t.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// schema returns the JSON Schema of the parameter.
func (p *Param) schema() map[string]any {
	s := map[string]any{"type": p.Type}
	if p.Description != "" {
		s["description"] = p.Description
	}
	if p.Default != nil {
		s["default"] = p.Default
	}
	if len(p.Enum) > 0 {
		values := make([]any, len(p.Enum))
		for i, text := range p.Enum {
			values[i] = p.enumValue(text)
		}
		s["enum"] = values
	}
	switch p.Type {
	case TypeString:
		s["maxLength"] = p.MaxLength
		if p.pattern != nil {
			s["pattern"] = p.pattern.String()
		}
	case TypeInteger, TypeNumber:
		s["minimum"] = *p.Min
		if p.Max != nil {
			s["maximum"] = *p.Max
		}
	}
	return s
}

// enumValue returns an enum entry in the JSON type of the parameter.
func (p *Param) enumValue(text string) any {
	if p.Type == TypeInteger || p.Type == TypeNumber {
		if f, err := strconv.ParseFloat(text, 64); err == nil {
			return f
		}
	}
	return text
}

// limits describes the values the parameter takes, for the description.
func (p *Param) limits() string {
	var parts []string
	switch {
	case len(p.Enum) > 0:
		parts = append(parts, "one of "+strings.Join(p.Enum, ", "))
	case p.Type == TypeString:
		parts = append(parts, "string matching "+p.Pattern)
	case p.Type == TypeBoolean:
		parts = append(parts, TypeBoolean)
	default:
		bound := p.Type + " from " + formatFloat(*p.Min)
		if p.Max != nil {
			bound += " to " + formatFloat(*p.Max)
		}
		parts = append(parts, bound)
	}
	if p.Default != nil {
		if text, ok := scalarText(p.Default); ok {
			parts = append(parts, "default "+text)
		}
	}
	if p.Description != "" {
		parts = append(parts, p.Description)
	}
	return strings.Join(parts, ", ")
}

// text returns the text the command line carries for value v, or what is
// wrong with v. trusted marks a value the author of the file wrote (a
// default): the rule against a leading "-" exists for values of callers.
func (p *Param) text(v any, trusted bool) (text, problem string) {
	if v == nil {
		return "", "is missing"
	}
	switch p.Type {
	case TypeBoolean:
		b, ok := v.(bool)
		if !ok {
			return "", "must be true or false"
		}
		return strconv.FormatBool(b), ""
	case TypeInteger:
		n, ok := toInt(v)
		if !ok {
			return "", "must be a whole number"
		}
		text = strconv.FormatInt(n, 10)
		if problem = p.checkRange(float64(n)); problem != "" {
			return "", problem
		}
	case TypeNumber:
		f, ok := toFloat(v)
		if !ok {
			return "", "must be a number"
		}
		text = formatFloat(f)
		if problem = p.checkRange(f); problem != "" {
			return "", problem
		}
	default:
		s, ok := scalarText(v)
		if !ok {
			return "", "must be a string"
		}
		text = s
		if problem = p.checkString(text, trusted); problem != "" {
			return "", problem
		}
	}
	if len(p.Enum) > 0 && !contains(p.Enum, text) {
		return "", "must be one of: " + strings.Join(p.Enum, ", ")
	}
	return text, ""
}

// checkString applies the limits of a string parameter to a value.
func (p *Param) checkString(text string, trusted bool) string {
	if strings.ContainsRune(text, 0) {
		return "must not contain a NUL byte"
	}
	if len(text) > p.MaxLength {
		return fmt.Sprintf("is longer than %d bytes", p.MaxLength)
	}
	if len(p.Enum) > 0 {
		// The list is the limit; text checks it for every type.
		return ""
	}
	if p.pattern != nil && !p.pattern.MatchString(text) {
		return "does not match the pattern " + p.Pattern
	}
	// A value the author wrote as the default is the author's choice, also
	// when a caller sends the same text.
	if !trusted && strings.HasPrefix(text, "-") && !p.isDefault(text) {
		return `must not start with "-": the command would read it as an option`
	}
	return ""
}

// isDefault reports whether text is the text of the parameter's default.
func (p *Param) isDefault(text string) bool {
	if p.Default == nil {
		return false
	}
	def, ok := scalarText(p.Default)
	return ok && def == text
}

// checkRange applies min and max to a numeric value.
func (p *Param) checkRange(f float64) string {
	if p.Min != nil && f < *p.Min {
		return "must be at least " + formatFloat(*p.Min)
	}
	if p.Max != nil && f > *p.Max {
		return "must be at most " + formatFloat(*p.Max)
	}
	return ""
}

// contains reports whether list has the entry s.
func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// formatFloat renders f in the shortest exact decimal form, without an
// exponent.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// scalarText renders a string, number or boolean as text; other values have
// no text form.
func scalarText(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case bool, float64, float32, int, int32, int64, uint, uint32, uint64, json.Number:
		return dadl.FormatScalar(val), true
	}
	return "", false
}

// toInt converts a decoded JSON or YAML value to a whole number.
func toInt(v any) (int64, bool) {
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int32:
		return int64(val), true
	case int64:
		return val, true
	case uint:
		return toInt(uint64(val))
	case uint32:
		return int64(val), true
	case uint64:
		if val > math.MaxInt64 {
			return 0, false
		}
		return int64(val), true
	case float64:
		if val != math.Trunc(val) || math.Abs(val) > maxExactInteger {
			return 0, false
		}
		return int64(val), true
	case json.Number:
		return toInt(string(val))
	case string:
		n, err := strconv.ParseInt(val, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// toFloat converts a decoded JSON or YAML value to a finite number.
func toFloat(v any) (float64, bool) {
	var f float64
	switch val := v.(type) {
	case float64:
		f = val
	case float32:
		f = float64(val)
	case json.Number:
		return toFloat(string(val))
	case string:
		parsed, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, false
		}
		f = parsed
	default:
		n, ok := toInt(v)
		if !ok {
			return 0, false
		}
		f = float64(n)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
