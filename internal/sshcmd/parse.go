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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

var (
	toolNameRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	paramNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Parse reads and checks the command file at path.
func Parse(path string) (*Spec, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from the operator's backends.yaml
	if err != nil {
		return nil, fmt.Errorf("read command file: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes checks a command file. The file is read strictly: a key it does
// not know, a command without an access class, a string parameter without a
// pattern or a list of values and a placeholder without a parameter are all
// errors. Each of them would otherwise leave a command wider than its author
// meant.
func ParseBytes(data []byte) (*Spec, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the command file is empty")
		}
		return nil, fmt.Errorf("parse command file: %w", err)
	}
	b := f.Backend
	if b.Type != BackendType {
		return nil, fmt.Errorf("backend.type must be %q, got %q", BackendType, b.Type)
	}
	if len(b.Tools) == 0 {
		return nil, errors.New("backend.tools declares no command")
	}
	defTimeout, err := parseTimeout(b.Defaults.Timeout, DefaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("backend.defaults.timeout: %w", err)
	}
	defOutput, err := parseMaxOutput(b.Defaults.MaxOutput, DefaultMaxOutput)
	if err != nil {
		return nil, fmt.Errorf("backend.defaults.max_output: %w", err)
	}

	sum := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	spec := &Spec{
		Name:        b.Name,
		Description: strings.TrimSpace(b.Description),
		Tools:       make(map[string]*Tool, len(b.Tools)),
		ContentHash: hex.EncodeToString(sum[:]),
	}
	names := make([]string, 0, len(b.Tools))
	for name := range b.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tool, err := compileTool(name, b.Tools[name], defTimeout, defOutput)
		if err != nil {
			return nil, fmt.Errorf("command %q: %w", name, err)
		}
		spec.Tools[name] = tool
	}
	return spec, nil
}

// compileTool checks one command and brings it into the form calls use.
func compileTool(name string, def toolDef, defTimeout time.Duration, defOutput int64) (*Tool, error) {
	if !toolNameRE.MatchString(name) {
		return nil, errors.New("the name must start with a letter and consist of letters, digits, _ and -, at most 64 characters")
	}
	if strings.TrimSpace(def.Description) == "" {
		return nil, errors.New("description is missing: it is what a caller chooses the command by")
	}
	if strings.TrimSpace(def.Access) == "" {
		return nil, errors.New("access is missing: every command needs an access class (read, write, admin, dangerous or a name of your own)")
	}
	timeout, err := parseTimeout(def.Timeout, defTimeout)
	if err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	maxOutput, err := parseMaxOutput(def.MaxOutput, defOutput)
	if err != nil {
		return nil, fmt.Errorf("max_output: %w", err)
	}

	tool := &Tool{
		Name:        name,
		Description: strings.TrimSpace(def.Description),
		Access:      strings.TrimSpace(def.Access),
		Timeout:     timeout,
		MaxOutput:   maxOutput,
		Params:      make(map[string]*Param, len(def.Params)),
		source:      append([]string(nil), def.Argv...),
		declared:    make(map[string]dadl.ParamDef, len(def.Params)),
	}
	for _, code := range def.SuccessExitCodes {
		if code < 0 || code > 255 {
			return nil, fmt.Errorf("success_exit_codes: %d is not an exit code (0 to 255)", code)
		}
	}
	tool.successCodes = append([]int{}, def.SuccessExitCodes...)
	if len(tool.successCodes) == 0 {
		tool.successCodes = []int{0}
	}
	for pname, pdef := range def.Params {
		p, err := compileParam(pname, pdef)
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", pname, err)
		}
		tool.Params[pname] = p
		tool.declared[pname] = dadl.ParamDef{
			Type:        p.Type,
			Required:    p.Default == nil,
			Default:     p.Default,
			Description: p.Description,
		}
	}
	if err := tool.compileArgv(def.Argv); err != nil {
		return nil, err
	}
	return tool, nil
}

// compileArgv parses the argument vector and checks it against the declared
// parameters: every placeholder names a parameter, and every parameter is
// used.
func (t *Tool) compileArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("argv is missing: it is the command to run, one list item per argument")
	}
	used := make(map[string]bool, len(t.Params))
	for i, arg := range argv {
		segs, err := parseArg(arg)
		if err != nil {
			return fmt.Errorf("argv[%d]: %w", i, err)
		}
		for _, s := range segs {
			if s.param == "" {
				continue
			}
			if i == 0 {
				return errors.New("argv[0] is the program and takes no placeholder")
			}
			if _, ok := t.Params[s.param]; !ok {
				return fmt.Errorf("argv[%d] uses {%s}, which params does not declare", i, s.param)
			}
			used[s.param] = true
		}
		t.argv = append(t.argv, segs)
	}
	if len(t.argv[0]) == 0 {
		return errors.New("argv[0] is empty: it names the program to run")
	}
	for pname := range t.Params {
		if !used[pname] {
			return fmt.Errorf("parameter %q is declared, but no argv item uses {%s}", pname, pname)
		}
	}
	return nil
}

// parseArg splits one argv item into literal text and placeholders. A
// placeholder is {name}; {{ and }} stand for a literal brace.
func parseArg(arg string) ([]segment, error) {
	if strings.ContainsRune(arg, 0) {
		return nil, errors.New("an argument cannot contain a NUL byte")
	}
	var (
		segs []segment
		lit  strings.Builder
	)
	flush := func() {
		if lit.Len() > 0 {
			segs = append(segs, segment{literal: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		switch c {
		case '{':
			if i+1 < len(arg) && arg[i+1] == '{' {
				lit.WriteByte('{')
				i++
				continue
			}
			end := strings.IndexByte(arg[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("%q has a { without a closing }; write {{ for a literal brace", arg)
			}
			name := arg[i+1 : i+end]
			if !paramNameRE.MatchString(name) {
				return nil, fmt.Errorf("%q: {%s} is not a parameter name; write {{ and }} for literal braces", arg, name)
			}
			flush()
			segs = append(segs, segment{param: name})
			i += end
		case '}':
			if i+1 < len(arg) && arg[i+1] == '}' {
				lit.WriteByte('}')
				i++
				continue
			}
			return nil, fmt.Errorf("%q has a } without an opening {; write }} for a literal brace", arg)
		default:
			lit.WriteByte(c)
		}
	}
	flush()
	return segs, nil
}

// compileParam checks one parameter declaration.
func compileParam(name string, def paramDef) (*Param, error) {
	if !paramNameRE.MatchString(name) {
		return nil, errors.New("the name must start with a lower-case letter and consist of lower-case letters, digits and _")
	}
	if name == HostParam {
		return nil, fmt.Errorf("%q is reserved: it selects the host of a backend that serves several", HostParam)
	}
	p := &Param{
		Name:        name,
		Type:        strings.ToLower(strings.TrimSpace(def.Type)),
		Description: strings.TrimSpace(def.Description),
		Pattern:     def.Pattern,
		MaxLength:   def.MaxLength,
	}
	if p.Type == "" {
		p.Type = TypeString
	}
	for _, v := range def.Enum {
		text, ok := scalarText(v)
		if !ok {
			return nil, errors.New("enum takes strings, numbers and booleans only")
		}
		p.Enum = append(p.Enum, text)
	}

	switch p.Type {
	case TypeString:
		if err := p.compileString(def); err != nil {
			return nil, err
		}
	case TypeInteger, TypeNumber:
		if err := p.compileNumeric(def); err != nil {
			return nil, err
		}
	case TypeBoolean:
		if def.Pattern != "" || len(def.Enum) > 0 || def.Min != nil || def.Max != nil || def.MaxLength != 0 {
			return nil, errors.New("a boolean takes no pattern, enum, min, max or max_length")
		}
	default:
		return nil, fmt.Errorf("type %q is not one of string, integer, number, boolean", def.Type)
	}

	if def.Default != nil {
		// The default is the author's, so the rule that keeps a caller's
		// value from becoming an option does not apply to it. Every other
		// limit does: a default outside them is a mistake in the file.
		if _, problem := p.text(def.Default, true); problem != "" {
			return nil, fmt.Errorf("default %s", problem)
		}
		p.Default = def.Default
	} else if def.Required != nil && !*def.Required {
		return nil, errors.New("an optional parameter needs a default: every placeholder must have a value")
	}
	return p, nil
}

// compileString checks the limits of a string parameter.
func (p *Param) compileString(def paramDef) error {
	if def.Min != nil || def.Max != nil {
		return errors.New("min and max apply to integer and number parameters")
	}
	switch {
	case def.MaxLength < 0 || def.MaxLength > MaxMaxLength:
		return fmt.Errorf("max_length must be between 1 and %d", MaxMaxLength)
	case def.MaxLength == 0:
		p.MaxLength = DefaultMaxLength
	}
	switch {
	case def.Pattern != "" && len(p.Enum) > 0:
		return errors.New("set pattern or enum, not both")
	case len(p.Enum) > 0:
		return nil
	case def.Pattern == "":
		return errors.New("a string parameter needs a pattern or an enum: say which values the command takes")
	}
	// The value must match as a whole, also when the author left the
	// anchors out; in Go, $ matches at the end of the text only, so a
	// trailing line break does not slip through.
	re, err := regexp.Compile(`^(?:` + def.Pattern + `)$`)
	if err != nil {
		return fmt.Errorf("pattern: %w", err)
	}
	p.pattern = re
	return nil
}

// compileNumeric checks the limits of an integer or number parameter.
func (p *Param) compileNumeric(def paramDef) error {
	if def.Pattern != "" || def.MaxLength != 0 {
		return errors.New("pattern and max_length apply to string parameters")
	}
	// Without a declared min a value is never negative: "-1" in the place
	// of an argument reads as an option or, to kill, as every process.
	zero := 0.0
	p.Min = &zero
	if def.Min != nil {
		p.Min = def.Min
	}
	p.Max = def.Max
	if p.Max != nil && *p.Max < *p.Min {
		return errors.New("max is below min (min is 0 unless declared)")
	}
	return nil
}

// parseTimeout reads a timeout, or returns fallback for an empty one.
func parseTimeout(s string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration such as 30s or 2m", s)
	}
	if d <= 0 || d > MaxTimeout {
		return 0, fmt.Errorf("%q is outside the range up to %s", s, MaxTimeout)
	}
	return d, nil
}

// parseMaxOutput reads an output limit, or returns fallback for an empty one.
func parseMaxOutput(s string, fallback int64) (int64, error) {
	if strings.TrimSpace(s) == "" {
		return fallback, nil
	}
	n, err := dadl.ParseByteSize(s)
	if err != nil {
		return 0, err
	}
	if n > MaxMaxOutput {
		return 0, fmt.Errorf("%q is above the maximum of %s", s, dadl.FormatByteSize(MaxMaxOutput))
	}
	return n, nil
}
