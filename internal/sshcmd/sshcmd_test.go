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
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

const (
	toolJournalTail    = "journal_tail"
	toolServiceRestart = "service_restart"
	paramUnit          = "unit"
	paramLines         = "lines"
	testUnit           = "caddy.service"
	testOtherUnit      = "a.service"
	serviceCaddy       = "caddy"
	errNoPatternMatch  = "does not match the pattern"
)

const exampleFile = `
backend:
  name: linux-host
  type: ssh
  description: Status and logs of services on a Linux host
  defaults:
    timeout: 20s
    max_output: 64KB
  tools:
    journal_tail:
      description: Last lines of a unit's journal
      access: read
      argv: [journalctl, -u, "{unit}", -n, "{lines}", --no-pager]
      params:
        unit:
          pattern: "[a-z0-9@_.-]+\\.service"
          description: the unit
        lines:
          type: integer
          default: 100
          min: 1
          max: 500
    service_restart:
      description: Restart a service
      access: write
      argv: [sudo, -n, systemctl, restart, "{unit}"]
      timeout: 2m
      params:
        unit:
          enum: [caddy, toolmesh]
    service_active:
      description: Whether a service runs
      access: read
      argv: [systemctl, is-active, "{unit}.service"]
      success_exit_codes: [0, 3]
      params:
        unit:
          enum: [caddy, toolmesh]
`

func mustParse(t *testing.T, src string) *Spec {
	t.Helper()
	spec, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	return spec
}

func TestParseBytes_Example(t *testing.T) {
	spec := mustParse(t, exampleFile)
	if spec.Name != "linux-host" || spec.Description == "" || len(spec.ContentHash) != 64 {
		t.Errorf("spec header = %q, %q, hash %q", spec.Name, spec.Description, spec.ContentHash)
	}
	if len(spec.Tools) != 3 {
		t.Fatalf("got %d tools, want 3", len(spec.Tools))
	}

	tail := spec.Tools[toolJournalTail]
	if tail.Access != "read" || tail.Timeout != 20*time.Second || tail.MaxOutput != 64<<10 {
		t.Errorf("journal_tail: access %q, timeout %s, max output %d", tail.Access, tail.Timeout, tail.MaxOutput)
	}
	if got, want := tail.Usage(), "journalctl -u {unit} -n {lines} --no-pager"; got != want {
		t.Errorf("Usage = %q, want %q", got, want)
	}
	doc := tail.Doc()
	for _, want := range []string{"Last lines of a unit's journal.", "Runs `journalctl -u {unit} -n {lines} --no-pager`. Parameters: ", "lines: integer from 1 to 500, default 100", `unit: string matching [a-z0-9@_.-]+\.service, the unit`} {
		if !strings.Contains(doc, want) {
			t.Errorf("Doc misses %q:\n%s", want, doc)
		}
	}

	restart := spec.Tools[toolServiceRestart]
	if restart.Timeout != 2*time.Minute || restart.MaxOutput != 64<<10 {
		t.Errorf("service_restart: timeout %s, max output %d", restart.Timeout, restart.MaxOutput)
	}
	if !restart.Succeeded(0) || restart.Succeeded(1) {
		t.Error("service_restart: only exit code 0 counts as success")
	}
	active := spec.Tools["service_active"]
	if !active.Succeeded(0) || !active.Succeeded(3) || active.Succeeded(1) {
		t.Error("service_active: exit codes 0 and 3 count as success, 1 does not")
	}
}

func TestParseBytes_ContentHashIgnoresLineEndings(t *testing.T) {
	lf := mustParse(t, exampleFile)
	crlf := mustParse(t, strings.ReplaceAll(exampleFile, "\n", "\r\n"))
	if lf.ContentHash != crlf.ContentHash {
		t.Error("the content hash differs between LF and CRLF line endings")
	}
}

// TestParse_ShippedExample keeps the example command file loadable: it is
// what an operator copies.
func TestParse_ShippedExample(t *testing.T) {
	spec, err := Parse(filepath.Join("..", "..", "config", "ssh", "linux-host.yaml.example"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"uptime", "disk_free", toolJournalTail, "service_active", toolServiceRestart} {
		if spec.Tools[name] == nil {
			t.Errorf("the example has no command %q", name)
		}
	}
	line, err := spec.Tools[toolJournalTail].Command(map[string]any{paramUnit: testUnit, paramLines: 20})
	if err != nil {
		t.Fatal(err)
	}
	if want := `'journalctl' '-u' 'caddy.service' '-n' '20' '--no-pager'`; line != want {
		t.Errorf("Command = %s, want %s", line, want)
	}
	if _, err := Parse(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing file was parsed")
	}
}

// fileWith wraps one command, given as the YAML below its name, in a file.
func fileWith(tool string) string {
	return "backend:\n  type: ssh\n  tools:\n    t:\n" + tool
}

func TestParseBytes_Refused(t *testing.T) {
	const head = "      description: d\n      access: read\n"
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"empty file", "", "empty"},
		{"wrong type", "backend:\n  type: rest\n  tools: {}\n", `backend.type must be "ssh"`},
		{"no tools", "backend:\n  type: ssh\n", "declares no command"},
		{"unknown key", fileWith(head + "      argv: [ls]\n      shell: true\n"), "field shell not found"},
		{"unknown top-level key", "backends: {}\n", "field backends not found"},
		{"no description", fileWith("      access: read\n      argv: [ls]\n"), "description is missing"},
		{"no access", fileWith("      description: d\n      argv: [ls]\n"), "access is missing"},
		{"no argv", fileWith(head), "argv is missing"},
		{"placeholder in program", fileWith(head + "      argv: [\"{p}\"]\n      params:\n        p: {enum: [ls]}\n"), "argv[0] is the program"},
		{"undeclared placeholder", fileWith(head + "      argv: [ls, \"{p}\"]\n"), "uses {p}, which params does not declare"},
		{"unused parameter", fileWith(head + "      argv: [ls]\n      params:\n        p: {enum: [a]}\n"), `parameter "p" is declared, but no argv item uses {p}`},
		{"free string", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {type: string}\n"), "needs a pattern or an enum"},
		{"pattern and enum", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {pattern: a, enum: [a]}\n"), "pattern or enum, not both"},
		{"bad pattern", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {pattern: \"[\"}\n"), "pattern:"},
		{"bad type", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {type: array}\n"), "not one of string, integer, number, boolean"},
		{"reserved host", fileWith(head + "      argv: [ls, \"{host}\"]\n      params:\n        host: {enum: [a]}\n"), `"host" is reserved`},
		{"optional without default", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {enum: [a], required: false}\n"), "optional parameter needs a default"},
		{"default outside enum", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {enum: [a], default: b}\n"), "default must be one of: a"},
		{"default outside range", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {type: integer, max: 5, default: 9}\n"), "default must be at most 5"},
		{"max below min", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {type: integer, max: -1}\n"), "max is below min"},
		{"pattern on integer", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {type: integer, pattern: \"1\"}\n"), "apply to string parameters"},
		{"min on string", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {pattern: a, min: 1}\n"), "apply to integer and number"},
		{"limits on boolean", fileWith(head + "      argv: [ls, \"{p}\"]\n      params:\n        p: {type: boolean, enum: [true]}\n"), "a boolean takes no"},
		{"unclosed brace", fileWith(head + "      argv: [ls, \"{p\"]\n"), "without a closing }"},
		{"stray closing brace", fileWith(head + "      argv: [ls, \"p}\"]\n"), "without an opening {"},
		{"bad placeholder name", fileWith(head + "      argv: [ls, \"{P x}\"]\n"), "is not a parameter name"},
		{"timeout too long", fileWith(head + "      argv: [ls]\n      timeout: 1h\n"), "outside the range"},
		{"bad timeout", fileWith(head + "      argv: [ls]\n      timeout: soon\n"), "is not a duration"},
		{"output too large", fileWith(head + "      argv: [ls]\n      max_output: 1GB\n"), "above the maximum"},
		{"bad exit code", fileWith(head + "      argv: [ls]\n      success_exit_codes: [300]\n"), "is not an exit code"},
		{"bad command name", "backend:\n  type: ssh\n  tools:\n    \"a b\":\n" + head + "      argv: [ls]\n", "the name must start with a letter"},
		{"unquoted placeholder", fileWith(head + "      argv: [ls, {p}]\n      params:\n        p: {enum: [a]}\n"), "cannot unmarshal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(tt.src))
			if err == nil {
				t.Fatal("the file was accepted")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseArg_Braces(t *testing.T) {
	spec := mustParse(t, fileWith("      description: d\n      access: read\n      argv: [awk, \"{{print ${n}}}\", \"--x={{}}\"]\n      params:\n        n: {type: integer, max: 9}\n"))
	line, err := spec.Tools["t"].Command(map[string]any{"n": 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := `'awk' '{print $2}' '--x={}'`; line != want {
		t.Errorf("Command = %s, want %s", line, want)
	}
}

func TestCheck(t *testing.T) {
	spec := mustParse(t, exampleFile)
	tail := spec.Tools[toolJournalTail]

	t.Run("fills the default and keeps numbers as numbers", func(t *testing.T) {
		got, err := tail.Check(map[string]any{paramUnit: testUnit}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got[paramUnit] != testUnit || got[paramLines] != 100 {
			t.Errorf("checked = %#v", got)
		}
		got, err = tail.Check(map[string]any{paramUnit: testUnit, paramLines: "250"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got[paramLines] != float64(250) {
			t.Errorf(`lines = %#v, want 250 as a number`, got[paramLines])
		}
	})

	t.Run("passes extra parameters through", func(t *testing.T) {
		extra := map[string]dadl.ParamDef{HostParam: {Type: TypeString, Required: true}}
		got, err := tail.Check(map[string]any{paramUnit: testUnit, "host": "web1"}, extra)
		if err != nil {
			t.Fatal(err)
		}
		if got["host"] != "web1" {
			t.Errorf("host = %#v", got["host"])
		}
		if _, err := tail.Check(map[string]any{paramUnit: testUnit}, extra); err == nil {
			t.Error("a call without the required extra parameter passed")
		}
	})

	refused := []struct {
		name   string
		tool   string
		params map[string]any
		want   string
	}{
		{"missing required", toolJournalTail, map[string]any{}, `missing required parameter "unit"`},
		{"unknown parameter", toolJournalTail, map[string]any{paramUnit: testOtherUnit, "line": 5}, `unknown parameter "line" (did you mean "lines"?)`},
		{"wrong type", toolJournalTail, map[string]any{paramUnit: testOtherUnit, paramLines: "many"}, `parameter "lines" must be integer`},
		{"pattern", toolJournalTail, map[string]any{paramUnit: serviceCaddy}, errNoPatternMatch},
		{"pattern is anchored", toolJournalTail, map[string]any{paramUnit: "x.service; reboot"}, errNoPatternMatch},
		{"trailing line break", toolJournalTail, map[string]any{paramUnit: "caddy.service\n"}, errNoPatternMatch},
		{"leading dash", toolJournalTail, map[string]any{paramUnit: "--flush.service"}, `must not start with "-"`},
		{"below min", toolJournalTail, map[string]any{paramUnit: testOtherUnit, paramLines: 0}, "must be at least 1"},
		{"above max", toolJournalTail, map[string]any{paramUnit: testOtherUnit, paramLines: 501}, "must be at most 500"},
		{"fraction", toolJournalTail, map[string]any{paramUnit: testOtherUnit, paramLines: 1.5}, `parameter "lines" must be integer`},
		{"outside enum", toolServiceRestart, map[string]any{paramUnit: "sshd"}, "must be one of: caddy, toolmesh"},
		{"list for a string", toolServiceRestart, map[string]any{paramUnit: []any{serviceCaddy}}, `parameter "unit" must be string`},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			_, err := spec.Tools[tt.tool].Check(tt.params, nil)
			if err == nil {
				t.Fatal("the call was accepted")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
			var apiErr *dadl.APIError
			if !errors.As(err, &apiErr) || apiErr.Code != dadl.ErrCodeInvalidInput {
				t.Errorf("error %T does not unwrap to an invalid_input APIError", err)
			}
		})
	}
}

func TestCheck_NegativeNumbers(t *testing.T) {
	const head = "      description: d\n      access: read\n      argv: [nice, -n, \"{n}\", true]\n      params:\n"
	closed := mustParse(t, fileWith(head+"        n: {type: integer}\n")).Tools["t"]
	if _, err := closed.Check(map[string]any{"n": -1}, nil); err == nil || !strings.Contains(err.Error(), "must be at least 0") {
		t.Errorf("without a declared min a negative value passed: %v", err)
	}
	open := mustParse(t, fileWith(head+"        n: {type: integer, min: -20, max: 19}\n")).Tools["t"]
	checked, err := open.Check(map[string]any{"n": -5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if line, _ := open.Command(checked); line != `'nice' '-n' '-5' 'true'` {
		t.Errorf("Command = %s", line)
	}
}

func TestCheck_DefaultMayStartWithDash(t *testing.T) {
	tool := mustParse(t, fileWith("      description: d\n      access: read\n      argv: [journalctl, --since, \"{since}\"]\n      params:\n        since: {pattern: \"-?[0-9]+[smhd]\", default: \"-1h\"}\n")).Tools["t"]
	// The author's default passes, also when a caller writes it out.
	for _, params := range []map[string]any{{}, {"since": "-1h"}} {
		checked, err := tool.Check(params, nil)
		if err != nil {
			t.Fatalf("Check(%v): %v", params, err)
		}
		if line, _ := tool.Command(checked); line != `'journalctl' '--since' '-1h'` {
			t.Errorf("Command = %s", line)
		}
	}
	// Another value with a dash is the caller's and is refused.
	if _, err := tool.Check(map[string]any{"since": "-2h"}, nil); err == nil {
		t.Error("a caller's value with a leading dash passed")
	}
}

func TestCheck_Limits(t *testing.T) {
	tool := mustParse(t, fileWith("      description: d\n      access: read\n      argv: [grep, -c, --, \"{q}\", /var/log/syslog]\n      params:\n        q: {pattern: \".*\", max_length: 8}\n")).Tools["t"]
	if _, err := tool.Check(map[string]any{"q": "123456789"}, nil); err == nil || !strings.Contains(err.Error(), "longer than 8 bytes") {
		t.Errorf("a value above max_length passed: %v", err)
	}
	if _, err := tool.Check(map[string]any{"q": "a\x00b"}, nil); err == nil {
		t.Error("a value with a NUL byte passed")
	}
}

func TestCommand_RefusesWithoutCheck(t *testing.T) {
	tool := mustParse(t, exampleFile).Tools[toolJournalTail]
	if _, err := tool.Command(map[string]any{paramUnit: "x; reboot", paramLines: 5}); err == nil {
		t.Error("Command rendered a value its parameter refuses")
	}
	if _, err := tool.Command(map[string]any{paramUnit: testOtherUnit}); err == nil {
		t.Error("Command rendered without a value for {lines}")
	}
}

func TestCommand_TooLong(t *testing.T) {
	tool := mustParse(t, fileWith("      description: d\n      access: read\n      argv: [echo, \"{a}{a}{a}{a}\"]\n      params:\n        a: {pattern: \"x*\", max_length: 32768}\n")).Tools["t"]
	checked, err := tool.Check(map[string]any{"a": strings.Repeat("x", 32768)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tool.Command(checked); err == nil || !strings.Contains(err.Error(), "command line longer than") {
		t.Errorf("an oversized command line was rendered: %v", err)
	}
}

func TestInputSchema(t *testing.T) {
	schema := mustParse(t, exampleFile).Tools[toolJournalTail].InputSchema()
	if schema["additionalProperties"] != false {
		t.Error("the schema is not closed")
	}
	if got := schema["required"]; !reflect.DeepEqual(got, []string{paramUnit}) {
		t.Errorf("required = %v, want [unit]", got)
	}
	props := schema["properties"].(map[string]any)
	lines := props[paramLines].(map[string]any)
	if lines["type"] != "integer" || lines["minimum"] != 1.0 || lines["maximum"] != 500.0 || lines["default"] != 100 {
		t.Errorf("lines = %v", lines)
	}
	unit := props[paramUnit].(map[string]any)
	if unit["pattern"] != `^(?:[a-z0-9@_.-]+\.service)$` || unit["maxLength"] != DefaultMaxLength {
		t.Errorf("unit = %v", unit)
	}
	restart := mustParse(t, exampleFile).Tools[toolServiceRestart].InputSchema()
	enum := restart["properties"].(map[string]any)[paramUnit].(map[string]any)["enum"]
	if !reflect.DeepEqual(enum, []any{serviceCaddy, "toolmesh"}) {
		t.Errorf("enum = %v", enum)
	}
}

func TestQuote(t *testing.T) {
	tests := map[string]string{
		"":          `''`,
		"plain":     `'plain'`,
		"two words": `'two words'`,
		"it's":      `'it'\''s'`,
		"$(id)":     `'$(id)'`,
		"a;b|c&d":   `'a;b|c&d'`,
		"~root":     `'~root'`,
		"*":         `'*'`,
		"A=b":       `'A=b'`,
		// No backslash stays inside the quotes: fish reads it as an escape
		// there, a POSIX shell does not.
		`a\b`:  `'a'\\'b'`,
		`end\`: `'end'\\''`,
		`\'`:   `''\\''\'''`,
		`\\`:   `''\\''\\''`,
	}
	for in, want := range tests {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestCommand_ShellSeesOneArgumentPerItem runs rendered command lines
// through the shells found on this machine: whatever a value contains, the
// program receives it as the one argument its argv item stands for.
func TestCommand_ShellSeesOneArgumentPerItem(t *testing.T) {
	var shells []string
	for _, name := range []string{"sh", "bash", "dash", "ksh", "zsh", "fish"} {
		if path, err := exec.LookPath(name); err == nil {
			shells = append(shells, path)
		}
	}
	if len(shells) == 0 {
		t.Skip("no shell in PATH")
	}
	for _, sh := range shells {
		t.Run(filepath.Base(sh), func(t *testing.T) { checkShellArguments(t, sh) })
	}
}

func checkShellArguments(t *testing.T, sh string) {
	t.Helper()
	tool := mustParse(t, fileWith("      description: d\n      access: read\n      argv: [printf, '[%s]', \"{a}\", \"pre-{a}-post\", \"{b}\"]\n      params:\n        a: {pattern: \"(?s).*\"}\n        b: {pattern: \"(?s).*\"}\n")).Tools["t"]

	values := []string{
		"plain",
		"two words",
		"it's",
		`"double"`,
		"$(echo injected)",
		"`echo injected`",
		"a; echo injected",
		"a && echo injected",
		"a | cat",
		"> /dev/null",
		"$HOME",
		"~",
		"*",
		`back\slash`,
		`two\\backslashes`,
		`trailing\`,
		`\'`,
		`\'; echo injected; '`,
		"line\nbreak",
		"tab\there",
		"'; echo injected; '",
		"",
	}
	for _, v := range values {
		checked, err := tool.Check(map[string]any{"a": v, "b": v}, nil)
		if err != nil {
			t.Fatalf("Check(%q): %v", v, err)
		}
		line, err := tool.Command(checked)
		if err != nil {
			t.Fatalf("Command(%q): %v", v, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// The line goes in on stdin, as sshd hands it to the shell as one
		// string. As an argument it would pass through the argument
		// quoting of the test's own platform first.
		cmd := exec.CommandContext(ctx, sh) //nolint:gosec // a shell from PATH, run on the rendered command line the test examines
		cmd.Stdin = strings.NewReader(line + "\n")
		out, err := cmd.Output()
		cancel()
		if err != nil {
			t.Fatalf("%s <<< %s: %v", sh, line, err)
		}
		if want := "[" + v + "][pre-" + v + "-post][" + v + "]"; string(out) != want {
			t.Errorf("value %q: the shell passed on %q, want %q\ncommand: %s", v, out, want, line)
		}
	}
}
