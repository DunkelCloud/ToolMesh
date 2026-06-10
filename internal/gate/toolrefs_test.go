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

package gate

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

const (
	warnMsgMarker        = `"msg":"policy references unknown tool"`
	testToolCreateMR     = "gitlab_create_merge_request"
	testToolUpdateMR     = "gitlab_update_merge_request"
	testToolCreateFile   = "gitlab_create_file"
	testPolicyFile       = "p.js"
	testLiteralWrongTool = "gitlab_create_merge"
	testLitYes           = "yes"
	testLitABC           = "abc"
)

func newWarnTestGate(t *testing.T, policySource string) (*Gate, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	writePolicy(t, dir, testPolicyFile, policySource)

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}
	buf.Reset() // drop the "loaded policy" startup line
	return g, buf
}

func TestGate_WarnUnknownToolRefs(t *testing.T) {
	registered := []string{
		testToolCreateMR,
		testToolUpdateMR,
		testToolCreateFile,
		"echo_echo",
	}

	tests := []struct {
		name        string
		policy      string
		tools       []string
		wantWarns   []string          // literals expected to be warned about
		wantSuggest map[string]string // literal -> expected close-match substring
	}{
		{
			name:      "wrong tool name in comparison warns with close match",
			policy:    `if (ctx.tool === "gitlab_create_merge") { throw new Error("no"); }`,
			tools:     registered,
			wantWarns: []string{testLiteralWrongTool},
			wantSuggest: map[string]string{
				testLiteralWrongTool: testToolCreateMR,
			},
		},
		{
			name:      "registered tool name does not warn",
			policy:    `if (ctx.tool === "gitlab_create_merge_request") { throw new Error("no"); }`,
			tools:     registered,
			wantWarns: nil,
		},
		{
			name:      "colon-separated name in comparison warns",
			policy:    `if (ctx.tool === "gitlab:create_merge_request") { throw new Error("no"); }`,
			tools:     registered,
			wantWarns: []string{"gitlab:create_merge_request"},
		},
		{
			name:      "tool-shaped literal with known backend prefix warns",
			policy:    `var blocked = ["gitlab_delete_everything"]; if (blocked.indexOf(ctx.tool) >= 0) { throw new Error("no"); }`,
			tools:     registered,
			wantWarns: []string{"gitlab_delete_everything"},
		},
		{
			name:      "snake_case literal with unknown prefix is ignored",
			policy:    `var fields = ["phone_number", "credit_card"];`,
			tools:     registered,
			wantWarns: nil,
		},
		{
			name:      "literal in comment is ignored",
			policy:    "// historic: ctx.tool === \"gitlab_old_tool\"\nvar x = 1;",
			tools:     registered,
			wantWarns: nil,
		},
		{
			name:      "duplicate literal warns once",
			policy:    `if (ctx.tool === "gitlab_create_merge" || ctx.tool === "gitlab_create_merge") { throw new Error("no"); }`,
			tools:     registered,
			wantWarns: []string{testLiteralWrongTool},
		},
		{
			name:      "empty registered tool list skips the check",
			policy:    `if (ctx.tool === "gitlab_create_merge") { throw new Error("no"); }`,
			tools:     nil,
			wantWarns: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, buf := newWarnTestGate(t, tt.policy)

			g.WarnUnknownToolRefs(tt.tools)
			out := buf.String()

			if got := strings.Count(out, warnMsgMarker); got != len(tt.wantWarns) {
				t.Fatalf("expected %d warnings, got %d. Output:\n%s", len(tt.wantWarns), got, out)
			}
			for _, lit := range tt.wantWarns {
				if !strings.Contains(out, `"literal":"`+lit+`"`) {
					t.Errorf("expected warning for literal %q, got: %s", lit, out)
				}
				if !strings.Contains(out, `"policy":"`+testPolicyFile+`"`) {
					t.Errorf("warning should reference the policy file, got: %s", out)
				}
			}
			for lit, want := range tt.wantSuggest {
				if !strings.Contains(out, want) {
					t.Errorf("warning for %q should suggest %q, got: %s", lit, want, out)
				}
			}
		})
	}
}

func TestScanStringLiterals(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "plain strings",
			src:  `var a = "one"; var b = 'two';`,
			want: []string{"one", "two"},
		},
		{
			name: "line comment skipped",
			src:  "// \"nope\"\nvar a = \"yes\";",
			want: []string{testLitYes},
		},
		{
			name: "block comment skipped",
			src:  `/* "nope" */ var a = "yes";`,
			want: []string{testLitYes},
		},
		{
			name: "regex literal with quotes does not derail the scanner",
			src:  `var re = /["']/; var a = "yes";`,
			want: []string{testLitYes},
		},
		{
			name: "division is not treated as a regex",
			src:  `var a = b / c; var d = "yes";`,
			want: []string{testLitYes},
		},
		{
			name: "escaped quote stays inside the literal",
			src:  `var a = "with \" quote"; var b = "next";`,
			want: []string{`with \" quote`, "next"},
		},
		{
			name: "template literal is captured",
			src:  "var a = `tpl_value`;",
			want: []string{"tpl_value"},
		},
		{
			name: "unterminated string does not panic",
			src:  `var a = "open`,
			want: []string{"open"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lits := scanStringLiterals(tt.src)
			got := make([]string, 0, len(lits))
			for _, l := range lits {
				got = append(got, l.value)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("scanStringLiterals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToolNameCandidates(t *testing.T) {
	prefixes := map[string]bool{"gitlab": true}

	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "identifier comparison",
			src:  `if (tool === "anything") {}`,
			want: []string{"anything"},
		},
		{
			name: "property comparison",
			src:  `if (ctx.tool !== "foo") {}`,
			want: []string{"foo"},
		},
		{
			name: "reversed operands",
			src:  `if ("bar" == tool) {}`,
			want: []string{"bar"},
		},
		{
			name: "switch case on tool",
			src:  `switch (ctx.tool) { case "baz": break; }`,
			want: []string{"baz"},
		},
		{
			name: "case in a switch on something else is ignored",
			src:  `switch (kind) { case "baz": break; }`,
			want: nil,
		},
		{
			name: "tool-shaped literal with known prefix",
			src:  `var l = ["gitlab_x_y"];`,
			want: []string{"gitlab_x_y"},
		},
		{
			name: "tool-shaped literal with unknown prefix is ignored",
			src:  `var l = ["acme_x_y"];`,
			want: nil,
		},
		{
			name: "toolAccess comparison is not a tool comparison",
			src:  `if (ctx.toolAccess === "read") {}`,
			want: nil,
		},
		{
			name: "duplicate literal reported once",
			src:  `if (tool === "dup" || tool === "dup") {}`,
			want: []string{"dup"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toolNameCandidates(tt.src, prefixes)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toolNameCandidates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloseMatches(t *testing.T) {
	tools := []string{
		testToolCreateMR,
		testToolCreateFile,
		"gitlab_update_file",
		"gitlab_delete_file",
		"echo_echo",
	}

	tests := []struct {
		name      string
		literal   string
		wantFirst string
		wantLen   int
	}{
		{
			name:      "prefix extension ranks first",
			literal:   testLiteralWrongTool,
			wantFirst: testToolCreateMR,
			wantLen:   1,
		},
		{
			name:      "typo within edit distance is suggested",
			literal:   "gitlab_creat_file",
			wantFirst: testToolCreateFile,
			wantLen:   1,
		},
		{
			name:    "no similar names yields no suggestions",
			literal: "zzz_nothing_alike",
			wantLen: 0,
		},
		{
			name:    "suggestions are capped at the limit",
			literal: "gitlab_",
			wantLen: maxCloseMatches,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := closeMatches(tt.literal, tools, maxCloseMatches)
			if len(got) != tt.wantLen {
				t.Fatalf("closeMatches(%q) = %v, want %d entries", tt.literal, got, tt.wantLen)
			}
			if tt.wantFirst != "" && got[0] != tt.wantFirst {
				t.Errorf("closeMatches(%q)[0] = %q, want %q", tt.literal, got[0], tt.wantFirst)
			}
		})
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{testLitABC, testLitABC, 0},
		{testLitABC, "", 3},
		{"", testLitABC, 3},
		{"gitlab_creat_file", "gitlab_create_file", 1},
		{"kitten", "sitting", 3},
	}

	for _, tt := range tests {
		if got := levenshtein(tt.a, tt.b); got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// toolRefRecorderEval is an Evaluator that records WarnUnknownToolRefs calls.
type toolRefRecorderEval struct {
	calls [][]string
}

func (e *toolRefRecorderEval) Name() string { return "tool-ref-recorder" }

func (e *toolRefRecorderEval) Evaluate(_ GateContext) (*EvalResult, error) {
	return &EvalResult{Allowed: true}, nil
}

func (e *toolRefRecorderEval) WarnUnknownToolRefs(registeredTools []string) {
	e.calls = append(e.calls, registeredTools)
}

// plainEval is an Evaluator that does not implement ToolRefWarner.
type plainEval struct{}

func (plainEval) Name() string { return "plain" }

func (plainEval) Evaluate(_ GateContext) (*EvalResult, error) {
	return &EvalResult{Allowed: true}, nil
}

func TestPipeline_WarnUnknownToolRefs_ForwardsToWarners(t *testing.T) {
	rec := &toolRefRecorderEval{}
	p := NewPipeline([]Evaluator{plainEval{}, rec})

	tools := []string{"gitlab_create_merge_request"}
	p.WarnUnknownToolRefs(tools)

	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 forwarded call, got %d", len(rec.calls))
	}
	if !reflect.DeepEqual(rec.calls[0], tools) {
		t.Errorf("forwarded tools = %v, want %v", rec.calls[0], tools)
	}
}
