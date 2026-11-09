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

package credentials

import (
	"errors"
	"reflect"
	"testing"
)

// testCmd is the program name in the splitting tests.
const testCmd = "cmd"

func TestSplitCommandLine(t *testing.T) {
	tests := []struct {
		line string
		want []string
	}{
		{"/usr/local/bin/sops -d --output-type dotenv /run/secrets/toolmesh.env",
			[]string{"/usr/local/bin/sops", "-d", "--output-type", "dotenv", "/run/secrets/toolmesh.env"}},
		{"  cmd\t a   b  ", []string{testCmd, "a", "b"}},
		{`cmd 'a b' "c d"`, []string{testCmd, "a b", "c d"}},
		{`cmd 'a|b>c;$HOME'`, []string{testCmd, "a|b>c;$HOME"}},
		{`cmd "say \"hi\" \\ \$5 \x"`, []string{testCmd, `say "hi" \ $5 \x`}},
		{`cmd a\ b \| x\$`, []string{testCmd, "a b", "|", "x$"}},
		{`cmd pre'mid'"post"`, []string{testCmd, "premidpost"}},
		{`cmd '' ""`, []string{testCmd, "", ""}},
		{"cmd a#b", []string{testCmd, "a#b"}},
		{"cmd --flag=value key=value", []string{testCmd, "--flag=value", "key=value"}},
		{"cmd a \\\nb", []string{testCmd, "a", "b"}},
		{`'C:\Program Files\tool.exe' run`, []string{`C:\Program Files\tool.exe`, "run"}},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got, err := splitCommandLine(tt.line)
			if err != nil {
				t.Fatalf("splitCommandLine: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitCommandLine_Errors(t *testing.T) {
	tests := []struct {
		line  string
		shell bool // refused as shell syntax
	}{
		{"sops -d secrets.env | grep CREDENTIAL", true},
		{"sops -d secrets.env > out", true},
		{"sops -d < secrets.env", true},
		{"cmd1; cmd2", true},
		{"cmd1 && cmd2", true},
		{"cmd &", true},
		{"sops -d $SECRETS_FILE", true},
		{`sops -d "$SECRETS_FILE"`, true},
		{"cmd `whoami`", true},
		{"cmd $(whoami)", true},
		{"cmd # comment", true},
		{"SOPS_AGE_KEY_FILE=/key sops -d f", true},
		{"cmd 'unterminated", false},
		{`cmd "unterminated`, false},
		{`cmd trailing\`, false},
		{"", false},
		{"   \t ", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			_, err := splitCommandLine(tt.line)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, errShellSyntax); got != tt.shell {
				t.Errorf("errors.Is(err, errShellSyntax) = %v, want %v (err: %v)", got, tt.shell, err)
			}
		})
	}
}
