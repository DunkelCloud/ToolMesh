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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Fixtures of the parser tests.
const (
	testCredB = "CREDENTIAL_B" //nolint:gosec // key name, not a credential
	testAlpha = "alpha"
	testBeta  = "beta"
)

func TestParseDotenv(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "plain pairs, comments and blank lines",
			input: "# comment\n\nCREDENTIAL_A=alpha\n   # indented comment\nCREDENTIAL_B=beta\n",
			want:  map[string]string{testCredA: testAlpha, testCredB: testBeta},
		},
		{
			name:  "sops dotenv output with an escaped line break",
			input: "#sops comment\nCREDENTIAL_KEY=-----BEGIN KEY-----\\nabc\\n-----END KEY-----\n",
			want:  map[string]string{"CREDENTIAL_KEY": "-----BEGIN KEY-----\nabc\n-----END KEY-----"},
		},
		{
			name:  "CRLF line endings and byte order mark",
			input: "\xEF\xBB\xBFCREDENTIAL_A=alpha\r\nCREDENTIAL_B=\"beta\"\r\n",
			want:  map[string]string{testCredA: testAlpha, testCredB: testBeta},
		},
		{
			name:  "export prefix and spaces around the equals sign",
			input: "export CREDENTIAL_A=alpha\nCREDENTIAL_B = beta \nexporter=x\n",
			want:  map[string]string{testCredA: testAlpha, testCredB: testBeta, "exporter": "x"},
		},
		{
			name:  "inline comment only after whitespace",
			input: "A=value # comment\nB=pa#ss\nC=#notacomment\nD= # only a comment\n",
			want:  map[string]string{"A": "value", "B": "pa#ss", "C": "#notacomment", "D": ""},
		},
		{
			name:  "equals sign inside the value",
			input: "A=key=value==\n",
			want:  map[string]string{"A": "key=value=="},
		},
		{
			name:  "single quotes are literal",
			input: `A='x\ny $HOME # not a comment "q"'` + "\n",
			want:  map[string]string{"A": `x\ny $HOME # not a comment "q"`},
		},
		{
			name:  "double quotes with escapes",
			input: `A="line1\nline2\ttab \"quoted\" back\\slash \$HOME \q"` + "\n",
			want:  map[string]string{"A": "line1\nline2\ttab \"quoted\" back\\slash $HOME \\q"},
		},
		{
			name:  "comment after the closing quote",
			input: `A="value with # hash" # comment` + "\nB='v' #c\n",
			want:  map[string]string{"A": "value with # hash", "B": "v"},
		},
		{
			name:  "quoted values spanning lines",
			input: "A=\"first\nsecond\"\nB='one\r\ntwo'\nC=after\n",
			want:  map[string]string{"A": "first\nsecond", "B": "one\ntwo", "C": "after"},
		},
		{
			name:  "empty values",
			input: "A=\nB=\"\"\nC=''\n",
			want:  map[string]string{"A": "", "B": "", "C": ""},
		},
		{
			name:  "later line wins",
			input: "A=first\nA=second\n",
			want:  map[string]string{"A": "second"},
		},
		{
			name:  "reserved RELOAD_IN is parsed like any key",
			input: "RELOAD_IN=300\nCREDENTIAL_A=alpha\n",
			want:  map[string]string{"RELOAD_IN": "300", testCredA: testAlpha},
		},
		{
			name:  "no trailing newline",
			input: "A=alpha",
			want:  map[string]string{"A": testAlpha},
		},
		{
			name:  "empty input",
			input: "",
			want:  map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDotenv([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseDotenv: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseDotenv_Errors(t *testing.T) {
	const (
		secret     = "s3cr3t-value-never-in-errors" //nolint:gosec // test fixture, not a credential
		invalidKey = "line 1: invalid variable name"
	)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"line without equals sign", "A=ok\n" + secret + "\n", "line 2: expected KEY=value"},
		{"key starting with a digit", "1A=" + secret + "\n", invalidKey},
		{"key with a dash", "A-B=" + secret + "\n", invalidKey},
		{"empty key", "=" + secret + "\n", invalidKey},
		{"unterminated double quote", "A=ok\nB=\"" + secret + "\nC=x\n", "line 2: unterminated quoted value"},
		{"unterminated single quote", "B='" + secret + "\n", "line 1: unterminated quoted value"},
		{"text after the closing quote", "A=\"" + secret + "\"trailing\n", "line 1: unexpected text after the closing quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDotenv([]byte(tt.input))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q leaks the line content", err)
			}
		})
	}
}

// TestParseDotenv_EnvExample checks that the shipped .env.example parses:
// whatever an operator copied from it can go through the command store.
func TestParseDotenv_EnvExample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	vars, err := parseDotenv(data)
	if err != nil {
		t.Fatalf("parse .env.example: %v", err)
	}
	if got := vars["CREDENTIAL_STORE"]; got != "embedded" {
		t.Errorf("CREDENTIAL_STORE = %q, want embedded", got)
	}
}
