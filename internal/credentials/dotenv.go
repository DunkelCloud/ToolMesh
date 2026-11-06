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
	"bytes"
	"fmt"
	"strings"
)

// utf8BOM is the UTF-8 byte order mark, which an editor may put in front of
// a file; it is not part of the first key.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// parseDotenv reads KEY=value lines as written by `sops -d --output-type
// dotenv` and by hand in a .env file:
//
//   - Blank lines and lines starting with # are skipped; a leading "export "
//     is ignored.
//   - Keys are environment variable names ([A-Za-z_][A-Za-z0-9_]*).
//   - Unquoted values are trimmed, end at a # preceded by a space or tab, and
//     take \n as a line break (the way sops writes multi-line values). No
//     other escapes apply.
//   - Single-quoted values are literal. Double-quoted values know the escapes
//     \n, \r, \t, \", \\ and \$; other backslashes stay as they are. Both may
//     span lines, and a comment may follow the closing quote.
//   - Variables are not expanded. A later line wins over an earlier one with
//     the same key.
//
// Errors name the line but never its content, which may be a secret.
func parseDotenv(data []byte) (map[string]string, error) {
	text := string(bytes.TrimPrefix(data, utf8BOM))
	lines := strings.Split(text, "\n")
	vars := make(map[string]string)

	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimLeft(strings.TrimSuffix(lines[i], "\r"), " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimLeft(rest, " \t")
		}

		key, raw, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("line %d: expected KEY=value", lineNo)
		}
		key = strings.TrimRight(key, " \t")
		if !validEnvName(key) {
			return nil, fmt.Errorf("line %d: invalid variable name", lineNo)
		}

		value := strings.TrimLeft(raw, " \t")
		if value == "" || (value[0] != '"' && value[0] != '\'') {
			vars[key] = unquotedValue(raw)
			continue
		}

		quote := value[0]
		body := value[1:]
		for {
			end := closingQuote(body, quote)
			if end >= 0 {
				rest := strings.TrimLeft(body[end+1:], " \t")
				if rest != "" && rest[0] != '#' {
					return nil, fmt.Errorf("line %d: unexpected text after the closing quote", lineNo)
				}
				body = body[:end]
				break
			}
			if i+1 >= len(lines) {
				return nil, fmt.Errorf("line %d: unterminated quoted value", lineNo)
			}
			i++
			body += "\n" + strings.TrimSuffix(lines[i], "\r")
		}
		if quote == '"' {
			body = unescapeDoubleQuoted(body)
		}
		vars[key] = body
	}
	return vars, nil
}

// unquotedValue cuts an inline comment off an unquoted value, trims it and
// turns \n into a line break. raw is everything after the equals sign.
func unquotedValue(raw string) string {
	for j := 1; j < len(raw); j++ {
		if raw[j] == '#' && (raw[j-1] == ' ' || raw[j-1] == '\t') {
			raw = raw[:j]
			break
		}
	}
	return strings.ReplaceAll(strings.Trim(raw, " \t"), `\n`, "\n")
}

// closingQuote returns the index of the quote that ends body, or -1. Inside
// double quotes a backslash escapes the next character.
func closingQuote(body string, quote byte) int {
	for j := 0; j < len(body); j++ {
		switch body[j] {
		case quote:
			return j
		case '\\':
			if quote == '"' {
				j++
			}
		}
	}
	return -1
}

// unescapeDoubleQuoted resolves the escapes of a double-quoted value.
func unescapeDoubleQuoted(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for j := 0; j < len(s); j++ {
		if s[j] != '\\' || j+1 == len(s) {
			b.WriteByte(s[j])
			continue
		}
		j++
		switch s[j] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"', '\\', '$':
			b.WriteByte(s[j])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[j])
		}
	}
	return b.String()
}

// validEnvName reports whether s is a portable environment variable name.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for j := 0; j < len(s); j++ {
		c := s[j]
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && j > 0:
		default:
			return false
		}
	}
	return true
}
