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
	"fmt"
	"strings"
)

// errShellSyntax explains why a shell feature is refused: the command runs
// without a shell (the container image has none).
var errShellSyntax = errors.New("the command runs without a shell, so pipes, redirections, command lists, variables, command substitution and comments are not supported; quote the character if it is meant literally")

// splitCommandLine splits a command line into arguments the way a POSIX shell
// splits words: spaces and tabs separate arguments, single quotes keep
// everything literal, double quotes keep everything but \", \\, \$ and \`,
// and a backslash outside quotes escapes the next character. Shell syntax
// that would need a shell to mean anything (| & ; < > ( ) $ `, a # that
// starts a word, a leading VAR=value) is an error rather than passed on as a
// literal argument. There is no globbing and no tilde expansion.
func splitCommandLine(line string) ([]string, error) {
	const (
		unquoted = iota
		inSingle
		inDouble
	)
	var (
		args  []string
		cur   strings.Builder
		inArg bool
		state = unquoted
	)
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch state {
		case inSingle:
			if r == '\'' {
				state = unquoted
			} else {
				cur.WriteRune(r)
			}
		case inDouble:
			switch r {
			case '"':
				state = unquoted
			case '\\':
				if i+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[i+1]) {
					i++
					cur.WriteRune(rs[i])
				} else {
					cur.WriteRune(r)
				}
			case '$', '`':
				return nil, fmt.Errorf("%q inside double quotes: %w", r, errShellSyntax)
			default:
				cur.WriteRune(r)
			}
		default:
			switch {
			case r == ' ' || r == '\t' || r == '\n' || r == '\r':
				if inArg {
					args = append(args, cur.String())
					cur.Reset()
					inArg = false
				}
			case r == '\'':
				state, inArg = inSingle, true
			case r == '"':
				state, inArg = inDouble, true
			case r == '\\':
				if i+1 >= len(rs) {
					return nil, errors.New("command line ends with a backslash")
				}
				i++
				if rs[i] == '\n' {
					continue // line continuation
				}
				cur.WriteRune(rs[i])
				inArg = true
			case strings.ContainsRune("|&;<>()$`", r), r == '#' && !inArg:
				return nil, fmt.Errorf("unquoted %q: %w", r, errShellSyntax)
			default:
				cur.WriteRune(r)
				inArg = true
			}
		}
	}
	if state != unquoted {
		return nil, errors.New("command line has an unterminated quote")
	}
	if inArg {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("command line is empty")
	}
	if name, _, ok := strings.Cut(args[0], "="); ok && validEnvName(name) {
		return nil, fmt.Errorf("leading variable assignment %q: %w", name+"=", errShellSyntax)
	}
	return args, nil
}
