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

import "strings"

// A policy declares how it relates to ToolMesh with directives in its header
// comment: the comment lines (// or /* */) and blank lines at the top of the
// file, before the first line of code. A directive is a comment line of the
// form
//
//	// toolmesh: enforce-with-kit
//
// with one or more names after the colon, separated by commas or spaces.
// The same text elsewhere in the file is prose and ignored.
const (
	// directivePrefix introduces a directive line.
	directivePrefix = "toolmesh:"
	// DirectiveEnforceWithKit declares that the policy runs in the
	// pre-execution phase even when a kit the caller holds covers the tool.
	// Without it a policy yields to the kit: an approver granted the call,
	// so the policy is skipped. Meant for parameter filters and conditions
	// that narrow what a scope allows, which hold for a kit's holder too.
	DirectiveEnforceWithKit = "enforce-with-kit"
)

// directives is what a policy's header comment declares.
type directives struct {
	enforceWithKit bool
	// unknown lists directive names the gate does not know, for a warning
	// at startup: a misspelled directive would otherwise be silent.
	unknown []string
}

// parseDirectives reads the directives of a policy's header comment.
func parseDirectives(src string) directives {
	var d directives
	for _, line := range headerCommentLines(src) {
		rest, ok := strings.CutPrefix(line, directivePrefix)
		if !ok {
			continue
		}
		for _, name := range strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			switch name {
			case DirectiveEnforceWithKit:
				d.enforceWithKit = true
			default:
				d.unknown = append(d.unknown, name)
			}
		}
	}
	return d
}

// headerCommentLines returns the text of the comment lines at the top of a
// policy source, each trimmed of its comment markers and surrounding space,
// up to the first line that holds code. The lines of a block comment are
// returned one by one, as in the file.
func headerCommentLines(src string) []string {
	var out []string
	inBlock := false
	for line := range strings.SplitSeq(src, "\n") {
		text := strings.TrimSpace(line)
		switch {
		case inBlock || strings.HasPrefix(text, "/*"):
			body, rest, ended := strings.Cut(strings.TrimPrefix(text, "/*"), "*/")
			out = append(out, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body), "*")))
			inBlock = !ended
			if ended && strings.TrimSpace(rest) != "" {
				return out // code follows the comment on the same line
			}
		case text == "":
			// Blank lines do not end the header.
		case strings.HasPrefix(text, "//"):
			out = append(out, strings.TrimSpace(strings.TrimPrefix(text, "//")))
		default:
			return out
		}
	}
	return out
}
