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
	"regexp"
	"sort"
	"strings"
)

// ToolRefWarner is implemented by evaluators that can statically check their
// loaded policies against the registered tool names. A policy that branches
// on a tool name that does not exist is a silent no-op — it never fires and
// never errors — so surfacing likely dead branches at startup is the only
// chance to catch the mistake.
type ToolRefWarner interface {
	// WarnUnknownToolRefs logs a warning for every tool-name literal in a
	// loaded policy that matches none of registeredTools.
	WarnUnknownToolRefs(registeredTools []string)
}

// WarnUnknownToolRefs forwards the registered tool names to every evaluator
// in the pipeline that implements ToolRefWarner. Purely diagnostic: the
// evaluators log warnings, nothing is rejected or blocked.
func (p *Pipeline) WarnUnknownToolRefs(registeredTools []string) {
	for _, ev := range p.evaluators {
		if w, ok := ev.(ToolRefWarner); ok {
			w.WarnUnknownToolRefs(registeredTools)
		}
	}
}

// WarnUnknownToolRefs scans all loaded policy sources for string literals
// that look like tool names and logs one warning per literal that matches no
// registered tool name. This bug class has occurred twice (PR #72, and a
// policy checking "gitlab_create_merge" where the real tool is
// "gitlab_create_merge_request"), each time as a silent no-op. The scan is a
// text heuristic, so findings are warnings only and never block startup.
func (g *Gate) WarnUnknownToolRefs(registeredTools []string) {
	for _, ref := range g.unknownToolRefs(registeredTools) {
		attrs := []any{"policy", ref.policy, "literal", ref.literal}
		if len(ref.closeMatches) > 0 {
			attrs = append(attrs, "close_matches", ref.closeMatches)
		}
		g.logger.Warn("policy references unknown tool", attrs...)
	}
}

// unknownToolRef is a tool-name literal in a loaded policy that matches no
// registered tool.
type unknownToolRef struct {
	policy       string
	literal      string
	closeMatches []string
}

// unknownToolRefs cross-checks every loaded policy against the registered
// tool names. With an empty tool list the check is skipped entirely — there
// is nothing to validate against and every literal would be a false alarm.
func (g *Gate) unknownToolRefs(registeredTools []string) []unknownToolRef {
	if len(registeredTools) == 0 {
		return nil
	}

	registered := make(map[string]bool, len(registeredTools))
	prefixes := make(map[string]bool)
	for _, t := range registeredTools {
		registered[t] = true
		if i := strings.IndexByte(t, '_'); i > 0 {
			prefixes[t[:i]] = true
		}
	}

	var refs []unknownToolRef
	for _, p := range g.policies {
		for _, lit := range toolNameCandidates(p.source, prefixes) {
			if registered[lit] {
				continue
			}
			refs = append(refs, unknownToolRef{
				policy:       p.name,
				literal:      lit,
				closeMatches: closeMatches(lit, registeredTools, maxCloseMatches),
			})
		}
	}
	return refs
}

// toolNameShape matches literals that look like ToolMesh tool names:
// "<backend>_<tool>" in snake_case with at least one underscore.
var toolNameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*_[a-z0-9_-]+$`)

// Comparison-context patterns: a literal directly compared to a variable or
// property named "tool" (covers `ctx.tool === "x"`, `tool !== "x"`, and the
// reversed operand order), or a `case "x":` inside a `switch` on tool.
var (
	toolCmpBefore = regexp.MustCompile(`(?:^|[^\w$.])(?:[\w$]+\s*\.\s*)?tool\s*[!=]==?\s*$`)
	toolCmpAfter  = regexp.MustCompile(`^\s*[!=]==?\s*(?:[\w$]+\s*\.\s*)?tool\b`)
	caseBefore    = regexp.MustCompile(`(?:^|[^\w$])case\s+$`)
	switchOnTool  = regexp.MustCompile(`switch\s*\(\s*(?:[\w$]+\s*\.\s*)?tool\s*\)`)
)

// cmpWindow is how many bytes around a literal are inspected for a
// comparison with `tool`. Comparisons are syntactically adjacent, so a small
// window suffices.
const cmpWindow = 64

// toolNameCandidates returns the deduplicated tool-name literals referenced
// by a policy source. A literal qualifies when it is directly compared to a
// `tool` variable (any value), or when it merely looks like a tool name AND
// its backend prefix (the segment before the first underscore) matches a
// registered backend — the prefix filter keeps unrelated snake_case strings
// such as field names ("phone_number") out of the check.
func toolNameCandidates(source string, knownPrefixes map[string]bool) []string {
	var out []string
	seen := make(map[string]bool)
	for _, lit := range scanStringLiterals(source) {
		if lit.value == "" || seen[lit.value] {
			continue
		}
		if isToolComparison(source, lit) {
			seen[lit.value] = true
			out = append(out, lit.value)
			continue
		}
		if !toolNameShape.MatchString(lit.value) {
			continue
		}
		if i := strings.IndexByte(lit.value, '_'); i > 0 && knownPrefixes[lit.value[:i]] {
			seen[lit.value] = true
			out = append(out, lit.value)
		}
	}
	return out
}

// isToolComparison reports whether the literal is directly compared against
// a `tool` variable or property in the surrounding source.
func isToolComparison(src string, lit stringLiteral) bool {
	before := src[max(0, lit.start-cmpWindow):lit.start]
	after := src[lit.end:min(len(src), lit.end+cmpWindow)]
	if toolCmpBefore.MatchString(before) || toolCmpAfter.MatchString(after) {
		return true
	}
	return caseBefore.MatchString(before) && switchOnTool.MatchString(src)
}

// stringLiteral is one quoted string found in a policy source. start is the
// byte offset of the opening quote, end the offset just past the closing
// quote (or len(src) for an unterminated literal).
type stringLiteral struct {
	value string
	start int
	end   int
}

// scanStringLiterals extracts all string literals from JavaScript source,
// skipping line comments, block comments, and regular expression literals so
// quoted text inside them is not mistaken for code. The scanner is a
// heuristic, not a full parser: it tracks just enough state to keep the
// tool-name check free of comment and regex false positives.
func scanStringLiterals(src string) []stringLiteral {
	var lits []stringLiteral
	var lastCode byte // last significant byte seen outside comments/strings

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			i = skipLineComment(src, i+2)
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i = skipBlockComment(src, i+2)
		case c == '/' && regexCanFollow(lastCode):
			i = skipRegex(src, i+1)
			lastCode = '/'
		case c == '\'' || c == '"' || c == '`':
			value, next := scanQuoted(src, i)
			lits = append(lits, stringLiteral{value: value, start: i, end: next})
			i = next
			lastCode = c
		default:
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				lastCode = c
			}
			i++
		}
	}
	return lits
}

func skipLineComment(src string, i int) int {
	for i < len(src) && src[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(src string, i int) int {
	for i+1 < len(src) {
		if src[i] == '*' && src[i+1] == '/' {
			return i + 2
		}
		i++
	}
	return len(src)
}

// regexCanFollow reports whether a '/' at the current position starts a
// regex literal rather than a division, judged by the last significant byte.
// After an identifier, number, or closing bracket a '/' is division; after
// an operator, opening bracket, separator, or at the start of the file it
// can only start a regex literal.
func regexCanFollow(lastCode byte) bool {
	switch lastCode {
	case 0, '(', '[', '{', ',', ';', ':', '=', '!', '&', '|', '?', '+', '-', '*', '%', '<', '>', '~', '^':
		return true
	}
	return false
}

// skipRegex advances past a regex literal body starting just after the
// opening '/'. Character classes may contain an unescaped '/' that does not
// terminate the literal. A newline aborts the scan (regex literals cannot
// span lines), which limits the damage of a misdetected division.
func skipRegex(src string, i int) int {
	inClass := false
	for i < len(src) {
		switch src[i] {
		case '\\':
			i++ // skip the escaped byte
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if !inClass {
				return i + 1
			}
		case '\n':
			return i
		}
		i++
	}
	return i
}

// scanQuoted consumes a string literal starting at the opening quote and
// returns its raw (unescaped-as-written) value plus the offset just past the
// closing quote. An unterminated literal runs to the end of the source.
func scanQuoted(src string, start int) (value string, end int) {
	quote := src[start]
	for i := start + 1; i < len(src); i++ {
		switch src[i] {
		case '\\':
			i++ // skip the escaped byte
		case quote:
			return src[start+1 : i], i + 1
		}
	}
	return src[start+1:], len(src)
}

// maxCloseMatches caps how many suggestions a warning carries.
const maxCloseMatches = 3

// maxEditDistance is the highest Levenshtein distance still offered as a
// "did you mean" suggestion for non-prefix matches.
const maxEditDistance = 3

// closeMatches returns up to limit registered tool names similar to the
// literal. Names extending the literal (or vice versa) rank first — that is
// the historic failure mode, e.g. "gitlab_create_merge" written for
// "gitlab_create_merge_request" — followed by small-edit-distance typos.
func closeMatches(literal string, registeredTools []string, limit int) []string {
	type scored struct {
		name  string
		score int
	}
	var candidates []scored
	for _, t := range registeredTools {
		if strings.HasPrefix(t, literal) || strings.HasPrefix(literal, t) {
			diff := len(t) - len(literal)
			if diff < 0 {
				diff = -diff
			}
			candidates = append(candidates, scored{name: t, score: diff})
			continue
		}
		// Offset typo scores so any prefix relation always ranks above them.
		if d := levenshtein(literal, t); d <= maxEditDistance {
			candidates = append(candidates, scored{name: t, score: 100 + d})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		return candidates[i].name < candidates[j].name
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	names := make([]string, 0, len(candidates))
	for _, c := range candidates {
		names = append(names, c.name)
	}
	return names
}

// levenshtein computes the edit distance between two strings using the
// classic two-row dynamic program. Tool names are short, so the
// O(len(a)×len(b)) cost is negligible.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
