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

package mcp

import (
	"strings"
	"unicode"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

const (
	// clientNameRunes is how many characters of a client_name the login
	// page shows.
	clientNameRunes = 80
	// clientNameMarks is how many combining marks may follow one letter
	// or digit. Writing systems need one or two; a stack of them draws
	// over the lines above and below.
	clientNameMarks = 2
	// clientNamePunctuation is the punctuation a client name keeps.
	clientNamePunctuation = "-_.,()+&/:@#!"
)

// clientDisplayName returns the self-declared client_name of client as the
// login page shows it, or "" when nothing of it is left.
//
// The name is whatever the client sent, and the page shows it next to its
// own statements, under a note that ToolMesh has not verified it. The page
// sets it apart in a box of its own; this function keeps to what a name is
// made of, so that nothing in it can pass for a mark of the page: letters
// and digits of any script, combining marks on them (clientNameMarks at
// most), single spaces, and the punctuation of clientNamePunctuation.
// Everything else is dropped: quotation marks and what is drawn like one,
// dashes and other symbols, controls, the bidirectional and other format
// characters, letters that are drawn as a blank, unassigned and private-use
// code points, invalid UTF-8. A list of characters to remove would always
// miss one; a list of characters to keep cannot. The result is cut to
// clientNameRunes characters.
func clientDisplayName(client *auth.OAuthClient) string {
	if client == nil {
		return ""
	}
	var b strings.Builder
	space := false // a space is owed before the next character
	marks := -1    // combining marks on the last letter or digit; -1 when none may follow
	for _, r := range client.ClientName {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			marks = -1
			continue
		case unicode.IsMark(r):
			if marks < 0 || marks >= clientNameMarks || isQuoteLike(r) {
				continue
			}
			marks++
			b.WriteRune(r)
			continue
		case (unicode.IsLetter(r) || unicode.IsNumber(r)) && !isBlankLetter(r) && !isQuoteLike(r):
			marks = 0
		case r < unicode.MaxASCII && strings.ContainsRune(clientNamePunctuation, r):
			marks = -1
		default:
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	name := b.String()
	if r := []rune(name); len(r) > clientNameRunes {
		name = strings.TrimSpace(string(r[:clientNameRunes])) + "…"
	}
	return name
}

// isBlankLetter reports whether r is a letter that is drawn as empty space:
// the Hangul fillers. A run of them pushes what follows out of sight or
// onto a line of its own.
func isBlankLetter(r rune) bool {
	switch r {
	case 0x115F, 0x1160, 0x3164, 0xFFA0:
		return true
	}
	return false
}

// isQuoteLike reports whether r is a letter or combining mark that is drawn
// like a quotation mark: the modifier letters for primes and apostrophes,
// the halfwidth sound marks, and the combining double accents, which after
// a letter look like a mark closing a quotation. The quotation marks
// themselves are punctuation or symbols and never kept.
func isQuoteLike(r rune) bool {
	if unicode.Is(unicode.Quotation_Mark, r) {
		return true
	}
	switch {
	case r >= 0x02B9 && r <= 0x02BF, r >= 0x02C8 && r <= 0x02CF, r == 0x02EE, // modifier primes, apostrophes, accents
		r == 0xFF9E, r == 0xFF9F, // halfwidth sound marks
		r == 0x030B, r == 0x030E, r == 0x030F: // combining double accents
		return true
	}
	return false
}
