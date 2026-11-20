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
	"unicode/utf8"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

// clientNameRunes is how many characters of a client_name the login page
// shows.
const clientNameRunes = 80

// clientDisplayName returns the self-declared client_name of client as the
// login page shows it, or "" when nothing of it is left.
//
// The page sets the name between quotation marks, under a note that
// ToolMesh has not verified it, and the name is whatever the client sent.
// It must not be able to end that quotation and go on in the page's own
// voice, reorder the line or break it. So quotation marks of every script
// and what is drawn like one are dropped, as is every character that is not
// printed: controls, the bidirectional and other format characters,
// unassigned and private-use code points, invalid UTF-8. White space of any
// kind becomes single spaces, and the rest is cut to clientNameRunes
// characters.
func clientDisplayName(client *auth.OAuthClient) string {
	if client == nil {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case r == utf8.RuneError, !unicode.IsPrint(r), isQuotationMark(r):
			return -1
		}
		return r
	}, client.ClientName)
	name := strings.Join(strings.Fields(cleaned), " ")
	if r := []rune(name); len(r) > clientNameRunes {
		name = strings.TrimSpace(string(r[:clientNameRunes])) + "…"
	}
	return name
}

// isQuotationMark reports whether r is a quotation mark or is drawn like
// one: the characters with the Unicode property Quotation_Mark, and the
// accents, primes and modifier letters that pass for them.
func isQuotationMark(r rune) bool {
	if unicode.Is(unicode.Quotation_Mark, r) {
		return true
	}
	switch {
	case r == '`', r == 0x00B4, // grave and acute accent
		r >= 0x02B9 && r <= 0x02BD, r == 0x02EE, // modifier letter primes and apostrophes
		r >= 0x2032 && r <= 0x2037, r == 0x2057, // primes and reversed primes
		r == 0x3003: // ditto mark
		return true
	}
	return false
}
