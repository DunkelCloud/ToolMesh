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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

// Characters of the client name tests, written as code points so that the
// source holds no invisible or direction-changing character.
const (
	cnLeftQuote  = "\U0000201c" // left double quotation mark
	cnRightQuote = "\U0000201d" // right double quotation mark
	cnDash       = "\U00002013" // en dash
	cnRLO        = "\U0000202e" // right-to-left override
	cnPDF        = "\U0000202c" // pop directional formatting
	cnEllipsis   = "\U00002026" // horizontal ellipsis
	cnAcute      = "\U00000301" // combining acute accent
	cnPlain      = "Claude"     // a name that needs no cleaning

	// cnEnclosed is a letter in an enclosing triangle, a keycap digit and a
	// letter with an emoji selector in an enclosing circle.
	cnEnclosed = "A\U000020e4 1\U0000fe0f\U000020e3 i\U0000fe0f\U000020dd"
)

// TestClientDisplayName pins what the login page shows of a client's
// self-declared name: what a name is made of, and nothing that could pass
// for a mark of the page, reorder the line or break it.
func TestClientDisplayName(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", cnPlain, cnPlain},
		{"other scripts stay", "Gr\U000000f6\U000000dfe \U00006771\U00004eac \U0000043a\U0000043b\U00000438\U00000435\U0000043d\U00000442",
			"Gr\U000000f6\U000000dfe \U00006771\U00004eac \U0000043a\U0000043b\U00000438\U00000435\U0000043d\U00000442"},
		{"prolonged sound mark stays", "\U000030b5\U000030fc\U000030d0\U000030fc", "\U000030b5\U000030fc\U000030d0\U000030fc"},
		{"decomposed accent stays", "Cafe" + cnAcute, "Cafe" + cnAcute},
		{"punctuation stays", "Acme (EU) - MCP/2.0 & Co.", "Acme (EU) - MCP/2.0 & Co."},
		{"ascii quotes", `Claude" - verified by ToolMesh. "x`, "Claude - verified by ToolMesh. x"},
		{"typographic quotes and dash", cnPlain + cnRightQuote + " " + cnDash + " verified. " + cnLeftQuote + "x", "Claude verified. x"},
		{"guillemets and corner brackets", "\U000000abA\U000000bb \U0000300cB\U0000300d \U0000201eC\U0000201c \U00002039D\U0000203a", "A B C D"},
		{"apostrophes and lookalikes", "it's `x` \U000000b4y \U00002032z \U000002bcw \U0000ff02v", "its x y z w v"},
		{"ornament quotes", cnPlain + "\U0000275e verified \U0000275d \U0001f676x\U0001f677", "Claude verified x"},
		{"quote-like letters and accents", "a\U000002dd b\U0000ff9e c\U0000030b d\U0000ff40", "a b c d"},
		{"brackets and other symbols", "[ok] <b>{x}</b> a|b c=d 100%\U00002713", "ok bx/b ab cd 100"},
		{"bidi controls", "evil" + cnRLO + "gnp.exe" + cnPDF + " \U00002066x\U00002069 \U0000200fy", "evilgnp.exe x y"},
		{"zero width and BOM", "Cl\U0000200bau\U0000200dde\U0000feff", cnPlain},
		{"control characters", "Cl\x00au\x1b[31mde\x7f", "Clau31mde"},
		{"line breaks and tabs", "Claude\r\n\tverified\U00002028by\U00002029ToolMesh", "Claude verified by ToolMesh"},
		{"other spaces", "  A\U000000a0B\U00003000C\U00002003D  ", "A B C D"},
		{"blank letters", "A\U00003164\U00003164B \U0000115f\U00002800 C", "AB C"},
		{"mark without a letter", cnAcute + "a " + cnAcute + "b", "a b"},
		{"stacked marks", "a" + strings.Repeat(cnAcute, 6) + "b", "a" + strings.Repeat(cnAcute, clientNameMarks) + "b"},
		{"enclosing marks and emoji selectors", cnEnclosed, "A 1 i"},
		{"invalid UTF-8", "Cl\xffau\xc3de", cnPlain},
		{"private use and unassigned", "A\U0000e000B\U000e0041C", "ABC"},
		{"only dropped characters", "\"" + cnRLO + "\U0000200b\x01'", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clientDisplayName(&auth.OAuthClient{ClientName: c.in}); got != c.want {
				t.Errorf("clientDisplayName(%+q) = %+q, want %+q", c.in, got, c.want)
			}
		})
	}
	if got := clientDisplayName(nil); got != "" {
		t.Errorf("nil client: %+q", got)
	}

	// The cut counts characters after cleaning, and the result never ends
	// in a space before the ellipsis.
	long := strings.Repeat(cnLeftQuote, 50) + strings.Repeat("ab ", 40)
	got := clientDisplayName(&auth.OAuthClient{ClientName: long})
	if n := len([]rune(got)); n > clientNameRunes+1 || !strings.HasSuffix(got, cnEllipsis) || strings.HasSuffix(got, " "+cnEllipsis) {
		t.Errorf("long name: %d characters, %+q", n, got)
	}
}

// TestAuthorize_LoginPageCleansClientName pins the page itself: a client
// name written to end a quotation and continue as a statement of ToolMesh
// arrives without its quotation marks and direction overrides, in an
// element of its own that isolates its direction, and the page states its
// charset. A client without a name is shown as such, in the page's words.
func TestAuthorize_LoginPageCleansClientName(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	page := func(name string) (string, http.Header) {
		t.Helper()
		// A limiter of its own, to keep the registration limit out of it.
		ts.srv.rateLimiter = auth.NewLocalDCRRateLimiter()
		clientID := registeredClientID(t, registerClient(t, ts.mux, name, consentEvilRedirect))
		q := url.Values{
			oauthClientID:      {clientID},
			oauthRedirectURI:   {consentEvilRedirect},
			oauthCodeChallenge: {testLoginChallenge},
			oauthState:         {"s1"},
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		return w.Body.String(), w.Header()
	}

	body, header := page(cnPlain + cnRightQuote + " " + cnDash + " verified by ToolMesh" + cnRLO + ". " + cnLeftQuote + "x")
	if want := `<p class="clientname"><bdi>Claude verified by ToolMesh. x</bdi></p>`; !strings.Contains(body, want) {
		t.Errorf("login page lacks the cleaned name in its own element: %s", want)
	}
	for _, not := range []string{cnRightQuote, cnLeftQuote, cnRLO, "&ldquo;", "&rdquo;"} {
		if strings.Contains(body, not) {
			t.Errorf("login page carries %+q", not)
		}
	}
	if ct := header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the charset stated", ct)
	}
	if !strings.Contains(body, `<meta charset="utf-8">`) {
		t.Error("login page lacks the charset declaration")
	}

	body, _ = page("\"" + cnRLO + "'")
	if !strings.Contains(body, `<p class="clientname none">no name given</p>`) || strings.Contains(body, "<bdi>") {
		t.Error("a name of which nothing is left is not shown as no name")
	}
}
