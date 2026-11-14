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

package enroll

import (
	"strings"
	"testing"
)

// TestPage_MailAddressesStayAsWritten pins the comments that keep a
// Cloudflare zone with "Email Address Obfuscation" from replacing the mail
// addresses on the page. Cloudflare shows a replaced address again with a
// script, and the page's policy runs none: an account label that is a mail
// address would be unreadable. Everything the page prints lies between the
// two comments, on the login form and on the page of a signed-in user.
func TestPage_MailAddressesStayAsWritten(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()

	check := func(what, body string, inside ...string) {
		t.Helper()
		off, on := strings.Index(body, string(emailOff)), strings.Index(body, string(emailOn))
		if off < 0 || on < off || strings.Count(body, string(emailOff)) != 1 || strings.Count(body, string(emailOn)) != 1 {
			t.Fatalf("%s: want one %s followed by one %s\n%s", what, emailOff, emailOn, body)
		}
		if main, end := strings.Index(body, "<main>"), strings.Index(body, "</main>"); off < main || on > end {
			t.Errorf("%s: the comments are not inside <main>", what)
		}
		for _, text := range inside {
			at := strings.Index(body, text)
			if at < off || at > on {
				t.Errorf("%s: %q is not between the comments (at %d, comments at %d and %d)", what, text, at, off, on)
			}
			if strings.Contains(body[:off], text) || strings.Contains(body[on:], text) {
				t.Errorf("%s: %q also appears outside the comments", what, text)
			}
		}
	}

	check("login form", b.get().Body.String(), `name="password"`)

	token := b.signIn(tAlice, tPassword)
	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	// The notice of the save and the list of accounts both name the label.
	check("page after a save", out.body, `<span class="label">`+tAccount+`</span>`, "Signed in as")
	check("page on reload", b.get().Body.String(), `<span class="label">`+tAccount+`</span>`)
}
