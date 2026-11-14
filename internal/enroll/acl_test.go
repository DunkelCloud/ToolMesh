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
	"bytes"
	"context"
	"errors"
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Fixtures of the tests of a limit stored with an account.
const (
	tScope       = "MAIL_SCOPE"
	tFieldACL    = "a." + tScope
	tFieldRemove = "x." + tScope
	tInbox       = `{"mailboxes":["INBOX"]}`
	tProjects    = `{"mailboxes":["Projects/*"],"send":false}`
	tAuditValue  = "value:" + tScopeLower
	tAuditGone   = "removed"
	tNoneShown   = `ACL: <span class="status">none</span>`
	tScopeLower  = "mail_scope"
	tNotAnObject = "ACL: the value must be one JSON object"
)

// newACLPage is a page whose backend takes a limit besides the two
// secrets; optional says whether an account may go without it.
func newACLPage(t *testing.T, optional bool) (*page, *browser, string) {
	t.Helper()
	p := newPage(t, tOrigin)
	p.limit = &backend.UserCredential{Name: tScopeLower, Label: "ACL", Hint: "What an agent reaches with this account.", Format: backend.UserCredentialFormatACL, Optional: optional}
	b := p.newBrowser()
	return p, b, b.signIn(tAlice, tPassword)
}

// with returns form with one more field.
func with(form url.Values, field, value string) url.Values {
	form.Set(field, value)
	return form
}

// aclChange changes only the limit of the test account.
func aclChange(token, field, value string) url.Values {
	return url.Values{tFieldTok: {token}, tFieldBE: {tBackend}, tFieldLbl: {tAccount}, field: {value}}
}

// shownACL is how the page lists a stored limit.
func shownACL(value string) string {
	return "ACL: <code>" + html.EscapeString(value) + "</code>"
}

// TestPage_ACL_StoredShownAndAudited is the limit on the page: it is
// stored in a compact form, shown again, named in the audit entry, and the
// secrets next to it stay hidden.
func TestPage_ACL_StoredShownAndAudited(t *testing.T) {
	p, b, token := newACLPage(t, true)

	form := b.get().Body.String()
	for _, want := range []string{`name="` + tFieldACL + `"`, `name="` + tFieldRemove + `"`, "ACL (optional)", "What an agent reaches with this account.", "It is not a secret"} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q", want)
		}
	}

	out := b.submit(tSavePath, with(saveForm(token), tFieldACL, " {\n \"mailboxes\": [ \"INBOX\" ]\n} "))
	if out.kind != noticeOK {
		t.Fatalf("save with a limit: notice %q (%s)", out.notice, out.kind)
	}
	if got, err := p.stored(tScope); err != nil || got != tInbox {
		t.Fatalf("stored limit = %q, %v, want %q", got, err, tInbox)
	}
	if !strings.Contains(out.body, shownACL(tInbox)) {
		t.Errorf("the page does not show the stored limit:\n%s", out.body)
	}
	if strings.Contains(out.body, tSecret) || strings.Contains(out.body, tPinValue) {
		t.Error("the page shows a secret")
	}
	e := p.audit.last(t)
	if e.Status != statusSuccess || e.Metadata[tAuditValue] != tInbox || !strings.Contains(e.Metadata["credentials"], tScopeLower) {
		t.Errorf("audit entry = %+v, want the limit under %q", e, tAuditValue)
	}
	for key, value := range e.Metadata {
		if strings.Contains(value, tSecret) || strings.Contains(value, tPinValue) {
			t.Errorf("audit metadata %q carries a secret", key)
		}
	}
	if strings.Contains(p.logs.String(), "INBOX") {
		t.Error("the log carries the limit; it belongs into the audit entry only")
	}

	// A change of the limit alone keeps the secrets, drops the session of
	// the account and is audited with the new value.
	forgets := p.forgets()
	out = b.submit(tSavePath, aclChange(token, tFieldACL, tProjects))
	if out.kind != noticeOK || !strings.Contains(out.body, shownACL(tProjects)) || strings.Contains(out.body, shownACL(tInbox)) {
		t.Fatalf("change of the limit: notice %q (%s)\n%s", out.notice, out.kind, out.body)
	}
	if got, _ := p.stored(tScope); got != tProjects {
		t.Errorf("stored limit = %q, want %q", got, tProjects)
	}
	if got, err := p.stored(tPin); err != nil || got != tPinValue {
		t.Errorf("the pin after a change of the limit = %q, %v", got, err)
	}
	if p.forgets() == forgets {
		t.Error("the backend was not told to drop the session: the old limit would stay in force")
	}
	if e := p.audit.last(t); e.Metadata[tAuditValue] != tProjects || e.Metadata["credentials"] != tScopeLower {
		t.Errorf("audit entry of the change = %+v", e.Metadata)
	}

	// Removing the limit: the entry is gone, the secrets stay, the audit
	// says so.
	out = b.submit(tSavePath, aclChange(token, tFieldRemove, "1"))
	if out.kind != noticeOK || !strings.Contains(out.body, tNoneShown) {
		t.Fatalf("removal of the limit: notice %q (%s)\n%s", out.notice, out.kind, out.body)
	}
	if !strings.HasPrefix(out.notice, "Removed the ACL of the account "+tAccount+" for "+tBackend+".") || strings.Contains(out.notice, "Stored the account") {
		t.Errorf("the notice of a removal = %q, want it to say what was removed", out.notice)
	}
	if _, err := p.stored(tScope); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("after the removal: err = %v, want no limit stored", err)
	}
	if got, err := p.stored(tPin); err != nil || got != tPinValue {
		t.Errorf("the pin after the removal = %q, %v", got, err)
	}
	e = p.audit.last(t)
	if e.Metadata[tAuditGone] != tScopeLower || e.Metadata[tAuditValue] != "" {
		t.Errorf("audit entry of the removal = %+v", e.Metadata)
	}
	if !strings.Contains(out.body, `<span class="label">`+tAccount+`</span>`) || strings.Contains(out.body, "incomplete") {
		t.Errorf("the account without a limit is not listed as stored:\n%s", out.body)
	}
}

// TestPage_ACL_OptionalMayBeAbsent pins the account without a limit: it is
// whole, and the page says that it has none.
func TestPage_ACL_OptionalMayBeAbsent(t *testing.T) {
	p, b, token := newACLPage(t, true)
	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeOK {
		t.Fatalf("save without a limit: notice %q (%s)", out.notice, out.kind)
	}
	if !strings.Contains(out.body, tNoneShown) || strings.Contains(out.body, "incomplete") {
		t.Errorf("the page does not list the account as stored without a limit:\n%s", out.body)
	}
	if e := p.audit.last(t); e.Metadata[tAuditValue] != "" || e.Metadata[tAuditGone] != "" || strings.Contains(e.Metadata["credentials"], tScopeLower) {
		t.Errorf("audit entry = %+v, want nothing about a limit", e.Metadata)
	}
	// Removing what is not there changes nothing: no write, no check, no
	// audit entry that claims a removal.
	checks, entries, forgets := p.checks(), p.audit.count(), p.forgets()
	out = b.submit(tSavePath, aclChange(token, tFieldRemove, "1"))
	if out.kind != noticeWarn || !strings.Contains(out.notice, "Nothing was changed") {
		t.Errorf("removal of a limit that is not stored: notice %q (%s)", out.notice, out.kind)
	}
	if p.checks() != checks || p.audit.count() != entries || p.forgets() != forgets {
		t.Errorf("the removal of nothing reached the backend or the audit: checks %d, audit entries %d, forgets %d", p.checks()-checks, p.audit.count()-entries, p.forgets()-forgets)
	}
}

// TestPage_ACL_Validation pins what the page refuses before anything is
// stored or checked.
func TestPage_ACL_Validation(t *testing.T) {
	p, b, token := newACLPage(t, true)
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{"a list", with(saveForm(token), tFieldACL, `["INBOX"]`), tNotAnObject},
		{"broken JSON", with(saveForm(token), tFieldACL, `{"mailboxes":`), tNotAnObject},
		{"plain words", with(saveForm(token), tFieldACL, "INBOX only"), tNotAnObject},
		{"too long", with(saveForm(token), tFieldACL, `{"m":"`+strings.Repeat("x", backend.MaxUserACLBytes)+`"}`), "longer than"},
		{"a value and its removal", with(with(saveForm(token), tFieldACL, tInbox), tFieldRemove, "1"), "either enter a value or remove the stored one"},
		{"a limit alone for a new account", aclChange(token, tFieldACL, tInbox), "Mailbox login is missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := b.submit(tSavePath, c.form)
			if out.kind != noticeError || !strings.Contains(out.notice, c.want) || !strings.Contains(out.notice, "Nothing was stored") {
				t.Fatalf("notice %q (%s), want an error with %q", out.notice, out.kind, c.want)
			}
			if strings.Contains(out.notice, "xxxxxxxx") || strings.Contains(out.notice, "INBOX only") {
				t.Errorf("the notice repeats what was entered: %q", out.notice)
			}
		})
	}
	// A removal for an account that does not exist is no change either.
	if out := b.submit(tSavePath, aclChange(token, tFieldRemove, "1")); out.kind != noticeWarn || !strings.Contains(out.notice, "Nothing was changed") {
		t.Errorf("a removal alone for a new account: notice %q (%s)", out.notice, out.kind)
	}
	if p.checks() != 0 || p.audit.count() != 0 {
		t.Errorf("checks %d, audit entries %d: a refused form reached the store", p.checks(), p.audit.count())
	}
	if _, err := p.stored(tLogin); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("after the refused forms: err = %v, want nothing stored", err)
	}
}

// TestPage_ACL_RefusedSaveOverAnUnreadableLimit pins what the review of
// this page found: an account whose limit cannot be read any more must not
// end up without one because an attempt to store it again was refused. The
// entry stays as it was, the account stays closed.
func TestPage_ACL_RefusedSaveOverAnUnreadableLimit(t *testing.T) {
	for name, form := range map[string]func(token string) url.Values{
		"the limit alone":              func(token string) url.Values { return aclChange(token, tFieldACL, tProjects) },
		"the limit with the secrets":   func(token string) url.Values { return with(saveForm(token), tFieldACL, tProjects) },
		"the removal of the limit":     func(token string) url.Values { return aclChange(token, tFieldRemove, "1") },
		"a secret next to the limit":   func(token string) url.Values { return pinChange(token, tChangedPin) },
		"the limit, restore failing":   func(token string) url.Values { return aclChange(token, tFieldACL, tProjects) },
		"the removal, restore failing": func(token string) url.Values { return aclChange(token, tFieldRemove, "1") },
	} {
		t.Run(name, func(t *testing.T) {
			p, b, token := newACLPage(t, true)
			if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
				t.Fatalf("save: %q", out.notice)
			}
			// The limit is sealed under a key that is gone.
			foreign, err := credentials.NewFileUserStore(p.dir, bytes.Repeat([]byte{8}, credentials.UserCredentialsKeyBytes))
			if err != nil {
				t.Fatal(err)
			}
			slot := credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: tAccount, Name: tScope}
			if err := foreign.PutUser(context.Background(), slot, tInbox); err != nil {
				t.Fatal(err)
			}
			reopened, err := credentials.NewFileUserStore(p.dir, tKey())
			if err != nil {
				t.Fatal(err)
			}
			p.store.FileUserStore = reopened

			failing := strings.HasSuffix(name, "restore failing")
			p.setCheck(backend.UserCheckRefused, "session login answered HTTP 403")
			if failing {
				p.store.failNextPut(2) // the save's write succeeds, the write that puts the earlier state back fails
			}
			out := b.submit(tSavePath, form(token))
			if out.kind != noticeError {
				t.Fatalf("notice %q (%s), want the refusal", out.notice, out.kind)
			}
			_, err = p.stored(tScope)
			if failing {
				// What cannot be put back is said, not hidden.
				if !strings.Contains(out.notice, "Putting the earlier state back failed") {
					t.Errorf("notice %q, want the failed rollback named", out.notice)
				}
				if e := p.audit.last(t); e.Status != statusError || !strings.Contains(e.Error, "putting the earlier state back failed") {
					t.Errorf("audit entry of the failed rollback = %+v", e)
				}
				return
			}
			if !errors.Is(err, credentials.ErrUserCredentialUnreadable) {
				t.Fatalf("the limit after the refused save: err = %v, want the earlier entry, still unreadable: the account would be open otherwise", err)
			}
			if strings.Contains(out.body, tNoneShown) || !strings.Contains(out.body, "can no longer be read") {
				t.Errorf("the page lists the account as one without a limit, or as usable:\n%s", out.body)
			}
			if got, err := p.stored(tPin); err != nil || got != tPinValue {
				t.Errorf("the pin after the refused save = %q, %v, want it untouched", got, err)
			}
		})
	}
}

// TestPage_ACL_ShowsOnlyALimit pins that the page shows a stored value only
// when it is what a limit is, one JSON object: with format acl put on the
// wrong entry, the secrets users stored under that name before must not
// appear on the page.
func TestPage_ACL_ShowsOnlyALimit(t *testing.T) {
	p, b, token := newACLPage(t, true)
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	slot := credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: tAccount, Name: tScope}
	for _, secret := range []string{"Basic YWxpY2U6c2VjcmV0", tSecret, `["not", "an", "object"]`} {
		if err := p.store.PutUser(context.Background(), slot, secret); err != nil {
			t.Fatal(err)
		}
		body := b.get().Body.String()
		if strings.Contains(body, html.EscapeString(secret)) || strings.Contains(body, secret) {
			t.Errorf("the page shows a stored value that is no limit: %q", secret)
		}
		if !strings.Contains(body, `ACL: <span class="status bad">stored, but it is not a limit: store it again</span>`) {
			t.Errorf("the page does not say that the stored value is no limit:\n%s", body)
		}
	}
}

// TestPage_ACL_AccountWithTheLimitOnly pins the listing of an account that
// holds a limit and none of its secrets: it is incomplete, and the limit is
// shown.
func TestPage_ACL_AccountWithTheLimitOnly(t *testing.T) {
	p, b, _ := newACLPage(t, true)
	slot := credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: tAccount, Name: tScope}
	if err := p.store.PutUser(context.Background(), slot, tInbox); err != nil {
		t.Fatal(err)
	}
	body := b.get().Body.String()
	if !strings.Contains(body, "incomplete, missing: Mailbox login, mail_pin") || !strings.Contains(body, shownACL(tInbox)) {
		t.Errorf("the page does not list the account as incomplete with its limit:\n%s", body)
	}
}

// TestPage_ACL_RequiredByTheOperator pins the entry without optional: an
// account needs the limit, the form offers no removal, and a forged
// removal does nothing.
func TestPage_ACL_RequiredByTheOperator(t *testing.T) {
	p, b, token := newACLPage(t, false)
	form := b.get().Body.String()
	if strings.Contains(form, tFieldRemove) || strings.Contains(form, "ACL (optional)") || !strings.Contains(form, `name="`+tFieldACL+`"`) {
		t.Errorf("the form of a required limit offers its removal, or lacks the field:\n%s", form)
	}
	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeError || !strings.Contains(out.notice, "ACL is missing. Nothing was stored.") {
		t.Fatalf("save without the required limit: notice %q (%s)", out.notice, out.kind)
	}
	if out := b.submit(tSavePath, with(saveForm(token), tFieldACL, tInbox)); out.kind != noticeOK {
		t.Fatalf("save with the limit: notice %q (%s)", out.notice, out.kind)
	}
	out = b.submit(tSavePath, aclChange(token, tFieldRemove, "1"))
	if out.kind != noticeError || !strings.Contains(out.notice, "Nothing was entered") {
		t.Errorf("forged removal of a required limit: notice %q (%s)", out.notice, out.kind)
	}
	if got, err := p.stored(tScope); err != nil || got != tInbox {
		t.Errorf("the required limit after the forged removal = %q, %v", got, err)
	}
}

// TestPage_ACL_RefusedLimitIsRolledBack pins what a refused check does to
// the limit: the earlier one is in force again, whether that was a value
// or none, and the notice says that the limit may be the reason.
func TestPage_ACL_RefusedLimitIsRolledBack(t *testing.T) {
	p, b, token := newACLPage(t, true)
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}

	// No limit before: none after.
	p.setCheck(backend.UserCheckRefused, "session login answered HTTP 403")
	out := b.submit(tSavePath, aclChange(token, tFieldACL, `{"mailboxes":["*"]}`))
	if out.kind != noticeError || !strings.Contains(out.notice, "They were not stored.") ||
		!strings.Contains(out.notice, "The API also refuses a limit that is not well-formed or that reaches further than this ToolMesh may.") {
		t.Fatalf("refused limit: notice %q (%s)", out.notice, out.kind)
	}
	if got, err := p.stored(tPin); err != nil || got != tPinValue {
		t.Errorf("the pin after a refused limit = %q, %v, want it untouched", got, err)
	}
	if _, err := p.stored(tScope); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("after a refused first limit: err = %v, want none stored", err)
	}
	if e := p.audit.last(t); e.Status != statusError || e.Metadata[tAuditValue] != `{"mailboxes":["*"]}` {
		t.Errorf("audit entry of the refused limit = %+v, want the error and the value that was tried", e)
	}

	// A limit before: the same one after a refused change and after a
	// refused removal.
	p.setCheck(backend.UserCheckAccepted, "")
	if out := b.submit(tSavePath, aclChange(token, tFieldACL, tInbox)); out.kind != noticeOK {
		t.Fatalf("save of a limit: %q", out.notice)
	}
	p.setCheck(backend.UserCheckRefused, "session login answered HTTP 400")
	for name, form := range map[string]url.Values{
		"change":  aclChange(token, tFieldACL, tProjects),
		"removal": aclChange(token, tFieldRemove, "1"),
	} {
		out := b.submit(tSavePath, form)
		if out.kind != noticeError {
			t.Errorf("refused %s: notice %q (%s)", name, out.notice, out.kind)
		}
		if got, err := p.stored(tScope); err != nil || got != tInbox {
			t.Errorf("after a refused %s: limit = %q, %v, want the earlier one", name, got, err)
		}
		if !strings.Contains(out.body, shownACL(tInbox)) {
			t.Errorf("after a refused %s the page does not show the earlier limit", name)
		}
	}

	// A refused save of secrets alone says nothing about limits.
	out = b.submit(tSavePath, pinChange(token, tChangedPin))
	if out.kind != noticeError || strings.Contains(out.notice, "limit") {
		t.Errorf("refused change of a secret: notice %q", out.notice)
	}
}

// TestPage_ACL_UnreadableLimit pins the page of an account whose limit is
// sealed under a key that is gone: the account is marked as not usable,
// and no value is shown for the limit.
func TestPage_ACL_UnreadableLimit(t *testing.T) {
	p, b, token := newACLPage(t, true)
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	foreign, err := credentials.NewFileUserStore(p.dir, bytes.Repeat([]byte{8}, credentials.UserCredentialsKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	slot := credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: tAccount, Name: tScope}
	if err := foreign.PutUser(context.Background(), slot, tInbox); err != nil {
		t.Fatal(err)
	}
	reopened, err := credentials.NewFileUserStore(p.dir, tKey())
	if err != nil {
		t.Fatal(err)
	}
	p.store.FileUserStore = reopened

	body := b.get().Body.String()
	if !strings.Contains(body, `ACL: <span class="status bad">stored, but it can no longer be read</span>`) || strings.Contains(body, "INBOX") {
		t.Errorf("the page does not mark the unreadable limit, or shows it:\n%s", body)
	}
	if !strings.Contains(body, "can no longer be read: store it again") {
		t.Errorf("the account with an unreadable limit is listed as usable:\n%s", body)
	}
}
