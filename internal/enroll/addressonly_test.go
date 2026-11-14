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
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const (
	// tOwn is the address of a page that has one of its own.
	tOwn = "https://credentials.internal.example:8444"
	// tOwnPlain is that host reached over plain http.
	tOwnPlain    = "http://credentials.internal.example:8444"
	tOriginUnset = "-" // a request without an Origin header
)

// ownAddressPage is a page that is at tOwn and nowhere else.
func ownAddressPage(t *testing.T) http.Handler {
	t.Helper()
	store, err := credentials.NewFileUserStore(t.TempDir(), tKey())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{
		Store:       store,
		Backends:    func() []Backend { return nil },
		Auth:        &fakeAuth{passwords: map[string]string{tAlice: tPassword}},
		Key:         tKey(),
		PublicURL:   tOwn,
		AddressOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc.Handler()
}

// TestPage_OwnAddress_OtherHostGetsNoPage pins that a page with an address
// of its own shows no form under another host name. What a user typed into
// such a form would travel the path that name leads over, and keeping
// passwords off such a path is what the page's own address is for.
func TestPage_OwnAddress_OtherHostGetsNoPage(t *testing.T) {
	h := ownAddressPage(t)
	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody))
		return rec
	}
	if rec := get(tOwn + Path); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Fatalf("GET at the page's address: %d\n%s", rec.Code, rec.Body.String())
	}
	for _, target := range []string{
		tOrigin + Path, // the address of the MCP endpoint
		"https://credentials.internal.example" + Path,  // the host without the port
		"https://10.0.0.5:8444" + Path,                 // the listener by its number
		tOrigin + Path + "/credentials.css",            // a file of the page
		"https://other.example:8444" + Path + "/login", // an endpoint of the page
	} {
		rec := get(target)
		body := rec.Body.String()
		if rec.Code != http.StatusMisdirectedRequest || strings.Contains(body, "<form") || strings.Contains(body, "password") {
			t.Errorf("GET %s = %d, want 421 without a form\n%s", target, rec.Code, body)
		}
		if !strings.Contains(body, tOwn+Path) {
			t.Errorf("GET %s: the answer does not name the page's address: %q", target, body)
		}
	}

	// A form under another name is turned away as well, whatever it says
	// about where it comes from.
	form := url.Values{tFieldName: {tAlice}, tFieldPW: {tPassword}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tOrigin+tLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(hFetchSite, tSameOrigin)
	req.Header.Set(hOrigin, tOrigin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest || len(rec.Result().Cookies()) != 0 {
		t.Errorf("sign-in under another host name = %d with %d cookies, want 421 and none", rec.Code, len(rec.Result().Cookies()))
	}
}

// TestPage_OwnAddress_FormsComeFromThatAddress pins that a page with an
// address of its own takes a form from that address only. The browser's
// verdict "same-origin" compares with the address the browser used; where
// the browser also says which address that was, it has to be the page's,
// scheme included.
func TestPage_OwnAddress_FormsComeFromThatAddress(t *testing.T) {
	cases := []struct {
		name         string
		site, origin string
		want         int
	}{
		{"verdict and the page's address", tSameOrigin, tOwn, http.StatusSeeOther},
		{"verdict alone", tSameOrigin, tOriginUnset, http.StatusSeeOther},
		{"verdict with an origin the browser withholds", tSameOrigin, originNull, http.StatusSeeOther},
		{"the page's address without a verdict", "", tOwn, http.StatusSeeOther},

		{"verdict, but from the MCP endpoint's address", tSameOrigin, tOrigin, http.StatusForbidden},
		{"verdict, but over plain http", tSameOrigin, tOwnPlain, http.StatusForbidden},
		{"verdict, but from the host without its port", tSameOrigin, "https://credentials.internal.example", http.StatusForbidden},
		{"verdict, but an origin that is no address", tSameOrigin, "credentials.internal.example:8444", http.StatusForbidden},
		{"another site", "cross-site", tOwn, http.StatusForbidden},
		{"same site, another origin", "same-site", tOwn, http.StatusForbidden},
		{"no verdict, another address", "", tOrigin, http.StatusForbidden},
		{"no verdict, plain http", "", tOwnPlain, http.StatusForbidden},
		{"nothing said", "", tOriginUnset, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := ownAddressPage(t)
			form := url.Values{tFieldName: {tAlice}, tFieldPW: {tPassword}}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, tOwn+tLoginPath, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.site != "" {
				req.Header.Set(hFetchSite, tc.site)
			}
			if tc.origin != tOriginUnset {
				req.Header.Set(hOrigin, tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("sign-in = %d, want %d", rec.Code, tc.want)
			}
			if signedIn := sessionCookieOf(rec) != nil; signedIn != (tc.want == http.StatusSeeOther) {
				t.Errorf("session cookie set = %v with status %d", signedIn, rec.Code)
			}
		})
	}
}

// TestNew_OwnAddressNeedsTheAddress pins that a page cannot be told to
// answer under its address only without being given that address: it would
// silently answer everywhere.
func TestNew_OwnAddressNeedsTheAddress(t *testing.T) {
	store, err := credentials.NewFileUserStore(t.TempDir(), tKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"", "not an address", "/credentials"} {
		_, err := New(Options{
			Store:       store,
			Backends:    func() []Backend { return nil },
			Auth:        &fakeAuth{passwords: map[string]string{}},
			Key:         tKey(),
			PublicURL:   addr,
			AddressOnly: true,
		})
		if err == nil {
			t.Errorf("New with AddressOnly and the address %q succeeded", addr)
		}
	}
}

// TestPage_WithoutOwnAddress_AnswersUnderEveryName pins the other side: a
// page on the main listener, with the public address of ToolMesh as its
// address, keeps answering under whatever name it is reached at, as an
// instance reached under several names needs it.
func TestPage_WithoutOwnAddress_AnswersUnderEveryName(t *testing.T) {
	p := newPage(t, tOrigin)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://toolmesh.internal.example"+Path, http.NoBody))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="password"`) {
		t.Errorf("GET under another name = %d, want the page", rec.Code)
	}
	b := p.newBrowser()
	b.base, b.origin, b.site = "https://toolmesh.internal.example", "https://toolmesh.internal.example", tSameOrigin
	if rec := b.post(tLoginPath, url.Values{tFieldName: {tAlice}, tFieldPW: {tPassword}}); rec.Code != http.StatusSeeOther {
		t.Errorf("sign-in under another name with the browser's verdict = %d, want it accepted", rec.Code)
	}
}
