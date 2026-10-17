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

package grants

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// call sends a request to the approver API as the approver alice and
// decodes the JSON answer into out, when given.
func call(t *testing.T, h http.Handler, method, path, body string, out any) int {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testApproverKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: answer is not JSON: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func TestHTTP_RequiresApproverKey(t *testing.T) {
	env := newTestEnv(t)
	h := env.svc.Handler()
	for _, key := range []string{"", "not-an-approver-key"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, PathPrefix, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("key %q: status %d, WWW-Authenticate %q; want 401 with a Bearer challenge", key, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestHTTP_Lifecycle(t *testing.T) {
	env := newTestEnv(t)
	h := env.svc.Handler()
	id := env.request(t, testKitNetDiag, "2h").Grant.ID

	var list listView
	if code := call(t, h, http.MethodGet, PathPrefix, "", &list); code != http.StatusOK ||
		len(list.Pending) != 1 || len(list.Active) != 0 || list.Note == "" {
		t.Fatalf("GET /grants = %d %+v", code, list)
	}
	p := list.Pending[0]
	if p.ID != id || p.Description != "Network diagnosis (read-only)" || p.Reason != testReason || p.TTL != "2h" ||
		p.UserID != testUser || p.CallerID != testCaller || len(p.Grants) != 2 {
		t.Errorf("pending view = %+v", p)
	}

	var one singleView
	if code := call(t, h, http.MethodGet, PathPrefix+"/"+id, "", &one); code != http.StatusOK || one.ID != id || one.State != StatePending {
		t.Errorf("GET /grants/%s = %d %+v", id, code, one)
	}

	var bad map[string]string
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/approve", `{"ttl": "3h"}`, &bad); code != http.StatusBadRequest || bad[jsonKeyError] == "" {
		t.Errorf("approve longer than requested = %d %v, want 400", code, bad)
	}
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/approve", `not json`, &bad); code != http.StatusBadRequest {
		t.Errorf("approve with a body that is not JSON = %d, want 400", code)
	}

	var approved singleView
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/approve", `{"ttl": "1h"}`, &approved); code != http.StatusOK ||
		approved.State != StateActive || approved.TTL != "1h" || approved.ApprovedBy != testApprover {
		t.Fatalf("approve = %d %+v", code, approved)
	}
	if kits := heldWhole(t.Context(), env.svc, testCaller); len(kits) != 1 {
		t.Errorf("HeldKits after approval = %v", kits)
	}

	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/revoke", "", nil); code != http.StatusOK {
		t.Errorf("revoke = %d", code)
	}
	if code := call(t, h, http.MethodGet, PathPrefix+"/"+id, "", &bad); code != http.StatusNotFound {
		t.Errorf("GET after revoke = %d, want 404", code)
	}
}

func TestHTTP_Deny(t *testing.T) {
	env := newTestEnv(t)
	h := env.svc.Handler()
	id := env.request(t, testKitAdmin, "").Grant.ID
	var denied singleView
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/deny", "", &denied); code != http.StatusOK || denied.Warning != "Production systems." {
		t.Errorf("deny = %d %+v", code, denied)
	}
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/approve", "", nil); code != http.StatusNotFound {
		t.Errorf("approve after deny = %d, want 404", code)
	}
}

func TestHTTP_MethodAndStoreErrors(t *testing.T) {
	env := newTestEnv(t)
	if code := call(t, env.svc.Handler(), http.MethodDelete, PathPrefix+"/abc", "", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d, want 405", code)
	}
	cat := newTestCatalog()
	broken := New(Options{Store: failingStore{}, Kits: cat, Approvers: cat, Logger: env.svc.logger})
	var out map[string]string
	if code := call(t, broken.Handler(), http.MethodGet, PathPrefix, "", &out); code != http.StatusInternalServerError || strings.Contains(out[jsonKeyError], errStoreDown.Error()) {
		t.Errorf("store failure = %d %v, want 500 without the store's error text", code, out)
	}
}
