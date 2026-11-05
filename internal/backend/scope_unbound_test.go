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

package backend

import (
	"testing"
)

// TestNewRESTAdapter_NoScopeRefused pins that the binding fails closed: an
// adapter built without a Scope is refused unless the caller asks for an
// unbound one explicitly, so code that forgets the binding gets no
// backend that reads any credential and sends it anywhere.
func TestNewRESTAdapter_NoScopeRefused(t *testing.T) {
	spec := func() *RESTAdapterOptions { return &RESTAdapterOptions{AllowPrivateURL: true} }
	s := bindingSpec(scopeEntryName, "https://api.example.com", "/ping", "github_token")
	if _, err := NewRESTAdapter(s, &testCredStore{}, quietLogger(), *spec()); err == nil {
		t.Error("an adapter without Scope and without Unbound was built")
	}
	opts := spec()
	opts.Unbound = true
	if _, err := NewRESTAdapter(s, &testCredStore{}, quietLogger(), *opts); err != nil {
		t.Errorf("with Unbound: %v", err)
	}
	// With a Scope, Unbound changes nothing: the DADL reads a credential
	// outside the entry and is refused.
	opts.Scope = &BackendScope{EntryName: scopeEntryName}
	if _, err := NewRESTAdapter(s, &testCredStore{}, quietLogger(), *opts); err == nil {
		t.Error("Unbound lifted the binding of a Scope")
	}
}
