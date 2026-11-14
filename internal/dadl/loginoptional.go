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

package dadl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Optional fields of a session login (auth.login.optional): a field of the
// login body whose credential may be absent. An API that takes a limit of
// the session at login, such as the calendars and mailboxes it may reach,
// gets that limit this way: with a value the field is sent, without one the
// login is the plain one.

// wholeCredentialRef returns the credential name when value is one
// credential reference and nothing else.
func wholeCredentialRef(value any) (string, bool) {
	ref, isString := value.(string)
	if !isString {
		return "", false
	}
	return strings.CutPrefix(ref, credentialPrefix)
}

// validateLoginOptional refuses an auth.login.optional that names something
// else than fields of the body's top level whose whole value is one
// credential reference, names a field twice, or stands in an auth block
// that is no session login.
func validateLoginOptional(auth AuthConfig) error {
	if auth.Login == nil || len(auth.Login.Optional) == 0 {
		return nil
	}
	if !strings.EqualFold(auth.Type, authTypeSession) {
		return fmt.Errorf("auth.login.optional is for auth.type %s; this auth block has type %q", authTypeSession, auth.Type)
	}
	seen := map[string]bool{}
	for _, field := range auth.Login.Optional {
		if seen[field] {
			return fmt.Errorf("auth.login.optional names %q twice", field)
		}
		seen[field] = true
		value, ok := auth.Login.Body[field]
		if !ok {
			return fmt.Errorf("auth.login.optional names %q, which is not a field of auth.login.body", field)
		}
		if _, isRef := wholeCredentialRef(value); !isRef {
			return fmt.Errorf("auth.login.optional names %q, whose value is not a credential reference (%q): only a field that carries one credential can be left out",
				field, credentialPrefix+"<name>")
		}
	}
	return nil
}

// IsSessionLogin reports whether the auth block logs in with a request of
// its own, whose body carries the credentials.
func (a AuthConfig) IsSessionLogin() bool {
	return strings.EqualFold(a.Type, authTypeSession) && a.Login != nil
}

// CanOmitCredential reports whether the login goes without the credential
// name when it has no value: the auth block is a session login that reads
// the name, and every place that reads it is a field auth.login.optional
// lists. A name that is also read where it cannot be left out is not one.
func (a AuthConfig) CanOmitCredential(name string) bool {
	if !a.IsSessionLogin() {
		return false
	}
	optional := map[string]bool{}
	for _, field := range a.Login.Optional {
		optional[field] = true
	}
	read, elsewhere := false, false
	for field, value := range a.Login.Body {
		if refName, isRef := wholeCredentialRef(value); isRef {
			if strings.EqualFold(refName, name) {
				read = true
				if !optional[field] {
					elsewhere = true
				}
			}
			continue
		}
		walkCredentialRefs(value, func(refName string) {
			if strings.EqualFold(refName, name) {
				read, elsewhere = true, true
			}
		})
	}
	return read && !elsewhere
}

// resolveLoginBody builds the body of the session login: the DADL's body
// with every credential reference replaced by its value. A field that
// auth.login.optional lists is left out when its credential is not there:
// the store has none of that name, or it is empty. Any other failure to
// read it fails the login, so that a limit which cannot be read is never
// taken for no limit. Only a field whose whole value is one credential
// reference is left out, whatever the list says: a spec built in code is
// not validated.
func (a *RestAuth) resolveLoginBody(ctx context.Context, tenant credentials.TenantInfo) (any, error) {
	login := a.config.Login
	if len(login.Optional) == 0 {
		return a.resolveLoginCredentials(ctx, login.Body, tenant)
	}
	optional := make(map[string]bool, len(login.Optional))
	for _, field := range login.Optional {
		if _, isRef := wholeCredentialRef(login.Body[field]); isRef {
			optional[field] = true
		}
	}
	out := make(map[string]any, len(login.Body))
	for field, value := range login.Body {
		resolved, err := a.resolveLoginCredentials(ctx, value, tenant)
		if err != nil {
			if optional[field] && errors.Is(err, credentials.ErrCredentialNotFound) {
				a.logger.Debug("session login goes without an optional field: its credential has no value", "field", field, "per_user", a.perUser)
				continue
			}
			return nil, err
		}
		if s, isString := resolved.(string); isString && s == "" && optional[field] {
			a.logger.Debug("session login goes without an optional field: its credential is empty", "field", field, "per_user", a.perUser)
			continue
		}
		out[field] = resolved
	}
	return out, nil
}

// loginValue returns what the login body carries for the credential name
// with the stored value: the value itself, or, for a credential whose value
// is a JSON object (UserAccounts.JSONValue), that object. A stored value
// that is no JSON object fails the login; the message does not repeat it.
func (a *RestAuth) loginValue(name, value string) (any, error) {
	if a.accounts == nil || !a.accounts.JSONValue(name) {
		return value, nil
	}
	object := strings.TrimSpace(value)
	if !strings.HasPrefix(object, "{") || !json.Valid([]byte(object)) {
		return nil, fmt.Errorf("login credential %q: the stored value is not a JSON object", name)
	}
	// The stored JSON itself goes into the body, so its members keep their
	// order and its numbers their digits; a decoded copy would not.
	return json.RawMessage(object), nil
}
