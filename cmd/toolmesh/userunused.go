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

package main

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// userValueLister is what the check for unused values needs of the store
// for credentials of users. *credentials.FileUserStore implements it.
type userValueLister interface {
	Users() []string
	ListUser(ctx context.Context, userID string) ([]credentials.UserCredentialInfo, error)
}

// unusedUserValues returns, per backend of declared, the credential names
// under which users hold values that the backend does not ask its users
// for: names that are not among declared[backend]. Names are compared in
// their stored form, upper case. A backend that is not in declared is left
// out: the credentials page lists its accounts as no longer used.
func unusedUserValues(ctx context.Context, store userValueLister, declared map[string][]string) (map[string][]string, error) {
	asked := make(map[string]map[string]bool, len(declared))
	for name, credentialNames := range declared {
		set := make(map[string]bool, len(credentialNames))
		for _, c := range credentialNames {
			set[strings.ToUpper(c)] = true
		}
		asked[name] = set
	}
	found := map[string]map[string]bool{}
	for _, userID := range store.Users() {
		infos, err := store.ListUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			names, loaded := asked[info.Backend]
			if !loaded || names[info.Name] {
				continue
			}
			if found[info.Backend] == nil {
				found[info.Backend] = map[string]bool{}
			}
			found[info.Backend][info.Name] = true
		}
	}
	out := make(map[string][]string, len(found))
	for name, set := range found {
		for c := range set {
			out[name] = append(out[name], strings.ToLower(c))
		}
		sort.Strings(out[name])
	}
	return out, nil
}

// warnUnusedUserValues logs the backends whose users hold values under
// credential names the backend no longer asks them for. Such values are
// not used. That matters most for the limit of an account: once its entry
// is gone from user_credentials, or renamed, the login reads that name from
// the instance, finds none and goes out without a limit, while the limits
// users stored stay in the store, unused. It runs at startup and after
// every reload of the backends.
func warnUnusedUserValues(ctx context.Context, users *userCredentialSetup, backends *userBackendRegistry, logger *slog.Logger) {
	if users == nil {
		return
	}
	declared := map[string][]string{}
	for _, b := range backends.list() {
		for _, c := range b.Credentials {
			declared[b.Name] = append(declared[b.Name], c.Name)
		}
	}
	unused, err := unusedUserValues(ctx, users.store, declared)
	if err != nil {
		logger.Error("user credentials: could not check for stored values that are not used", "error", err)
		return
	}
	names := make([]string, 0, len(unused))
	for name := range unused {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		logger.Warn("user credentials: users hold values under names this backend does not ask its users for. They are not used. If one of them limited what an account reaches, calls of that account are not limited by it: list the name under user_credentials again, or tell the users",
			"backend", name, "credentials", unused[name])
	}
}
