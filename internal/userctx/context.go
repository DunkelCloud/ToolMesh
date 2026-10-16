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

// Package userctx provides user context propagation through the execution pipeline.
package userctx

import (
	"context"
)

// UserContext represents the authenticated user making a tool call.
type UserContext struct {
	UserID        string   `json:"userId"`
	CompanyID     string   `json:"companyId"`
	Roles         []string `json:"roles"`
	Plan          string   `json:"plan"` // "free" | "pro"
	Authenticated bool     `json:"authenticated"`
	CallerID      string   `json:"callerId"`    // verified identifier (API key: admin-set, OAuth: client_id UUID)
	CallerName    string   `json:"callerName"`  // self-reported display name (informational, not for policy decisions)
	CallerClass   string   `json:"callerClass"` // "trusted" | "standard" | "untrusted"
	// GrantKey identifies the credential the caller connected with where
	// CallerID does not: an API key without caller_id, whose CallerID is the
	// user's id. Grants of kits are bound to it instead of to CallerID.
	GrantKey string `json:"-"`
}

// GrantBinding returns what grants of kits are bound to besides the user:
// GrantKey when set, CallerID otherwise.
func (uc *UserContext) GrantBinding() string {
	if uc.GrantKey != "" {
		return uc.GrantKey
	}
	return uc.CallerID
}

type contextKey struct{}

// WithUserContext stores a UserContext in the given context.
func WithUserContext(ctx context.Context, uc *UserContext) context.Context {
	return context.WithValue(ctx, contextKey{}, uc)
}

// FromContext extracts the UserContext from a context, or returns nil.
func FromContext(ctx context.Context) *UserContext {
	uc, _ := ctx.Value(contextKey{}).(*UserContext)
	return uc
}
