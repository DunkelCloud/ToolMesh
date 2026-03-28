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
	CallerID      string   `json:"callerId"`    // e.g. "claude-code", "expertcouncil"
	CallerClass   string   `json:"callerClass"` // "trusted" | "standard" | "untrusted"
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
