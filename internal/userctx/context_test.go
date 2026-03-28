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

package userctx

import (
	"context"
	"testing"
)

func TestWithUserContext_FromContext(t *testing.T) {
	uc := &UserContext{
		UserID:        "user-1",
		CompanyID:     "acme",
		Roles:         []string{"admin", "viewer"},
		Plan:          "pro",
		Authenticated: true,
	}

	ctx := WithUserContext(context.Background(), uc)
	got := FromContext(ctx)

	if got == nil {
		t.Fatal("expected user context, got nil")
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-1")
	}
	if got.CompanyID != "acme" {
		t.Errorf("CompanyID = %q, want %q", got.CompanyID, "acme")
	}
	if got.Plan != "pro" {
		t.Errorf("Plan = %q, want %q", got.Plan, "pro")
	}
	if !got.Authenticated {
		t.Error("Authenticated = false, want true")
	}
	if len(got.Roles) != 2 {
		t.Errorf("Roles length = %d, want 2", len(got.Roles))
	}
}

func TestFromContext_Empty(t *testing.T) {
	got := FromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestUserContext_CallerOrigin(t *testing.T) {
	uc := &UserContext{
		UserID:      "user-42",
		CallerID:    "claude-code",
		CallerClass: "trusted",
	}

	ctx := WithUserContext(context.Background(), uc)
	got := FromContext(ctx)

	if got.CallerID != "claude-code" {
		t.Errorf("CallerID = %q, want %q", got.CallerID, "claude-code")
	}
	if got.CallerClass != "trusted" {
		t.Errorf("CallerClass = %q, want %q", got.CallerClass, "trusted")
	}
}
