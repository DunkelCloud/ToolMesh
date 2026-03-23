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
	"encoding/json"
	"testing"

	commonpb "go.temporal.io/api/common/v1"
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

func TestHeaderPropagator_InjectExtract(t *testing.T) {
	uc := &UserContext{
		UserID:        "user-42",
		CompanyID:     "corp",
		Roles:         []string{"editor"},
		Plan:          "free",
		Authenticated: true,
	}

	ctx := WithUserContext(context.Background(), uc)
	propagator := &HeaderPropagator{}

	// Inject
	writer := &mockHeaderWriter{headers: make(map[string]*commonpb.Payload)}
	if err := propagator.Inject(ctx, writer); err != nil {
		t.Fatalf("Inject failed: %v", err)
	}

	payload, ok := writer.headers[headerKey]
	if !ok {
		t.Fatal("expected header to be set")
	}

	// Verify the payload is valid JSON
	var decoded UserContext
	if err := json.Unmarshal(payload.Data, &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if decoded.UserID != "user-42" {
		t.Errorf("decoded UserID = %q, want %q", decoded.UserID, "user-42")
	}

	// Extract
	reader := &mockHeaderReader{headers: writer.headers}
	extractedCtx, err := propagator.Extract(context.Background(), reader)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	extracted := FromContext(extractedCtx)
	if extracted == nil {
		t.Fatal("expected extracted user context, got nil")
	}
	if extracted.UserID != "user-42" {
		t.Errorf("UserID = %q, want %q", extracted.UserID, "user-42")
	}
	if extracted.CompanyID != "corp" {
		t.Errorf("CompanyID = %q, want %q", extracted.CompanyID, "corp")
	}
}

func TestHeaderPropagator_Inject_NilContext(t *testing.T) {
	propagator := &HeaderPropagator{}
	writer := &mockHeaderWriter{headers: make(map[string]*commonpb.Payload)}

	if err := propagator.Inject(context.Background(), writer); err != nil {
		t.Fatalf("Inject failed: %v", err)
	}

	if len(writer.headers) != 0 {
		t.Errorf("expected no headers to be set, got %d", len(writer.headers))
	}
}

func TestHeaderPropagator_Extract_MissingHeader(t *testing.T) {
	propagator := &HeaderPropagator{}
	reader := &mockHeaderReader{headers: make(map[string]*commonpb.Payload)}

	ctx, err := propagator.Extract(context.Background(), reader)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if FromContext(ctx) != nil {
		t.Error("expected nil user context when header is missing")
	}
}

// Mock implementations for Temporal HeaderWriter/HeaderReader

type mockHeaderWriter struct {
	headers map[string]*commonpb.Payload
}

func (w *mockHeaderWriter) Set(key string, value *commonpb.Payload) {
	w.headers[key] = value
}

type mockHeaderReader struct {
	headers map[string]*commonpb.Payload
}

func (r *mockHeaderReader) Get(key string) (*commonpb.Payload, bool) {
	v, ok := r.headers[key]
	return v, ok
}

func (r *mockHeaderReader) ForEachKey(handler func(string, *commonpb.Payload) error) error {
	for k, v := range r.headers {
		if err := handler(k, v); err != nil {
			return err
		}
	}
	return nil
}
