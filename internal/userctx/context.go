// Package userctx provides user context propagation through Temporal workflows.
package userctx

import (
	"context"
	"encoding/json"
	"fmt"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/workflow"
)

const headerKey = "toolmesh-user-context"

// UserContext represents the authenticated user making a tool call.
// It is immutable within a Temporal workflow and propagated via headers.
type UserContext struct {
	UserID        string   `json:"userId"`
	CompanyID     string   `json:"companyId"`
	Roles         []string `json:"roles"`
	Plan          string   `json:"plan"` // "free" | "pro"
	Authenticated bool     `json:"authenticated"`
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

// HeaderPropagator implements Temporal's ContextPropagator interface to pass
// UserContext through workflow and activity headers.
type HeaderPropagator struct{}

// Inject serializes UserContext into Temporal headers.
func (h *HeaderPropagator) Inject(ctx context.Context, writer workflow.HeaderWriter) error {
	uc := FromContext(ctx)
	if uc == nil {
		return nil
	}
	data, err := json.Marshal(uc)
	if err != nil {
		return fmt.Errorf("marshal user context: %w", err)
	}
	writer.Set(headerKey, &commonpb.Payload{Data: data})
	return nil
}

// Extract deserializes UserContext from Temporal headers.
func (h *HeaderPropagator) Extract(ctx context.Context, reader workflow.HeaderReader) (context.Context, error) {
	payload, ok := reader.Get(headerKey)
	if !ok || payload == nil {
		return ctx, nil
	}
	var uc UserContext
	if err := json.Unmarshal(payload.Data, &uc); err != nil {
		return ctx, fmt.Errorf("unmarshal user context: %w", err)
	}
	return WithUserContext(ctx, &uc), nil
}

// InjectFromWorkflow serializes UserContext into Temporal headers from a workflow context.
func (h *HeaderPropagator) InjectFromWorkflow(ctx workflow.Context, writer workflow.HeaderWriter) error {
	return nil
}

// ExtractToWorkflow deserializes UserContext from Temporal headers into a workflow context.
func (h *HeaderPropagator) ExtractToWorkflow(ctx workflow.Context, reader workflow.HeaderReader) (workflow.Context, error) {
	return ctx, nil
}
