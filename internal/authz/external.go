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

package authz

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/openfga/go-sdk/client"
)

// External checks against an OpenFGA server that is operated separately
// (TOOLMESH_AUTHZ_MODE=external). The store may be shared with other
// applications, so External only reads: it never writes a model or a tuple.
// Its model is the operator's; every check asks whether user:<id> has
// can_execute on tool:<name>.
type External struct {
	client *client.OpenFgaClient
	logger *slog.Logger
}

// NewExternal creates an External authorizer for the given OpenFGA API URL
// and store.
func NewExternal(apiURL, storeID string, logger *slog.Logger) (*External, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg := &client.ClientConfiguration{
		ApiUrl:  apiURL,
		StoreId: storeID,
	}

	fgaClient, err := client.NewSdkClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create openfga client: %w", err)
	}

	return &External{
		client: fgaClient,
		logger: logger,
	}, nil
}

// Check verifies if the caller in req is allowed to execute req.Tool.
func (a *External) Check(ctx context.Context, req Request) (bool, error) {
	// OpenFGA object IDs cannot contain colons; encode colons as "%3A" to avoid
	// collisions between "backend:tool_name" and "backend_tool_name". Tuples in
	// external stores are written by operators in this form, so it must not
	// change.
	fgaToolID := strings.ReplaceAll(req.Tool, ":", "%3A")
	body := client.ClientCheckRequest{
		User:     "user:" + req.UserID,
		Relation: relCanExecute,
		Object:   "tool:" + fgaToolID,
	}

	resp, err := a.client.Check(ctx).Body(body).Execute()
	if err != nil {
		return false, fmt.Errorf("openfga check for user=%s tool=%s: %w", req.UserID, req.Tool, err)
	}

	allowed := resp.GetAllowed()
	a.logger.DebugContext(ctx, "authz check",
		"user", req.UserID,
		"tool", req.Tool,
		"allowed", allowed,
	)

	return allowed, nil
}

// Healthy checks if the OpenFGA server is reachable.
func (a *External) Healthy(ctx context.Context) error {
	_, err := a.client.ListStores(ctx).Execute()
	if err != nil {
		return fmt.Errorf("openfga health check: %w", err)
	}
	return nil
}

// Close releases nothing; the SDK client holds no resources that need it.
func (a *External) Close() error { return nil }
