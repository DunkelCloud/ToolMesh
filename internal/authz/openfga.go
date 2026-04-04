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

// Package authz provides authorization via OpenFGA.
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/openfga/go-sdk/client"
)

// Authorizer checks whether users are allowed to execute tools.
type Authorizer struct {
	client *client.OpenFgaClient
	logger *slog.Logger
}

// NewAuthorizer creates an Authorizer backed by OpenFGA.
func NewAuthorizer(apiURL, storeID string, logger *slog.Logger) (*Authorizer, error) {
	cfg := &client.ClientConfiguration{
		ApiUrl:  apiURL,
		StoreId: storeID,
	}

	fgaClient, err := client.NewSdkClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create openfga client: %w", err)
	}

	return &Authorizer{
		client: fgaClient,
		logger: logger,
	}, nil
}

// Check verifies if the given user is allowed to execute the specified tool.
// Returns true if authorized, false otherwise.
func (a *Authorizer) Check(ctx context.Context, userID, toolName string) (bool, error) {
	// OpenFGA object IDs cannot contain colons; encode colons as "%3A" to avoid
	// collisions between "backend:tool_name" and "backend_tool_name".
	fgaToolID := strings.ReplaceAll(toolName, ":", "%3A")
	body := client.ClientCheckRequest{
		User:     "user:" + userID,
		Relation: "can_execute",
		Object:   "tool:" + fgaToolID,
	}

	resp, err := a.client.Check(ctx).Body(body).Execute()
	if err != nil {
		return false, fmt.Errorf("openfga check for user=%s tool=%s: %w", userID, toolName, err)
	}

	allowed := resp.GetAllowed()
	a.logger.DebugContext(ctx, "authz check",
		"user", userID,
		"tool", toolName,
		"allowed", allowed,
	)

	return allowed, nil
}

// Healthy checks if the OpenFGA server is reachable.
func (a *Authorizer) Healthy(ctx context.Context) error {
	_, err := a.client.ListStores(ctx).Execute()
	if err != nil {
		return fmt.Errorf("openfga health check: %w", err)
	}
	return nil
}
