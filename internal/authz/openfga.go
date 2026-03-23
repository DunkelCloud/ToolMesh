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

	openfga "github.com/openfga/go-sdk"
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
	// OpenFGA object IDs cannot contain colons; tool names like "echo:echo"
	// are stored as "tool:echo_echo" in tuples.
	fgaToolID := strings.ReplaceAll(toolName, ":", "_")
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

// CreateStore creates a new OpenFGA store and returns its ID.
func CreateStore(ctx context.Context, apiURL, name string) (string, error) {
	cfg := &client.ClientConfiguration{
		ApiUrl: apiURL,
	}

	fgaClient, err := client.NewSdkClient(cfg)
	if err != nil {
		return "", fmt.Errorf("create openfga client: %w", err)
	}

	resp, err := fgaClient.CreateStore(ctx).Body(client.ClientCreateStoreRequest{
		Name: name,
	}).Execute()
	if err != nil {
		return "", fmt.Errorf("create store: %w", err)
	}

	return resp.GetId(), nil
}

// WriteModel writes the authorization model to the given store.
func WriteModel(ctx context.Context, apiURL, storeID string) (string, error) {
	cfg := &client.ClientConfiguration{
		ApiUrl:  apiURL,
		StoreId: storeID,
	}

	fgaClient, err := client.NewSdkClient(cfg)
	if err != nil {
		return "", fmt.Errorf("create openfga client: %w", err)
	}

	model := openfga.WriteAuthorizationModelRequest{
		SchemaVersion: "1.2",
		TypeDefinitions: []openfga.TypeDefinition{
			{
				Type: "user",
			},
			{
				Type: "company",
				Relations: &map[string]openfga.Userset{
					"member": {
						This: ptrMap(map[string]any{}),
					},
				},
				Metadata: &openfga.Metadata{
					Relations: &map[string]openfga.RelationMetadata{
						"member": {
							DirectlyRelatedUserTypes: &[]openfga.RelationReference{
								{Type: "user"},
							},
						},
					},
				},
			},
			{
				Type: "plan",
				Relations: &map[string]openfga.Userset{
					"subscriber": {
						This: ptrMap(map[string]any{}),
					},
				},
				Metadata: &openfga.Metadata{
					Relations: &map[string]openfga.RelationMetadata{
						"subscriber": {
							DirectlyRelatedUserTypes: &[]openfga.RelationReference{
								{Type: "user"},
								{Type: "user", Wildcard: ptrMap(map[string]any{})},
								{Type: "company", Relation: ptr("member")},
							},
						},
					},
				},
			},
			{
				Type: "tool",
				Relations: &map[string]openfga.Userset{
					"associated_plan": {
						This: ptrMap(map[string]any{}),
					},
					"can_execute": {
						TupleToUserset: &openfga.TupleToUserset{
							Tupleset: openfga.ObjectRelation{
								Relation: ptr("associated_plan"),
							},
							ComputedUserset: openfga.ObjectRelation{
								Relation: ptr("subscriber"),
							},
						},
					},
				},
				Metadata: &openfga.Metadata{
					Relations: &map[string]openfga.RelationMetadata{
						"associated_plan": {
							DirectlyRelatedUserTypes: &[]openfga.RelationReference{
								{Type: "plan"},
							},
						},
					},
				},
			},
		},
	}

	resp, err := fgaClient.WriteAuthorizationModel(ctx).Body(model).Execute()
	if err != nil {
		return "", fmt.Errorf("write model: %w", err)
	}

	return resp.GetAuthorizationModelId(), nil
}

// WriteTuples writes relationship tuples to the store.
func WriteTuples(ctx context.Context, apiURL, storeID string, tuples []client.ClientTupleKey) error {
	cfg := &client.ClientConfiguration{
		ApiUrl:  apiURL,
		StoreId: storeID,
	}

	fgaClient, err := client.NewSdkClient(cfg)
	if err != nil {
		return fmt.Errorf("create openfga client: %w", err)
	}

	_, err = fgaClient.Write(ctx).Body(client.ClientWriteRequest{
		Writes: tuples,
	}).Execute()
	if err != nil {
		return fmt.Errorf("write tuples: %w", err)
	}

	return nil
}

// Healthy checks if the OpenFGA server is reachable.
func (a *Authorizer) Healthy(ctx context.Context) error {
	_, err := a.client.ListStores(ctx).Execute()
	if err != nil {
		return fmt.Errorf("openfga health check: %w", err)
	}
	return nil
}

func ptr(s string) *string                    { return &s }
func ptrMap(m map[string]any) *map[string]any { return &m } //nolint:gocritic // required by OpenFGA SDK
