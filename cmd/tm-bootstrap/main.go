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

// Command tm-bootstrap initializes the OpenFGA store with the ToolMesh
// authorization model and example tuples.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/openfga/go-sdk/client"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	apiURL := os.Getenv("OPENFGA_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	ctx := context.Background()

	// Create store
	logger.Info("creating OpenFGA store")
	storeID, err := authz.CreateStore(ctx, apiURL, "toolmesh")
	if err != nil {
		logger.Error("failed to create store", "error", err)
		os.Exit(1)
	}
	logger.Info("store created", "storeId", storeID)

	// Write authorization model
	logger.Info("writing authorization model")
	modelID, err := authz.WriteModel(ctx, apiURL, storeID)
	if err != nil {
		logger.Error("failed to write model", "error", err)
		os.Exit(1)
	}
	logger.Info("model written", "modelId", modelID)

	// Write bootstrap tuples
	logger.Info("writing bootstrap tuples")
	tuples := []client.ClientTupleKey{
		{
			User:     "user:*",
			Relation: "subscriber",
			Object:   "plan:free",
		},
		{
			User:     "company:acme#member",
			Relation: "subscriber",
			Object:   "plan:pro",
		},
		{
			User:     "plan:pro",
			Relation: "associated_plan",
			Object:   "tool:*",
		},
	}

	if err := authz.WriteTuples(ctx, apiURL, storeID, tuples); err != nil {
		logger.Error("failed to write tuples", "error", err)
		os.Exit(1)
	}
	logger.Info("bootstrap tuples written")

	fmt.Printf("\nBootstrap complete!\n")
	fmt.Printf("Store ID: %s\n", storeID)
	fmt.Printf("Model ID: %s\n", modelID)
	fmt.Printf("\nSet this in your .env:\n")
	fmt.Printf("OPENFGA_STORE_ID=%s\n", storeID)
}
