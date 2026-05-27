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

// Command randombit-mcp is a minimal stdio MCP server that exposes a single
// biased random tool. It exists to support unit-backend integration tests:
// the dice unit calls flip() repeatedly and asserts that the empirical
// distribution matches the configured bias within statistical bounds, which
// only succeeds when the whole UNIT sandbox → api.* → MCP adapter chain
// actually reaches this process.
//
// Environment variables:
//
//	RANDOMBIT_SEED       integer seed for deterministic output (default: time-based)
//	RANDOMBIT_BIAS_NUM   numerator of the bias for "A" (default: 75)
//	RANDOMBIT_BIAS_DEN   denominator of the bias for "A" (default: 100)
package main

import (
	"context"
	"log"
	"math/rand/v2"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultBiasNumerator   = 75
	defaultBiasDenominator = 100
)

type flipArgs struct{}

func main() {
	biasNum := envInt("RANDOMBIT_BIAS_NUM", defaultBiasNumerator)
	biasDen := envInt("RANDOMBIT_BIAS_DEN", defaultBiasDenominator)
	if biasDen <= 0 || biasNum < 0 || biasNum > biasDen {
		log.Fatalf("randombit-mcp: invalid bias %d/%d (need 0 <= num <= den, den > 0)", biasNum, biasDen)
	}

	seed := envInt64("RANDOMBIT_SEED", time.Now().UnixNano())
	// rand/v2 PCG accepts two seed words; derive the second from the first
	// so a single env value still produces a deterministic stream.
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15)) //nolint:gosec // not cryptographic
	var mu sync.Mutex

	server := mcp.NewServer(&mcp.Implementation{Name: "randombit", Version: "0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "flip",
		Description: "Return \"A\" with the configured bias (default 75%), otherwise \"B\".",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ flipArgs) (*mcp.CallToolResult, any, error) {
		mu.Lock()
		n := rng.IntN(biasDen)
		mu.Unlock()
		out := "B"
		if n < biasNum {
			out = "A"
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: out}},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("randombit-mcp: %v", err)
	}
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("randombit-mcp: env %s=%q is not an integer", key, v) //nolint:gosec // operator-controlled env at startup
	}
	return n
}

func envInt64(key string, fallback int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Fatalf("randombit-mcp: env %s=%q is not an integer", key, v) //nolint:gosec // operator-controlled env at startup
	}
	return n
}
