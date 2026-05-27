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

package unit_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/unit"
)

// TestDiceUnit_StatisticalDistribution is the walking-skeleton end-to-end
// test for the unit-backend stack. It builds the randombit-mcp stdio server,
// drives the dice unit's roll(n) tool 1000 times with a known seed, and
// asserts that the empirical A/B split matches the configured 75/25 bias.
//
// The statistical check is what makes this useful as a smoke test: a stub
// or short-circuit somewhere in the sandbox → api.* → MCP chain would never
// produce a 75/25 split for 1000 trials. The acceptance window is set to
// ±4σ (≈ ±55) so the test stays well under any plausible flake rate while
// still catching a broken pipeline.
func TestDiceUnit_StatisticalDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	repoRoot := findRepoRoot(t)
	binDir := t.TempDir()
	mcpBin := filepath.Join(binDir, "randombit-mcp")
	if runtime.GOOS == "windows" {
		mcpBin += ".exe"
	}
	buildCmd := exec.CommandContext(context.Background(), "go", "build", "-o", mcpBin, "./cmd/randombit-mcp") //nolint:gosec // controlled args
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build randombit-mcp: %v\n%s", err, out)
	}

	// Stage a unit directory that points at the freshly-built binary and
	// pins the bias seed so the test is deterministic.
	unitDir := t.TempDir()
	unitYAML := "" +
		"unit: dice\n" +
		"implementation: ./dice.js\n" +
		"expose:\n" +
		"  audit: full\n" +
		"backends:\n" +
		"  - name: randombit\n" +
		"    transport: stdio\n" +
		"    command: " + mcpBin + "\n"
	if err := os.WriteFile(filepath.Join(unitDir, "unit.yaml"), []byte(unitYAML), 0o600); err != nil {
		t.Fatalf("write unit.yaml: %v", err)
	}
	jsSrc, err := os.ReadFile(filepath.Join(repoRoot, "units", "dice", "dice.js")) //nolint:gosec // path under controlled repoRoot
	if err != nil {
		t.Fatalf("read dice.js source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "dice.js"), jsSrc, 0o600); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("write dice.js: %v", err)
	}

	t.Setenv("RANDOMBIT_SEED", "42")
	t.Setenv("RANDOMBIT_BIAS_NUM", "75")
	t.Setenv("RANDOMBIT_BIAS_DEN", "100")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	creds := credentials.NewEmbeddedStore()

	ctx := context.Background()
	res, err := unit.LoadUnit(ctx, unitDir, creds, logger)
	if err != nil {
		t.Fatalf("LoadUnit: %v", err)
	}
	defer res.Adapter.Close()

	tools, err := res.Backend.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "roll" {
		t.Fatalf("expected single tool 'roll', got %+v", tools)
	}

	const n = 1000
	result, err := res.Backend.Execute(ctx, "roll", map[string]any{"n": n})
	if err != nil {
		t.Fatalf("Execute roll: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatalf("empty content")
	}

	// The first content block carries a JSON summary {n, counts: {A, B}}.
	block, ok := result.Content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] is not a map: %T", result.Content[0])
	}
	text, _ := block["text"].(string)
	var summary struct {
		N      int `json:"n"`
		Counts struct {
			A int `json:"A"`
			B int `json:"B"`
		} `json:"counts"`
	}
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		t.Fatalf("decode summary %q: %v", text, err)
	}
	if summary.N != n {
		t.Fatalf("summary.n = %d, want %d", summary.N, n)
	}
	if summary.Counts.A+summary.Counts.B != n {
		t.Fatalf("counts sum to %d, want %d (A=%d, B=%d)", summary.Counts.A+summary.Counts.B, n, summary.Counts.A, summary.Counts.B)
	}

	// Binomial check: mean = n*p, σ = sqrt(n*p*(1-p)). Accept |empirical - mean| < 4σ.
	const p = 0.75
	mean := float64(n) * p
	sigma := math.Sqrt(float64(n) * p * (1 - p))
	tolerance := 4 * sigma
	if math.Abs(float64(summary.Counts.A)-mean) > tolerance {
		t.Fatalf("A-count %d outside 4σ window [%.1f, %.1f] (mean %.1f, σ %.2f) — sandbox→api.*→MCP chain is broken",
			summary.Counts.A, mean-tolerance, mean+tolerance, mean, sigma)
	}
}

// findRepoRoot walks up from the test file location until it finds the
// repository root (the directory that contains go.mod).
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod above %s", wd)
		}
		dir = parent
	}
}
