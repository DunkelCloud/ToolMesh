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

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const minimalUnitJS = `function describe() { return { tools: [{ name: "run", description: "noop" }] }; }
function run() { return { content: [{ type: "text", text: "ok" }] }; }
`

// stubBackend is a no-op ToolBackend used to seed the composite with a
// pre-existing named entry for collision tests.
type stubBackend struct{}

func (stubBackend) Execute(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{Content: []any{}}, nil
}
func (stubBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) { return nil, nil }
func (stubBackend) Healthy(_ context.Context) error                               { return nil }

func writeUnit(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	yaml := "unit: " + name + "\nimplementation: ./impl.js\n"
	if err := os.WriteFile(filepath.Join(dir, "unit.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write unit.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "impl.js"), []byte(minimalUnitJS), 0o600); err != nil {
		t.Fatalf("write impl.js: %v", err)
	}
}

// captureLogger returns a slog.Logger that captures all records into buf
// so tests can assert on the error messages emitted by loadUnits.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestLoadUnits_DuplicateNameSkipped pre-creates two unit directories
// with the same yaml-declared name. With opt-in scanning these would
// not happen in practice today (the loader only sees direct children),
// but the guard exists for upcoming changes (hot-reload, multi-tenant
// roots) where a duplicate could slip in. First-wins, second is
// logged + skipped, second adapter is closed.
func TestLoadUnits_DuplicateNameSkipped(t *testing.T) {
	root := t.TempDir()
	writeUnit(t, filepath.Join(root, "first"), "twin")
	writeUnit(t, filepath.Join(root, "second"), "twin")

	var buf bytes.Buffer
	logger := captureLogger(&buf)
	comp := backend.NewCompositeBackend(nil)
	creds := credentials.NewEmbeddedStore()

	adapters := loadUnits(context.Background(), root, "", creds, nil, comp, logger)
	t.Cleanup(func() {
		for _, a := range adapters {
			a.Close()
		}
	})

	if len(adapters) != 1 {
		t.Fatalf("expected exactly one adapter retained, got %d", len(adapters))
	}
	if !strings.Contains(buf.String(), "duplicate unit name") {
		t.Fatalf("expected duplicate-name error in log, got:\n%s", buf.String())
	}

	// Composite must hold exactly one backend named "twin".
	names := comp.BackendNames()
	count := 0
	for _, n := range names {
		if n == "twin" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one composite entry for 'twin', got %d (names=%v)", count, names)
	}
}

// TestLoadUnits_NameCollidesWithExistingBackend seeds the composite with
// a pre-existing named backend (simulating a REST/echo entry), then
// tries to load a unit with the same name. The unit must be rejected
// rather than overwriting the existing entry, and its private MCPAdapter
// must be closed to release sub-backend sessions.
func TestLoadUnits_NameCollidesWithExistingBackend(t *testing.T) {
	root := t.TempDir()
	writeUnit(t, filepath.Join(root, "ghost"), "ghost")

	var buf bytes.Buffer
	logger := captureLogger(&buf)

	// Pre-seed the composite with a backend named "ghost".
	pre := stubBackend{}
	comp := backend.NewCompositeBackend(map[string]backend.ToolBackend{"ghost": pre})
	creds := credentials.NewEmbeddedStore()

	adapters := loadUnits(context.Background(), root, "", creds, nil, comp, logger)
	t.Cleanup(func() {
		for _, a := range adapters {
			a.Close()
		}
	})

	if len(adapters) != 0 {
		t.Fatalf("expected no unit adapters retained, got %d", len(adapters))
	}
	if !strings.Contains(buf.String(), "collides with existing backend") {
		t.Fatalf("expected collision error in log, got:\n%s", buf.String())
	}
}

// TestLoadUnits_HappyPath confirms a plain unit still loads and lands in
// the composite when no collision is present.
func TestLoadUnits_HappyPath(t *testing.T) {
	root := t.TempDir()
	writeUnit(t, filepath.Join(root, "lone"), "lone")

	var buf bytes.Buffer
	logger := captureLogger(&buf)
	comp := backend.NewCompositeBackend(nil)
	creds := credentials.NewEmbeddedStore()

	adapters := loadUnits(context.Background(), root, "", creds, nil, comp, logger)
	t.Cleanup(func() {
		for _, a := range adapters {
			a.Close()
		}
	})

	if len(adapters) != 1 {
		t.Fatalf("expected one adapter, got %d", len(adapters))
	}
	names := comp.BackendNames()
	found := false
	for _, n := range names {
		if n == "lone" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unit 'lone' not in composite names %v", names)
	}
	if !strings.Contains(buf.String(), "unit loaded") {
		t.Fatalf("expected 'unit loaded' in log, got:\n%s", buf.String())
	}
}
