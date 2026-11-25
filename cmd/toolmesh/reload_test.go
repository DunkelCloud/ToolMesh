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
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/health"
	"github.com/DunkelCloud/ToolMesh/internal/mcp"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	reloadUnitName = "lone"
	reloadUnitTool = "lone_run"
	// reloadUnitMarker is what the unit's tool answers, so a test can tell
	// that the unit, and nothing else, ran.
	reloadUnitMarker = "unit-ran"
	reloadEcho       = "echo"
	reloadAlpha      = "alpha"
	reloadAlphaPing  = "alpha_get_ping"
	reloadConfig     = "backends.yaml"
	reloadDADL       = "api.dadl"

	// reloadStartup is backends.yaml at startup: one REST entry.
	reloadStartup = `
backends:
  - name: alpha
    transport: rest
    dadl: api.dadl
`

	// reloadChangedDADL replaces alpha's tool and declares a health check
	// against a closed local port. The tests record health targets instead
	// of running a monitor, so nothing is ever sent to it.
	reloadChangedDADL = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: changed
  type: rest
  base_url: "http://127.0.0.1:1"
  health:
    path: /status
  tools:
    get_pong:
      method: GET
      path: /pong
`
)

// writeReloadUnit writes the unit "lone" with one tool, promoted to the
// top-level tool list, under dir/units.
func writeReloadUnit(t *testing.T, dir string) {
	t.Helper()
	unitDir := filepath.Join(dir, "units", reloadUnitName)
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"unit.yaml": "unit: " + reloadUnitName + "\nimplementation: ./impl.js\nexpose:\n  tools: [run]\n",
		"impl.js": `function describe() { return { tools: [{ name: "run", description: "Runs the reload test unit" }] }; }
function run() { return { content: [{ type: "text", text: "` + reloadUnitMarker + `" }] }; }
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(unitDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// writeReloadFiles writes files into dir.
func writeReloadFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// recordedHealthTargets stands in for the health monitor and keeps the
// names of the targets it was last given.
type recordedHealthTargets struct{ names []string }

func (r *recordedHealthTargets) Replace(_ context.Context, targets []health.Target) {
	r.names = make([]string, 0, len(targets))
	for _, tg := range targets {
		r.names = append(r.names, tg.Name)
	}
	slices.Sort(r.names)
}

// reloadServer is a server's backends wired the way main wires them, over
// the files in one directory, with the MCP handler that serves tools/list,
// discover_tools and execute_code.
type reloadServer struct {
	composite    *backend.CompositeBackend
	userBackends *userBackendRegistry
	health       *recordedHealthTargets
	reloader     *backendsReloader
	handler      *mcp.Handler
}

// startReloadServer starts the backends from dir/backends.yaml, the DADLs in
// dir and the units in dir/units, as main does at startup.
func startReloadServer(t *testing.T, dir string) *reloadServer {
	t.Helper()
	ctx := context.Background()
	logger := quietLogger()
	cfg := &config.Config{
		BackendsConfigPath: filepath.Join(dir, reloadConfig),
		DADLDir:            dir,
		UnitsDir:           filepath.Join(dir, "units"),
	}
	creds := credentials.NewEmbeddedStore()
	bc := &buildBackendsConfig{cfg: cfg, credStore: creds, logger: logger, owners: dadl.NewCredentialOwners()}
	build := func(ctx context.Context) (*backendsResult, error) {
		res, err := buildBackends(ctx, bc)
		if res != nil {
			t.Cleanup(res.mcpAdapter.Close)
		}
		return res, err
	}

	res, err := build(ctx)
	if err != nil {
		t.Fatalf("startup: %v", err)
	}
	s := &reloadServer{userBackends: &userBackendRegistry{}, health: &recordedHealthTargets{}}
	s.health.Replace(ctx, res.healthTargets)
	s.composite = backend.NewCompositeBackend(res.named)
	echo := backend.NewEchoBackend()
	s.composite.AddNamed(reloadEcho, echo)
	for _, p := range res.passthroughs {
		s.composite.AddPassthrough(p)
	}
	s.userBackends.set(res.named)
	units, adapters := loadUnits(ctx, cfg.UnitsDir, cfg.DADLDir, creds, bc.owners, nil, s.composite, logger)
	t.Cleanup(func() {
		for _, a := range adapters {
			a.Close()
		}
	})
	if units[reloadUnitName] == nil {
		t.Fatalf("startup did not load unit %q", reloadUnitName)
	}
	s.reloader = &backendsReloader{
		build:        build,
		composite:    s.composite,
		echo:         echo,
		units:        units,
		userBackends: s.userBackends,
		health:       s.health,
		adapter:      res.mcpAdapter,
	}
	t.Cleanup(s.reloader.close)
	exec := executor.New(nil, nil, s.composite, nil, nil, 5*time.Second, logger, nil, nil)
	s.handler = mcp.NewHandler(exec, s.composite, nil, "", nil, logger, false)
	return s
}

// backendsState is what a server shows of its backends, for comparing two
// servers or one server before and after a reload.
type backendsState struct {
	backends     []string
	tools        []string
	health       []string
	userBackends []string
}

func (s *reloadServer) state(t *testing.T) backendsState {
	t.Helper()
	descs, err := s.composite.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	st := backendsState{
		backends: s.composite.BackendNames(),
		health:   s.health.names,
	}
	for _, d := range descs {
		st.tools = append(st.tools, d.Name)
	}
	for _, b := range s.userBackends.list() {
		st.userBackends = append(st.userBackends, b.Name)
	}
	slices.Sort(st.backends)
	slices.Sort(st.tools)
	slices.Sort(st.userBackends)
	return st
}

// callText calls a meta tool the way an MCP client does and returns the text
// of the result.
func (s *reloadServer) callText(t *testing.T, tool string, params map[string]any) string {
	t.Helper()
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "alice", Authenticated: true})
	res, err := s.handler.HandleToolCall(ctx, tool, params)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var texts []string
	for _, c := range res.Content {
		if m, ok := c.(map[string]any); ok {
			if text, ok := m["text"].(string); ok {
				texts = append(texts, text)
			}
		}
	}
	text := strings.Join(texts, "\n")
	if res.IsError {
		t.Fatalf("%s returned an error: %s", tool, text)
	}
	return text
}

// assertUnitServed checks that a client sees the unit on every surface:
// promoted in tools/list, found by discover_tools and callable from
// execute_code.
func (s *reloadServer) assertUnitServed(t *testing.T) {
	t.Helper()
	list, err := s.handler.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if !slices.ContainsFunc(list, func(d mcp.ToolDefinition) bool { return d.Name == reloadUnitTool }) {
		t.Errorf("tools/list does not offer the promoted unit tool %s", reloadUnitTool)
	}
	if got := s.callText(t, "discover_tools", map[string]any{"pattern": "^" + reloadUnitName + "_"}); !strings.Contains(got, reloadUnitTool) {
		t.Errorf("discover_tools does not find %s:\n%s", reloadUnitTool, got)
	}
	code := "return await toolmesh." + reloadUnitTool + "({})"
	if got := s.callText(t, "execute_code", map[string]any{"code": code}); !strings.Contains(got, reloadUnitMarker) {
		t.Errorf("execute_code did not run the unit: %s", got)
	}
}

// A reload of backends.yaml must keep the units loaded at startup: on every
// client surface, in the composite, and as a restart would leave them. A
// reload that fails, or would hand a unit's name to another backend, changes
// nothing. Before the fix, every reload dropped all units until a restart.
func TestBackendsReload_KeepsUnits(t *testing.T) {
	tests := []struct {
		name string
		// files are written over the startup files before the reload.
		files        map[string]string
		wantErr      string
		wantBackends []string
		wantTools    []string
		wantNoTools  []string
		wantHealth   []string
	}{
		{
			name: "entry added",
			files: map[string]string{reloadConfig: reloadStartup + `
  - name: beta
    transport: rest
    dadl: api.dadl
`},
			wantBackends: []string{reloadAlpha, "beta", reloadEcho, reloadUnitName},
			wantTools:    []string{reloadAlphaPing, "beta_get_ping", reloadUnitTool},
		},
		{
			name:         "DADL of an entry changed",
			files:        map[string]string{reloadDADL: reloadChangedDADL},
			wantBackends: []string{reloadAlpha, reloadEcho, reloadUnitName},
			wantTools:    []string{"alpha_get_pong", reloadUnitTool},
			wantNoTools:  []string{reloadAlphaPing},
			wantHealth:   []string{reloadAlpha},
		},
		{
			name:         "entry removed",
			files:        map[string]string{reloadConfig: "backends: []\n"},
			wantBackends: []string{reloadEcho, reloadUnitName},
			wantTools:    []string{reloadUnitTool},
			wantNoTools:  []string{reloadAlphaPing},
		},
		{
			name:    "file does not load",
			files:   map[string]string{reloadConfig: reloadStartup + "unknown_key: true\n"},
			wantErr: "parse backends config",
		},
		{
			name: "REST entry takes the name of a unit",
			files: map[string]string{reloadConfig: reloadStartup + `
  - name: lone
    transport: rest
    dadl: api.dadl
`},
			wantErr: "running unit (lone)",
		},
		{
			name: "MCP entry takes the name of a unit",
			files: map[string]string{reloadConfig: reloadStartup + `
  - name: lone
    transport: stdio
    command: toolmesh-reload-test-no-such-command
`},
			wantErr: "running unit (lone)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeReloadFiles(t, dir, map[string]string{reloadConfig: reloadStartup, reloadDADL: testDADLContent})
			writeReloadUnit(t, dir)
			s := startReloadServer(t, dir)
			s.assertUnitServed(t)
			before := s.state(t)
			version := s.composite.ToolSetVersion()

			writeReloadFiles(t, dir, tt.files)
			err := s.reloader.reload(context.Background())

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("reload error = %v, want one containing %q", err, tt.wantErr)
				}
				if got := s.state(t); !stateEqual(got, before) {
					t.Errorf("a failed reload changed the backends:\nbefore %+v\nafter  %+v", before, got)
				}
				if s.composite.ToolSetVersion() != version {
					t.Error("a failed reload published a new tool set")
				}
				s.assertUnitServed(t)
				return
			}

			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if s.composite.ToolSetVersion() == version {
				t.Error("the reload did not publish a new tool set")
			}
			got := s.state(t)
			if !slices.Equal(got.backends, tt.wantBackends) {
				t.Errorf("backends = %v, want %v", got.backends, tt.wantBackends)
			}
			for _, tool := range tt.wantTools {
				if !slices.Contains(got.tools, tool) {
					t.Errorf("tool %s missing after the reload: %v", tool, got.tools)
				}
			}
			for _, tool := range tt.wantNoTools {
				if slices.Contains(got.tools, tool) {
					t.Errorf("tool %s still served after the reload", tool)
				}
			}
			if !slices.Equal(got.health, tt.wantHealth) {
				t.Errorf("health targets = %v, want %v", got.health, tt.wantHealth)
			}
			s.assertUnitServed(t)

			// A restart on the same files ends up where the reload did.
			if fresh := startReloadServer(t, dir).state(t); !stateEqual(got, fresh) {
				t.Errorf("reload and restart differ:\nreload  %+v\nrestart %+v", got, fresh)
			}
		})
	}
}

func stateEqual(a, b backendsState) bool {
	return slices.Equal(a.backends, b.backends) && slices.Equal(a.tools, b.tools) &&
		slices.Equal(a.health, b.health) && slices.Equal(a.userBackends, b.userBackends)
}

// summarizedBackend is a passthrough that routes the MCP backends it names.
type summarizedBackend struct {
	stubBackend
	names []string
}

func (s summarizedBackend) BackendSummaries() []backend.BackendInfo {
	infos := make([]backend.BackendInfo, 0, len(s.names))
	for _, n := range s.names {
		infos = append(infos, backend.BackendInfo{Name: n})
	}
	return infos
}

func TestUnitNameClashes(t *testing.T) {
	const dice, netdata = "dice", "netdata"
	units := map[string]backend.ToolBackend{dice: stubBackend{}, netdata: stubBackend{}}
	tests := []struct {
		name  string
		named []string
		mcp   []string
		units map[string]backend.ToolBackend
		want  []string
	}{
		{name: "no clash", named: []string{reloadAlpha}, mcp: []string{"beta"}, units: units},
		{name: "named backend", named: []string{netdata}, units: units, want: []string{netdata}},
		{name: "MCP backend", mcp: []string{dice}, units: units, want: []string{dice}},
		{name: "both, sorted", named: []string{netdata}, mcp: []string{dice}, units: units, want: []string{dice, netdata}},
		{name: "no units", named: []string{netdata}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &backendsResult{named: map[string]backend.ToolBackend{}}
			for _, n := range tt.named {
				res.named[n] = stubBackend{}
			}
			res.passthroughs = []backend.ToolBackend{summarizedBackend{names: tt.mcp}}
			if got := unitNameClashes(res, tt.units); !slices.Equal(got, tt.want) {
				t.Errorf("clashes = %v, want %v", got, tt.want)
			}
		})
	}
}
