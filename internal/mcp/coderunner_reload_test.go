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

package mcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
)

const (
	rlAlpha  = "alpha"
	rlBeta   = "beta"
	rlNewAPI = "new-api"
	rlPing   = "ping"
	rlPong   = "pong"
	rlLookup = "lookup"

	// Canonical names of the tools the scripts and views below refer to.
	rlAlphaPing = "alpha_ping"
	rlBetaPing  = "beta_ping"

	rlPingV1 = "Pings the alpha service"
	rlPingV2 = "Pings the alpha service, version two"

	// rlBaseline runs before every reload so the runner has already served
	// a script from the startup tool set when the backends are swapped.
	rlBaseline = `return await toolmesh.alpha_ping({})`
)

// reloadTestBackend serves a fixed tool list and answers every call with
// "<label>.<tool>", so a script can tell which backend ran it. onExecute,
// when set, runs before the answer.
type reloadTestBackend struct {
	label     string
	tools     []backend.ToolDescriptor
	onExecute func()
}

func (b *reloadTestBackend) Execute(_ context.Context, toolName string, _ map[string]any) (*backend.ToolResult, error) {
	if b.onExecute != nil {
		b.onExecute()
	}
	return &backend.ToolResult{Content: []any{map[string]any{
		contentKeyType: contentKeyText,
		contentKeyText: b.label + "." + toolName,
	}}}, nil
}

func (b *reloadTestBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return b.tools, nil
}

func (b *reloadTestBackend) Healthy(_ context.Context) error { return nil }

// rlBackend builds a backend whose tools carry the given names, each with a
// description naming the backend.
func rlBackend(label string, toolNames ...string) *reloadTestBackend {
	b := &reloadTestBackend{label: label}
	for _, n := range toolNames {
		b.tools = append(b.tools, backend.ToolDescriptor{
			Name:        n,
			Description: fmt.Sprintf("Runs %s on %s", n, label),
		})
	}
	return b
}

// rlStartup is the backend set the handler is built with.
func rlStartup() map[string]backend.ToolBackend {
	alpha := rlBackend(rlAlpha, rlPing)
	alpha.tools[0].Description = rlPingV1
	return map[string]backend.ToolBackend{rlAlpha: alpha}
}

// newReloadHandler builds a handler over a composite backend holding the
// startup set, the way main wires it.
func newReloadHandler(t *testing.T) (*Handler, *backend.CompositeBackend) {
	t.Helper()
	cb := backend.NewCompositeBackend(rlStartup())
	logger := newQuietMCPLogger()
	exec := executor.New(nil, nil, cb, nil, nil, 5*time.Second, logger, nil, nil)
	return NewHandler(exec, cb, nil, "", nil, logger, false), cb
}

// execScript runs code through execute_code and returns all text blocks of
// the result, joined, and whether the result is an error.
func execScript(h *Handler, code string) (string, bool, error) {
	res, err := h.HandleToolCall(ctxForUser("alice"), toolExecuteCode, map[string]any{argNameCode: code})
	if err != nil {
		return "", false, err
	}
	var texts []string
	for _, c := range res.Content {
		if m, ok := c.(map[string]any); ok {
			if s, ok := m[contentKeyText].(string); ok {
				texts = append(texts, s)
			}
		}
	}
	return strings.Join(texts, "\n"), res.IsError, nil
}

// runScript is execScript for the test goroutine.
func runScript(t *testing.T, h *Handler, code string) (string, bool) {
	t.Helper()
	text, isErr, err := execScript(h, code)
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	return text, isErr
}

// A hot reload of backends.yaml swaps the composite backend's children. The
// next execute_code script must see the tool set as it is after the swap:
// added backends and tools callable, removed ones gone, changed descriptions
// visible to the in-sandbox discovery helpers. Before the fix, the runner
// kept the name table it was built with at startup.
func TestExecuteCode_SeesHotReloadedBackends(t *testing.T) {
	tests := []struct {
		name    string
		after   func() map[string]backend.ToolBackend
		code    string
		want    string
		wantErr bool
	}{
		{
			name: "added backend is callable",
			after: func() map[string]backend.ToolBackend {
				m := rlStartup()
				m[rlBeta] = rlBackend(rlBeta, rlPing)
				return m
			},
			code: `return await toolmesh.beta_ping({})`,
			want: "beta.ping",
		},
		{
			name: "added backend with a hyphen is callable by its sanitized name",
			after: func() map[string]backend.ToolBackend {
				m := rlStartup()
				m[rlNewAPI] = rlBackend(rlNewAPI, rlPing)
				return m
			},
			code: `return await toolmesh.new_api_ping({})`,
			want: "new-api.ping",
		},
		{
			name: "tool added to a kept backend is callable",
			after: func() map[string]backend.ToolBackend {
				return map[string]backend.ToolBackend{rlAlpha: rlBackend(rlAlpha, rlPing, rlPong)}
			},
			code: `return await toolmesh.alpha_pong({})`,
			want: "alpha.pong",
		},
		{
			name: "removed backend is gone",
			after: func() map[string]backend.ToolBackend {
				return map[string]backend.ToolBackend{rlBeta: rlBackend(rlBeta, rlPing)}
			},
			code:    rlBaseline,
			want:    "no member 'alpha_ping'",
			wantErr: true,
		},
		{
			name: "describe shows the reloaded description",
			after: func() map[string]backend.ToolBackend {
				m := rlStartup()
				m[rlAlpha].(*reloadTestBackend).tools[0].Description = rlPingV2
				return m
			},
			code: `return toolmesh.describe("alpha_ping").description`,
			want: rlPingV2,
		},
		{
			name: "discover finds a tool of the added backend",
			after: func() map[string]backend.ToolBackend {
				m := rlStartup()
				m[rlBeta] = rlBackend(rlBeta, rlLookup)
				return m
			},
			code: `return toolmesh.discover("lookup").map(t => t.name)`,
			want: "beta_lookup",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, cb := newReloadHandler(t)
			if text, isErr := runScript(t, h, rlBaseline); isErr || !strings.Contains(text, "alpha.ping") {
				t.Fatalf("baseline run = %q (error %v), want alpha.ping", text, isErr)
			}

			cb.Swap(tc.after(), nil)

			text, isErr := runScript(t, h, tc.code)
			if isErr != tc.wantErr {
				t.Fatalf("error = %v, want %v; result: %s", isErr, tc.wantErr, text)
			}
			if !strings.Contains(text, tc.want) {
				t.Errorf("result = %q, want it to contain %q", text, tc.want)
			}
		})
	}
}

// A script keeps the tool set it started with even when a reload lands while
// it runs; the next script sees the new one.
func TestExecuteCode_RunKeepsItsToolSet(t *testing.T) {
	h, cb := newReloadHandler(t)

	var once sync.Once
	alpha := rlBackend(rlAlpha, rlPing)
	alpha.onExecute = func() {
		once.Do(func() {
			cb.Swap(map[string]backend.ToolBackend{
				rlAlpha: rlBackend(rlAlpha, rlPing),
				rlBeta:  rlBackend(rlBeta, rlPing),
			}, nil)
		})
	}
	cb.Swap(map[string]backend.ToolBackend{rlAlpha: alpha}, nil)

	const probe = `await toolmesh.alpha_ping({}); return typeof toolmesh.beta_ping`
	if text, _ := runScript(t, h, probe); !strings.Contains(text, `"undefined"`) {
		t.Errorf("run during the reload: typeof toolmesh.beta_ping = %s, want undefined", text)
	}
	if text, _ := runScript(t, h, probe); !strings.Contains(text, `"function"`) {
		t.Errorf("run after the reload: typeof toolmesh.beta_ping = %s, want function", text)
	}
}

// Scripts run while reloads swap the backends back and forth. Each script
// must either call the tool or fail cleanly on a missing member, never see a
// half-built tool set; run with -race to check the shared state.
func TestExecuteCode_ConcurrentRunsDuringReloads(t *testing.T) {
	h, cb := newReloadHandler(t)
	withBeta := func() map[string]backend.ToolBackend {
		m := rlStartup()
		m[rlBeta] = rlBackend(rlBeta, rlPing)
		return m
	}

	stop := make(chan struct{})
	var swaps sync.WaitGroup
	swaps.Add(1)
	go func() {
		defer swaps.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				cb.Swap(withBeta(), nil)
			} else {
				cb.Swap(rlStartup(), nil)
			}
		}
	}()

	var runs sync.WaitGroup
	for w := 0; w < 4; w++ {
		runs.Add(1)
		go func() {
			defer runs.Done()
			for i := 0; i < 20; i++ {
				text, _, err := execScript(h, `return await toolmesh.beta_ping({})`)
				if err != nil {
					t.Errorf("HandleToolCall: %v", err)
					return
				}
				if !strings.Contains(text, "beta.ping") && !strings.Contains(text, "no member 'beta_ping'") &&
					!strings.Contains(text, "no backend found") {
					t.Errorf("unexpected result: %s", text)
					return
				}
			}
		}()
	}
	runs.Wait()
	close(stop)
	swaps.Wait()
}

// The hint preflight reads the tool names a script uses from the same view
// the run gets, so a script naming a tool of a reloaded backend is checked
// against that backend's hint before it runs.
func TestExecuteCode_PreflightNamesFollowReload(t *testing.T) {
	tests := []struct {
		name  string
		after func() map[string]backend.ToolBackend
		code  string
		want  []string
	}{
		{
			name: "tool of an added backend is named",
			after: func() map[string]backend.ToolBackend {
				m := rlStartup()
				m[rlBeta] = rlBackend(rlBeta, rlPing)
				return m
			},
			code: `await toolmesh.alpha_ping({}); return toolmesh["beta_ping"]({})`,
			want: []string{rlAlphaPing, rlBetaPing},
		},
		{
			name: "tool of a removed backend is not named",
			after: func() map[string]backend.ToolBackend {
				return map[string]backend.ToolBackend{rlBeta: rlBackend(rlBeta, rlPing)}
			},
			code: `await toolmesh.alpha_ping({}); return toolmesh.beta_ping({})`,
			want: []string{rlBetaPing},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, cb := newReloadHandler(t)
			cb.Swap(tc.after(), nil)
			got := h.codeRunner.currentView(context.Background()).namedTools(tc.code)
			if !slices.Equal(got, tc.want) {
				t.Errorf("namedTools = %v, want %v", got, tc.want)
			}
		})
	}
}

// fakeToolSource is a versioned tool listing whose version, tools and
// listing error a test sets, and which counts how often it was listed.
type fakeToolSource struct {
	version atomic.Uint64
	lists   atomic.Int32

	mu    sync.Mutex
	tools []backend.ToolDescriptor
	err   error
}

func (s *fakeToolSource) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	s.lists.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tools, s.err
}

func (s *fakeToolSource) ToolSetVersion() uint64 { return s.version.Load() }

// set publishes a new tool list and listing error, then moves the version,
// in the order backend.ToolSetVersioner asks for.
func (s *fakeToolSource) set(err error, names ...string) {
	s.mu.Lock()
	s.tools = nil
	for _, n := range names {
		s.tools = append(s.tools, backend.ToolDescriptor{Name: n})
	}
	s.err = err
	s.mu.Unlock()
	s.version.Add(1)
}

// newFollowingRunner builds a code runner over src's current tools that
// follows src, the way NewHandler wires one to the composite backend.
func newFollowingRunner(src *fakeToolSource) *CodeRunner {
	version := src.ToolSetVersion()
	tools, _ := src.ListTools(context.Background())
	r := NewCodeRunner(NewCodeModeParser(tools).nameMap, tools, nil, nil, newQuietMCPLogger())
	r.followToolSet(src, version)
	return r
}

// The runner lists the tools again only when the source's version moved,
// once per change, and a failed listing leaves the previous tool set in
// place until a later run lists successfully.
func TestCodeRunner_CurrentView(t *testing.T) {
	errListing := errors.New("listing failed")
	tests := []struct {
		name string
		// change runs between the startup listing and the runs; nil
		// changes nothing.
		change func(src *fakeToolSource)
		// runs is how many runs take a view in a row.
		runs      int
		wantTools []string
		wantLists int32 // listings after startup
	}{
		{
			name:      "unchanged version keeps the startup view",
			runs:      3,
			wantTools: []string{rlAlphaPing},
			wantLists: 0,
		},
		{
			name:      "moved version lists once for all later runs",
			change:    func(src *fakeToolSource) { src.set(nil, rlAlphaPing, rlBetaPing) },
			runs:      3,
			wantTools: []string{rlAlphaPing, rlBetaPing},
			wantLists: 1,
		},
		{
			name:      "failed listing keeps the previous view and is retried",
			change:    func(src *fakeToolSource) { src.set(errListing, rlBetaPing) },
			runs:      3,
			wantTools: []string{rlAlphaPing},
			wantLists: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeToolSource{}
			src.set(nil, rlAlphaPing)
			r := newFollowingRunner(src)
			startup := src.lists.Load()
			if tc.change != nil {
				tc.change(src)
			}

			var view *toolView
			for i := 0; i < tc.runs; i++ {
				view = r.currentView(context.Background())
			}

			got := make([]string, 0, len(view.nameMap))
			for _, canonical := range view.nameMap {
				got = append(got, canonical)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.wantTools) {
				t.Errorf("tools = %v, want %v", got, tc.wantTools)
			}
			if lists := src.lists.Load() - startup; lists != tc.wantLists {
				t.Errorf("listings = %d, want %d", lists, tc.wantLists)
			}
		})
	}
}

// After a change, runs that start at the same time share one listing: the
// first lists, the others wait for its view instead of listing again.
func TestCodeRunner_CurrentViewListsOnceForConcurrentRuns(t *testing.T) {
	src := &fakeToolSource{}
	src.set(nil, rlAlphaPing)
	r := newFollowingRunner(src)
	startup := src.lists.Load()
	src.set(nil, rlAlphaPing, rlBetaPing)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := r.currentView(context.Background()).nameMap[rlBetaPing]; !ok {
				t.Error("view after the change lacks beta_ping")
			}
		}()
	}
	wg.Wait()
	if lists := src.lists.Load() - startup; lists != 1 {
		t.Errorf("listings = %d, want 1", lists)
	}
}
