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

// The sandbox error contract test drives the same tool failures through both
// JavaScript sandboxes — execute_code (CodeRunner) and DADL composites (the
// composite engine inside the REST adapter) — and pins the shape in which
// each failure reaches the script. The failures come from the real pipeline:
// a REST backend with an errors config, the embedded authorization engine, a
// gate policy and an upstream MCP server. Both sandboxes run the same probe
// script: it calls the tool, catches whatever is thrown and reports what it
// saw.
//
// Each case has three subtests:
//
//   - execute_code: the shape the script sees in execute_code today.
//   - composite: the shape the script sees in a composite today.
//   - contract: whether both sandboxes report the failure the same way —
//     both throw with the same code, both return the same kind of value, or
//     both abort the run.
//
// Where the sandboxes differ, the case records the divergence and the
// contract subtest is skipped with it, so a divergence is never accepted
// silently. The contract subtest fails as soon as the sandboxes agree: the
// note goes together with the divergence, and the per-sandbox expectations
// change with it. Changing how a sandbox reports failures changes the
// interface scripts are written against; record such a change as an ADR
// under docs/adr.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Fixture names of the error contract test.
const (
	ecUser         = "u1"
	ecShop         = "shop"  // REST backend (DADL) holding the probe composites
	ecRelay        = "relay" // upstream MCP backend
	ecProbe        = "probe"
	ecProbeShort   = "probe_short"
	ecParamID      = "id"
	ecTypeString   = "string"
	ecTypeObject   = "object"
	ecAccessRead   = "read"
	ecAccessWrite  = "write"
	ecAccessDanger = "dangerous"
	ecInPath       = "path"
	ecMissingID    = "missing"
	ecContentJSON  = "application/json"
	ecHeaderCT     = "Content-Type"
	ecKindString   = "string"
	ecKindObject   = "object"
	ecKindUndef    = "undefined"
	ecKindError    = "error"
	ecUpstreamText = "upstream lookup failed: no record 42"
)

// Timing of the two deadline cases. The REST client gives up on a request
// after ecHTTPTimeout. A short run has ecShortRun in all; the gate holds the
// call in it for ecGateHold, without watching the context, so that the run's
// deadline has passed (and the sandbox has been told to stop) well before the
// call returns.
const (
	ecHTTPTimeout = 250 * time.Millisecond
	ecShortRun    = 200 * time.Millisecond
	ecGateHold    = 600 * time.Millisecond
)

// ecProbeScript is the script body both sandboxes run; the sandbox-specific
// prefix defines call(). It reports either the value the call resolved to or
// the error it threw, with the semantic fields a composite error carries.
const ecProbeScript = `
let out;
try {
  const v = await call();
  out = {threw: false, kind: v === undefined ? "undefined" : v === null ? "null" : Array.isArray(v) ? "array" : typeof v};
  if (typeof v === "string") { out.text = v; } else if (v !== undefined) { out.text = JSON.stringify(v); }
  if (out.kind === "object") { out.keys = Object.keys(v).sort().join(","); }
} catch (e) {
  out = {threw: true, kind: "error", text: String(e && e.message !== undefined ? e.message : e)};
  if (e && e.code !== undefined) { out.code = e.code; }
  if (e && e.http_status !== undefined) { out.http_status = e.http_status; }
  if (e && e.provider_code !== undefined) { out.provider_code = e.provider_code; }
}
return out;
`

// ecPolicy is the gate policy of the fixture: one pre-execution rejection,
// one post-execution rejection, and a pre-execution hold for the run
// deadline case. The hold busy-waits because a policy cannot watch the
// call's context.
var ecPolicy = fmt.Sprintf(`
if (ctx.phase === "pre" && ctx.tool === "shop_archive_item") {
    throw "archiving needs an approval";
}
if (ctx.phase === "post" && ctx.tool === "shop_get_secret") {
    throw "response withheld: it contains a credential";
}
if (ctx.phase === "pre" && ctx.tool === "shop_report") {
    var until = Date.now() + %d;
    while (Date.now() < until) {}
}
`, ecGateHold.Milliseconds())

// ecShape is the expected outcome of the probe in one sandbox. Every field
// but the text must match exactly; the text must start with prefix and
// contain contains.
type ecShape struct {
	aborted      bool
	threw        bool
	kind         string
	keys         string
	code         string
	httpStatus   int
	providerCode string
	prefix       string
	contains     string
}

// ecOutcome is what the probe reported, or — when Aborted — that the run
// ended before the script could report anything; Text then holds the error
// the caller of the sandbox received.
type ecOutcome struct {
	Aborted      bool   `json:"-"`
	Threw        bool   `json:"threw"`
	Kind         string `json:"kind"`
	Text         string `json:"text"`
	Keys         string `json:"keys"`
	Code         string `json:"code"`
	HTTPStatus   int    `json:"http_status"`
	ProviderCode string `json:"provider_code"`
}

// signal is how the outcome lets the script tell what happened, the part of
// the outcome both sandboxes must share to report a failure the same way.
func (o ecOutcome) signal() string {
	switch {
	case o.Aborted:
		return "aborts the run"
	case o.Threw:
		return fmt.Sprintf("throws (code %q)", o.Code)
	default:
		return "returns a value of kind " + o.Kind
	}
}

func (s ecShape) check(t *testing.T, got ecOutcome) {
	t.Helper()
	if got.Aborted != s.aborted || got.Threw != s.threw || got.Kind != s.kind ||
		got.Keys != s.keys || got.Code != s.code || got.HTTPStatus != s.httpStatus ||
		got.ProviderCode != s.providerCode ||
		!strings.HasPrefix(got.Text, s.prefix) || !strings.Contains(got.Text, s.contains) {
		t.Errorf("probe outcome\n got: %+v\nwant: %+v", got, s)
	}
}

// ecCase is one failure, driven through both sandboxes.
type ecCase struct {
	name string
	// tool is the canonical tool name. execute_code calls it as
	// toolmesh.<tool>, the probe composite as api.<tool without "shop_">.
	tool string
	args map[string]any
	// shortRun bounds the whole run by ecShortRun: execute_code's budget
	// and the timeout of the short probe composite.
	shortRun bool

	codeMode ecShape
	// composite is nil when a composite cannot make the call at all;
	// noComposite says why.
	composite   *ecShape
	noComposite string
	// divergence names how the sandboxes report the failure differently;
	// empty when they agree.
	divergence string
}

func TestSandboxErrorContract(t *testing.T) {
	f := newECFixture(t)

	cases := []ecCase{
		{
			name: "REST error mapped by the errors config",
			tool: "shop_get_item",
			args: map[string]any{ecParamID: ecMissingID},
			codeMode: ecShape{
				kind:   ecKindString,
				prefix: "Error: [not_found] HTTP 404: No item with id missing (provider_code=item_missing)",
			},
			composite: &ecShape{
				threw: true, kind: ecKindError,
				code: dadl.ErrCodeNotFound, httpStatus: http.StatusNotFound, providerCode: "item_missing",
				prefix: "composite probe: api.get_item failed: [not_found] HTTP 404",
			},
			divergence: "execute_code returns the error text as a string; a composite throws an error carrying code, http_status and provider_code",
		},
		{
			name: "undeclared parameter rejected before the request",
			tool: "shop_list_items",
			args: map[string]any{"limt": 5},
			codeMode: ecShape{
				kind:     ecKindString,
				prefix:   `Error: tool "list_items": unknown parameter "limt"`,
				contains: `did you mean "limit"`,
			},
			composite: &ecShape{
				threw: true, kind: ecKindError,
				code: dadl.ErrCodeInvalidInput, httpStatus: http.StatusBadRequest,
				prefix: "composite probe: api.list_items failed:",
			},
			divergence: "execute_code returns the rejection as a string; a composite throws it with code invalid_input",
		},
		{
			// In the standard wiring the coercer is keyed by the bare names of
			// the TypeScript tool definitions, while calls carry the backend
			// prefix, so it does not apply to routed tools. The fixture keys
			// it by the canonical name to reach this branch.
			name:        "argument the coercer cannot convert",
			tool:        "echo_add",
			args:        map[string]any{"a": "two", "b": 1},
			codeMode:    ecShape{kind: ecKindUndef},
			noComposite: "a composite calls only the tools of its own DADL backend, and those are not coerced",
		},
		{
			name: "call denied by authorization",
			tool: "shop_delete_item",
			args: map[string]any{ecParamID: "42"},
			codeMode: ecShape{
				kind:   ecKindString,
				prefix: "User u1 is not authorized to execute tool shop_delete_item.",
			},
			composite: &ecShape{
				threw: true, kind: ecKindError,
				prefix: "composite probe: api.delete_item failed: user u1 is not authorized to execute child tool shop_delete_item",
			},
			divergence: "execute_code returns the denial as a string without the \"Error: \" prefix; a composite throws it without a code",
		},
		{
			name: "call rejected by the pre-execution gate",
			tool: "shop_archive_item",
			args: map[string]any{ecParamID: "42"},
			codeMode: ecShape{
				kind:   ecKindString,
				prefix: "Gate rejected (pre-execution): evaluator goja rejected: policy errcontract.js: archiving needs an approval",
			},
			composite: &ecShape{
				threw: true, kind: ecKindError,
				prefix:   "composite probe: api.archive_item failed: gate rejected child tool shop_archive_item",
				contains: "archiving needs an approval",
			},
			divergence: "execute_code returns the rejection as a string without the \"Error: \" prefix; a composite throws it without a code",
		},
		{
			name: "response rejected by the post-execution gate",
			tool: "shop_get_secret",
			codeMode: ecShape{
				kind:   ecKindString,
				prefix: "Gate rejected (post-execution): evaluator goja rejected: policy errcontract.js: response withheld: it contains a credential",
			},
			composite: &ecShape{
				kind: ecKindObject, keys: "token",
			},
			divergence: "a composite's child call does not pass the post-execution gate (it runs once, on the composite's result), so the composite receives the response the gate rejects in execute_code",
		},
		{
			name:        "MCP upstream reports isError with a text message",
			tool:        "relay_lookup",
			args:        map[string]any{ecParamID: "42"},
			codeMode:    ecShape{kind: ecKindString, prefix: ecUpstreamText},
			noComposite: "a composite calls only the tools of its own DADL backend",
		},
		{
			// The parsed error text cannot be told apart from a successful
			// result.
			name:        "MCP upstream reports isError with a JSON text",
			tool:        "relay_lookup_json",
			args:        map[string]any{ecParamID: "42"},
			codeMode:    ecShape{kind: ecKindObject, keys: "detail,error", contains: `"error":"not_found"`},
			noComposite: "a composite calls only the tools of its own DADL backend",
		},
		{
			name: "REST tool error without a semantic code",
			tool: "shop_import_items",
			args: map[string]any{"source": "tm-blob://a1b2c3d4"},
			codeMode: ecShape{
				kind:   ecKindString,
				prefix: `Error: parameter "source": blob handle "tm-blob://a1b2c3d4" needs an explicit format fragment`,
			},
			composite: &ecShape{
				threw: true, kind: ecKindError,
				prefix:   "composite probe: api.import_items failed: tool import_items returned error:",
				contains: "needs an explicit format fragment",
			},
			divergence: "execute_code returns the error text as a string; a composite throws it without a code",
		},
		{
			name: "backend request timeout",
			tool: "shop_export_items",
			codeMode: ecShape{
				kind: ecKindObject, keys: "error,tool",
				prefix:   `{"error":"backend execution failed for shop_export_items: execute REST tool \"export_items\": http request:`,
				contains: "Client.Timeout exceeded",
			},
			composite: &ecShape{
				threw: true, kind: ecKindError,
				prefix:   `composite probe: api.export_items failed: execute REST tool "export_items": http request:`,
				contains: "Client.Timeout exceeded",
			},
			divergence: "execute_code returns an object {error, tool}; a composite throws without a code",
		},
		{
			// A canceled request context takes the same path: the sandbox is
			// interrupted, and the script gets no chance to handle it.
			name:     "run deadline passes during a call",
			tool:     "shop_report",
			shortRun: true,
			codeMode: ecShape{
				aborted:  true,
				prefix:   "execute_code: interrupted:",
				contains: "context deadline exceeded",
			},
			composite: &ecShape{
				aborted:  true,
				prefix:   "Error: composite probe_short: interrupted:",
				contains: "context deadline exceeded",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codeMode := f.runCodeMode(t, tc)
			var comp ecOutcome
			if tc.composite != nil {
				comp = f.runComposite(t, tc)
			}

			t.Run("execute_code", func(t *testing.T) {
				tc.codeMode.check(t, codeMode)
			})
			t.Run("composite", func(t *testing.T) {
				if tc.composite == nil {
					t.Skip("no composite counterpart: " + tc.noComposite)
				}
				tc.composite.check(t, comp)
			})
			t.Run("contract", func(t *testing.T) {
				if tc.composite == nil {
					t.Skip("no composite counterpart: " + tc.noComposite)
				}
				same := codeMode.signal() == comp.signal()
				switch {
				case tc.divergence == "" && !same:
					t.Errorf("sandboxes disagree: execute_code %s, a composite %s", codeMode.signal(), comp.signal())
				case tc.divergence != "" && same:
					t.Errorf("both sandboxes now %s; remove the divergence note %q", codeMode.signal(), tc.divergence)
				case tc.divergence != "":
					t.Skipf("TODO: known divergence (execute_code %s, a composite %s): %s",
						codeMode.signal(), comp.signal(), tc.divergence)
				}
			})
		})
	}
}

// ecFixture is the pipeline both sandboxes run against: a caller context,
// the executor and the code runner of an MCP handler built on it.
type ecFixture struct {
	ctx    context.Context
	exec   *executor.Executor
	runner *CodeRunner
}

// newECFixture wires the pipeline the way the server does: a composite
// backend with a REST backend (DADL), the built-in echo backend and an
// upstream MCP backend; the embedded authorization engine; a gate pipeline;
// and the executor as the child guard of composites.
func newECFixture(t *testing.T) *ecFixture {
	t.Helper()
	logger := handlerTestLogger()
	creds := credentials.NewEmbeddedStore()

	shop, err := backend.NewRESTAdapter(ecSpec(newECAPI(t).URL), creds, logger, backend.RESTAdapterOptions{AllowPrivateURL: true})
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}
	shop.SetHTTPTimeout(ecHTTPTimeout)

	upstream := newECUpstream(t)
	relay := backend.NewMCPAdapterFromEntries([]backend.BackendEntry{
		{Name: ecRelay, Transport: "http", URL: upstream.URL},
	}, creds, logger)
	if err := relay.Connect(context.Background()); err != nil {
		t.Fatalf("connect upstream MCP backend: %v", err)
	}
	t.Cleanup(relay.Close)

	cb := backend.NewCompositeBackend(map[string]backend.ToolBackend{ecShop: shop})
	cb.AddNamed("echo", backend.NewEchoBackend())
	cb.AddPassthrough(relay)
	if _, ok := relay.LookupTool("relay_lookup"); !ok {
		t.Fatal("upstream MCP backend did not register its tools")
	}

	engine, err := authz.OpenEmbedded(context.Background(), authz.EmbeddedOptions{Path: filepath.Join(t.TempDir(), authz.DBFileName)})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	grants := []authz.Grant{{User: ecUser, AllTools: true}}
	denies := []authz.Grant{{User: ecUser, Tools: []string{"shop_delete_item"}}}
	if _, err := engine.Apply(context.Background(), grants, denies); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	policies := t.TempDir()
	if err := os.WriteFile(filepath.Join(policies, "errcontract.js"), []byte(ecPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(policies, logger)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	exec := executor.New(engine, nil, cb, gate.NewPipeline([]gate.Evaluator{g}), nil, 10*time.Second, logger, nil, nil)
	cb.SetChildGuard(exec)

	coercer := tsdef.NewCoercer([]tsdef.ToolDef{{
		Name: "echo_add",
		Params: []tsdef.ParamDef{
			{Name: "a", Type: tsdef.ParamType{Kind: jsonTypeNumber}, Required: true},
			{Name: "b", Type: tsdef.ParamType{Kind: jsonTypeNumber}, Required: true},
		},
	}}, logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: ecUser, Authenticated: true})

	// One call through the whole pipeline first, so that no case pays for a
	// cold authorization engine or connection; the deadline cases rely on the
	// checks before the gate being fast.
	warm, err := exec.ExecuteTool(ctx, executor.ExecuteToolRequest{ToolName: "shop_list_items", Params: map[string]any{}})
	if err != nil || warm.IsError {
		t.Fatalf("warm-up call: %v %+v", err, warm)
	}

	return &ecFixture{
		ctx:    ctx,
		exec:   exec,
		runner: NewHandler(exec, cb, coercer, "", nil, logger, false).codeRunner,
	}
}

// runCodeMode runs the probe in execute_code against tc.tool.
func (f *ecFixture) runCodeMode(t *testing.T, tc ecCase) ecOutcome {
	t.Helper()
	if tc.shortRun {
		f.runner.SetTimeout(ecShortRun)
		defer f.runner.SetTimeout(0)
	}
	args, err := json.Marshal(tc.args)
	if err != nil {
		t.Fatal(err)
	}
	if tc.args == nil {
		args = []byte("{}")
	}
	code := fmt.Sprintf("const call = () => toolmesh.%s(%s);\n%s", sanitizeName(tc.tool), args, ecProbeScript)

	res, err := f.runner.ExecuteWithOptions(f.ctx, code, ExecuteOptions{})
	if err != nil {
		return ecOutcome{Aborted: true, Text: err.Error()}
	}
	text := ecResultText(t, res)
	if res.IsError {
		return ecOutcome{Aborted: true, Text: text}
	}

	// With tool calls the response lists them, followed by {return: ...}.
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &entries); err == nil {
		for _, e := range entries {
			if ret, ok := e[resultKeyReturn]; ok {
				return ecDecode(t, ret)
			}
		}
		t.Fatalf("execute_code response has no return entry: %s", text)
	}
	return ecDecode(t, []byte(text))
}

// runComposite runs the probe composite of the shop backend against
// tc.tool, called like any tool through the executor.
func (f *ecFixture) runComposite(t *testing.T, tc ecCase) ecOutcome {
	t.Helper()
	probe := ecProbe
	if tc.shortRun {
		probe = ecProbeShort
	}
	args := tc.args
	if args == nil {
		args = map[string]any{}
	}
	res, err := f.exec.ExecuteTool(f.ctx, executor.ExecuteToolRequest{
		ToolName: ecShop + "_" + probe,
		Params: map[string]any{
			"tool": strings.TrimPrefix(tc.tool, ecShop+"_"),
			"args": args,
		},
	})
	if err != nil {
		return ecOutcome{Aborted: true, Text: err.Error()}
	}
	text := ecResultText(t, res)
	if res.IsError {
		return ecOutcome{Aborted: true, Text: text}
	}
	return ecDecode(t, []byte(text))
}

func ecResultText(t *testing.T, res *backend.ToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("empty tool result: %+v", res)
	}
	block, _ := res.Content[0].(map[string]any)
	text, _ := block[contentKeyText].(string)
	return text
}

func ecDecode(t *testing.T, raw []byte) ecOutcome {
	t.Helper()
	var o ecOutcome
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode probe report %s: %v", raw, err)
	}
	return o
}

// ecSpec is the DADL of the shop backend: one tool per failure and two probe
// composites, which differ only in their timeout.
func ecSpec(baseURL string) *dadl.Spec {
	probe := dadl.CompositeDef{
		Description: "Calls one tool of this backend and reports how the outcome reached the script",
		Code:        "const call = () => api[params.tool](params.args || {});\n" + ecProbeScript,
		Access:      ecAccessRead,
		Params: map[string]dadl.ParamDef{
			"tool": {Type: ecTypeString, Required: true},
			"args": {Type: ecTypeObject},
		},
		Timeout: "10s",
	}
	short := probe
	short.Timeout = ecShortRun.String()

	idParam := map[string]dadl.ParamDef{ecParamID: {Type: ecTypeString, In: ecInPath, Required: true}}
	return &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.2.md",
		Backend: dadl.BackendDef{
			Name:    ecShop,
			Type:    "rest",
			BaseURL: baseURL,
			Tools: map[string]dadl.ToolDef{
				"get_item": {
					Method: http.MethodGet, Path: "/items/{id}", Access: ecAccessRead, Params: idParam,
					Errors: &dadl.ErrorConfig{
						Format:      "json",
						MessagePath: "$.error.message",
						CodePath:    "$.error.code",
						Map:         map[int]string{http.StatusNotFound: dadl.ErrCodeNotFound},
					},
				},
				"list_items": {
					Method: http.MethodGet, Path: "/items", Access: ecAccessRead,
					Params: map[string]dadl.ParamDef{"limit": {Type: "integer", In: "query"}},
				},
				"archive_item": {Method: http.MethodPost, Path: "/items/{id}/archive", Access: ecAccessWrite, Params: idParam},
				"delete_item":  {Method: http.MethodDelete, Path: "/items/{id}", Access: ecAccessDanger, Params: idParam},
				"get_secret":   {Method: http.MethodGet, Path: "/secret", Access: ecAccessRead},
				"import_items": {
					Method: http.MethodPost, Path: "/import", Access: ecAccessWrite,
					Params: map[string]dadl.ParamDef{"source": {Type: ecTypeString, In: "body", Required: true}},
				},
				"export_items": {Method: http.MethodGet, Path: "/export", Access: ecAccessRead},
				"report":       {Method: http.MethodGet, Path: "/report", Access: ecAccessRead},
			},
			Composites: map[string]dadl.CompositeDef{
				ecProbe:      probe,
				ecProbeShort: short,
			},
		},
	}
}

// newECAPI serves the REST API behind the shop backend.
func newECAPI(t *testing.T) *httptest.Server {
	t.Helper()
	reply := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set(ecHeaderCT, ecContentJSON)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue(ecParamID) == ecMissingID {
			reply(w, http.StatusNotFound, `{"error": {"code": "item_missing", "message": "No item with id missing"}}`)
			return
		}
		reply(w, http.StatusOK, `{"id": "1"}`)
	})
	mux.HandleFunc("GET /items", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `[{"id": "1"}]`)
	})
	mux.HandleFunc("POST /items/{id}/archive", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"archived": true}`)
	})
	mux.HandleFunc("DELETE /items/{id}", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"deleted": true}`)
	})
	mux.HandleFunc("GET /secret", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"token": "not-a-real-token"}`)
	})
	mux.HandleFunc("POST /import", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"imported": 1}`)
	})
	mux.HandleFunc("GET /export", func(w http.ResponseWriter, r *http.Request) {
		// Answers only after the client has given up.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * ecHTTPTimeout):
		}
	})
	mux.HandleFunc("GET /report", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"rows": 0}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newECUpstream serves an MCP server over Streamable HTTP whose tools answer
// with isError: one with a plain text, one with a text that is valid JSON.
func newECUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: ecRelay, Version: "1.0.0"}, nil)
	schema := map[string]any{
		"type":       ecTypeObject,
		"properties": map[string]any{ecParamID: map[string]any{"type": ecTypeString}},
	}
	failWith := func(text string) mcpsdk.ToolHandler {
		return func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			return &mcpsdk.CallToolResult{
				IsError: true,
				Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: text}},
			}, nil
		}
	}
	server.AddTool(&mcpsdk.Tool{Name: "lookup", Description: "Looks up a record", InputSchema: schema},
		failWith(ecUpstreamText))
	server.AddTool(&mcpsdk.Tool{Name: "lookup_json", Description: "Looks up a record, answering in JSON", InputSchema: schema},
		failWith(`{"error": "not_found", "detail": "no record 42"}`))

	srv := httptest.NewServer(mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return server }, nil))
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv
}
