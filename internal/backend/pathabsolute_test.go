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

package backend

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_PathParamsCannotFormAbsoluteURL pins that only a tool
// path the DADL writes as an absolute URL addresses another host. A path
// parameter keeps its ":", so the values "http:" and a host turn the
// template "{a}//{b}/x" into a URL on that host; a backend without
// credentials would send the request there. Such a call is refused before
// anything is sent, and a path that is absolute in the DADL still works.
func TestRESTAdapter_PathParamsCannotFormAbsoluteURL(t *testing.T) {
	var baseHits, otherHits atomic.Int32
	count := func(n *atomic.Int32) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n.Add(1)
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			_, _ = w.Write([]byte(`{}`))
		})
	}
	base := httptest.NewServer(count(&baseHits))
	defer base.Close()
	other := httptest.NewServer(count(&otherHits))
	defer other.Close()

	segment := func(name string) (string, dadl.ParamDef) {
		return name, dadl.ParamDef{Type: schemaTypeString, In: paramInPath, Required: true}
	}
	params := func(names ...string) map[string]dadl.ParamDef {
		out := map[string]dadl.ParamDef{}
		for _, n := range names {
			k, v := segment(n)
			out[k] = v
		}
		return out
	}
	const (
		assembled, declared = "assembled", "declared"
		partA, partB        = "part_a", "part_b"
	)
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: base.URL,
			Tools: map[string]dadl.ToolDef{
				assembled: {Method: testMethodGET, Path: "{" + partA + "}//{" + partB + "}/x", Params: params(partA, partB)},
				declared:  {Method: testMethodGET, Path: other.URL + "/v1/{item}", Params: params("item")},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}

	otherHost := strings.TrimPrefix(other.URL, "http://")
	result, err := a.Execute(context.Background(), assembled, map[string]any{partA: "http:", partB: otherHost})
	var text string
	switch {
	case err != nil:
		text = err.Error()
	case result != nil && result.IsError:
		text = toolResultText(result)
	default:
		t.Fatalf("the call was not refused: %+v", result)
	}
	if !strings.Contains(text, "into an absolute URL") {
		t.Errorf("the refusal does not say why: %s", text)
	}
	if n := otherHits.Load() + baseHits.Load(); n != 0 {
		t.Errorf("%d requests were sent for the refused call", n)
	}

	// The same template with ordinary values stays on the base host.
	if result, err := a.Execute(context.Background(), assembled, map[string]any{partA: "v1", partB: "items"}); err != nil || result.IsError {
		t.Errorf("ordinary values were refused: %v %+v", err, result)
	}
	if baseHits.Load() != 1 || otherHits.Load() != 0 {
		t.Errorf("ordinary values: base %d, other %d requests; want one on the base host", baseHits.Load(), otherHits.Load())
	}

	// A path that is an absolute URL in the DADL goes to its host.
	if result, err := a.Execute(context.Background(), declared, map[string]any{"item": "42"}); err != nil || result.IsError {
		t.Errorf("the absolute path of the DADL was refused: %v %+v", err, result)
	}
	if otherHits.Load() != 1 {
		t.Errorf("the absolute path of the DADL reached its host %d times, want once", otherHits.Load())
	}
}

// toolResultText joins the text parts of a tool result.
func toolResultText(result *ToolResult) string {
	var b strings.Builder
	for _, c := range result.Content {
		if m, ok := c.(map[string]any); ok {
			if s, ok := m["text"].(string); ok {
				b.WriteString(s)
			}
		}
	}
	return b.String()
}
