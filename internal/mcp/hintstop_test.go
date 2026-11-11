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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// stoppedEntries runs a script that reads and then writes without a proof,
// and returns the call entries of its partial result.
func stoppedEntries(t *testing.T, opts ExecuteOptions) ([]map[string]any, error) {
	t.Helper()
	runner, _ := newProofRunner(t, time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC))
	result, err := runner.ExecuteWithOptions(ctxForUser("alice"), `
		await toolmesh.test_bar({});
		await toolmesh.test_foo({title: "New page"});
		return "done";
	`, opts)
	if err == nil {
		t.Fatal("script ran to completion, want it to stop at the write")
	}
	if result == nil || len(result.Content) == 0 {
		t.Fatal("no partial result")
	}
	block, _ := result.Content[0].(map[string]any)
	text, _ := block[contentKeyText].(string)
	var entries []map[string]any
	if uerr := json.Unmarshal([]byte(text), &entries); uerr != nil {
		t.Fatalf("partial result is not a list of entries: %v\n%s", uerr, text)
	}
	return entries, err
}

// A script reads before it writes. When the write is refused for want of a
// hint proof, the run is repeated, and what it read is read again: the
// partial result lists the read by its size, not with the data.
func TestCodeRunner_HintStopCutsReadResults(t *testing.T) {
	entries, err := stoppedEntries(t, ExecuteOptions{})
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want the read and the refused write", len(entries))
	}
	read := entries[0]
	if _, full := read[resultKeyResult]; full {
		t.Errorf("read entry carries its full result: %v", read)
	}
	if read[resultKeyStatus] != resultStatusOK || read[resultKeyBytes] == nil {
		t.Errorf("read entry = %v, want {tool, status, resultBytes}", read)
	}
	if !strings.Contains(err.Error(), "read calls by the size of their result only") {
		t.Errorf("error does not say that read results were cut:\n%v", err)
	}
}

// With include_results the caller asked for every result in full.
func TestCodeRunner_HintStopKeepsResultsOnRequest(t *testing.T) {
	entries, err := stoppedEntries(t, ExecuteOptions{IncludeResults: true})
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want the read and the refused write", len(entries))
	}
	if _, full := entries[0][resultKeyResult]; !full {
		t.Errorf("read entry lost its result: %v", entries[0])
	}
	if strings.Contains(err.Error(), "by the size of their result only") {
		t.Errorf("error claims results were cut:\n%v", err)
	}
}

// Only successful reads shrink. A call that may have changed something
// keeps its answer, which the caller cannot get again without repeating
// the change; a failed call keeps its message.
func TestCompactReadResults(t *testing.T) {
	ok := func() *backend.ToolResult {
		return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: `{"id": 7}`}}}
	}
	failed := &backend.ToolResult{IsError: true, Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "not found"}}}
	const (
		readTool  = "wiki_read_page"
		writeTool = "tickets_create_ticket"
	)
	in := []any{
		map[string]any{logKeyTool: readTool, resultKeyResult: ok()},
		map[string]any{logKeyTool: writeTool, resultKeyResult: ok()},
		map[string]any{logKeyTool: readTool, resultKeyResult: failed},
		map[string]any{logKeyTool: readTool, outcomeError: "dispatch failed"},
		"not an entry",
	}
	out := compactReadResults(in, func(name string) bool { return name == readTool })

	first, _ := out[0].(map[string]any)
	if _, full := first[resultKeyResult]; full || first[resultKeyStatus] != resultStatusOK || first[resultKeyBytes] != len(`{"id": 7}`) {
		t.Errorf("successful read = %v, want {tool, status, resultBytes}", first)
	}
	for i, name := range map[int]string{1: "write", 2: "failed read", 3: "dispatch failure"} {
		kept, _ := out[i].(map[string]any)
		orig, _ := in[i].(map[string]any)
		if len(kept) != len(orig) || kept[resultKeyResult] != orig[resultKeyResult] {
			t.Errorf("%s entry changed: %v", name, kept)
		}
	}
	if out[4] != "not an entry" {
		t.Errorf("non-entry changed: %v", out[4])
	}
	if _, full := in[0].(map[string]any)[resultKeyResult]; !full {
		t.Error("the input list was modified")
	}
}
