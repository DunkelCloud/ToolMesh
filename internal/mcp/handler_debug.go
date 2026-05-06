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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// debugMaxGenerateBytes caps the size of generated payloads so debug_generate
// can't be used to exhaust memory or transport buffers.
const debugMaxGenerateBytes = 10 * 1024 * 1024 // 10 MB

// debugAsciiCharset is the alphabet used for the deterministic "ascii" pattern.
const debugAsciiCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// debugDisabledResult is returned when a caller invokes a debug tool while
// TOOLMESH_DEBUG_TOOLS is off. It points to the env var so the operator
// knows what to flip.
func debugDisabledResult(name string) *backend.ToolResult {
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: fmt.Sprintf("%s is disabled (set TOOLMESH_DEBUG_TOOLS=true to enable diagnostic tools)", name),
		}},
	}
}

// debugErrorResult wraps a plain text error in the standard ToolResult shape.
func debugErrorResult(msg string) *backend.ToolResult {
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: msg,
		}},
	}
}

// debugTextResult wraps a JSON-encoded payload in the standard ToolResult shape.
func debugTextResult(payload map[string]any) *backend.ToolResult {
	body, err := json.Marshal(payload)
	if err != nil {
		return debugErrorResult(fmt.Sprintf("debug: marshal result: %s", err))
	}
	return &backend.ToolResult{
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: string(body),
		}},
	}
}

// handleDebugEcho echoes back size and integrity metadata for the supplied
// payload. It does not call any backend, so the round-trip measures only the
// LLM-client → MCP server path plus minimal handler overhead.
func (h *Handler) handleDebugEcho(params map[string]any) *backend.ToolResult {
	payload, ok := params[argNamePayload]
	if !ok {
		return debugErrorResult("Missing required parameter: payload")
	}

	bytes, ptype, hashInput, chars := classifyPayload(payload)
	sum := sha256.Sum256(hashInput)

	out := map[string]any{
		"received_bytes": bytes,
		contentKeyType:   ptype,
		"sha256":         hex.EncodeToString(sum[:]),
	}
	if ptype == jsonTypeString {
		out["received_chars"] = chars
	}
	return debugTextResult(out)
}

// classifyPayload returns the byte size, type label, canonical hash input
// and (for strings) the rune count of an arbitrary JSON value.
func classifyPayload(payload any) (bytes int, ptype string, hashInput []byte, chars int) {
	switch v := payload.(type) {
	case string:
		return len(v), jsonTypeString, []byte(v), utf8.RuneCountInString(v)
	case map[string]any:
		b, _ := json.Marshal(v)
		return len(b), jsonTypeObject, b, 0
	case []any:
		b, _ := json.Marshal(v)
		return len(b), jsonTypeArray, b, 0
	case float64:
		b, _ := json.Marshal(v)
		return len(b), jsonTypeNumber, b, 0
	case bool:
		b, _ := json.Marshal(v)
		return len(b), jsonTypeBoolean, b, 0
	case nil:
		return 4, jsonTypeNull, []byte(jsonTypeNull), 0
	default:
		b, _ := json.Marshal(v)
		return len(b), fmt.Sprintf("%T", v), b, 0
	}
}

// handleDebugGenerate produces a string of exactly size_bytes characters and
// returns it together with metadata. Used to probe the maximum response size
// the calling transport will accept from ToolMesh.
func (h *Handler) handleDebugGenerate(params map[string]any) *backend.ToolResult {
	size, ok := readIntParam(params, "size_bytes")
	if !ok {
		return debugErrorResult("Parameter 'size_bytes' must be a number")
	}
	if size < 0 {
		return debugErrorResult("Parameter 'size_bytes' must be non-negative")
	}
	if size > debugMaxGenerateBytes {
		return debugErrorResult(fmt.Sprintf("Parameter 'size_bytes' exceeds maximum (%d > %d)", size, debugMaxGenerateBytes))
	}

	pattern := debugPatternASCII
	if p, ok := params[argNamePattern].(string); ok && p != "" {
		pattern = p
	}

	text, err := generateDebugPayload(size, pattern)
	if err != nil {
		return debugErrorResult(err.Error())
	}

	sum := sha256.Sum256(text)
	return debugTextResult(map[string]any{
		contentKeyText:    string(text),
		"requested_bytes": size,
		"returned_bytes":  len(text),
		argNamePattern:    pattern,
		"sha256":          hex.EncodeToString(sum[:]),
	})
}

// generateDebugPayload returns size bytes of the requested pattern. Both
// patterns produce printable ASCII so the result fits cleanly into JSON.
func generateDebugPayload(size int, pattern string) ([]byte, error) {
	switch pattern {
	case debugPatternASCII:
		out := make([]byte, size)
		for i := 0; i < size; i++ {
			out[i] = debugAsciiCharset[i%len(debugAsciiCharset)]
		}
		return out, nil
	case "random":
		out := make([]byte, size)
		raw := make([]byte, size)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("random read failed: %w", err)
		}
		for i := 0; i < size; i++ {
			out[i] = debugAsciiCharset[int(raw[i])%len(debugAsciiCharset)]
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown pattern %q (allowed: ascii, random)", pattern)
	}
}

// readIntParam coerces an MCP-decoded numeric parameter (which arrives as
// float64 from JSON) into an int. Returns ok=false if the value is missing
// or not a number-like type.
func readIntParam(params map[string]any, name string) (int, bool) {
	v, ok := params[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

// debugToolDefinitions returns the tool list entries advertised when debug
// tools are enabled. Kept separate so BuildToolList can append them cleanly.
func debugToolDefinitions() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        toolDebugEcho,
			Description: "Diagnostic tool: returns size and SHA-256 of the supplied payload without touching any backend. Use to probe the per-call argument-size limit of the calling transport (e.g. binary-search the largest payload a client can send) and to verify round-trip byte integrity. Disabled unless TOOLMESH_DEBUG_TOOLS=true.",
			InputSchema: map[string]any{
				contentKeyType: jsonTypeObject,
				schemaKeyProperties: map[string]any{
					argNamePayload: map[string]any{
						schemaKeyDescription: "Arbitrary JSON value to echo (string, object, array, number, boolean, null).",
					},
				},
				schemaKeyRequired: []string{argNamePayload},
			},
		},
		{
			Name:        toolDebugGenerate,
			Description: "Diagnostic tool: generates a printable string of exactly size_bytes characters and returns it together with its SHA-256. Use to probe the maximum response size the calling transport will accept from ToolMesh. Capped at 10 MB. Disabled unless TOOLMESH_DEBUG_TOOLS=true.",
			InputSchema: map[string]any{
				contentKeyType: jsonTypeObject,
				schemaKeyProperties: map[string]any{
					"size_bytes": map[string]any{
						contentKeyType:       jsonTypeInteger,
						schemaKeyDescription: "Number of bytes to return (0 to 10485760).",
					},
					argNamePattern: map[string]any{
						contentKeyType:       jsonTypeString,
						"enum":               []string{debugPatternASCII, "random"},
						schemaKeyDescription: "ascii (default) = deterministic alphanumeric cycle; random = printable random.",
					},
				},
				schemaKeyRequired: []string{"size_bytes"},
			},
		},
	}
}
