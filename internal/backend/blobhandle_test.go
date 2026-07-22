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
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// newBlobTestAdapter builds a REST adapter pointed at baseURL with one JSON
// tool ("describe_image": nested object param) and one file_url tool
// ("extract_text"), plus a blob store pre-loaded with jpegContent.
func newBlobTestAdapter(t *testing.T, baseURL string) (*RESTAdapter, *blob.Store, string) {
	t.Helper()
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Tools: map[string]dadl.ToolDef{
				"describe_image": {
					Method:      "POST",
					Path:        "/describe",
					Description: "vision-style JSON tool",
					Params: map[string]dadl.ParamDef{
						testParamModel: {Type: "string", In: paramInBody},
						testParamInput: {Type: schemaTypeObject, In: paramInBody},
					},
				},
				"extract_text": {
					Method:      "PUT",
					Path:        "/extract",
					Description: "raw-body file tool",
					ContentType: "application/octet-stream",
					Params: map[string]dadl.ParamDef{
						paramTypeFile: {Type: dadl.ParamTypeFileURL, In: paramInBody, Required: true},
					},
				},
			},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := blob.NewStore(t.TempDir(), "http://broker.local", logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	adapter.SetBlobStore(store)

	id, _, err := store.PutNamed(strings.NewReader(jpegContent), "image/jpeg", "scan.jpg", time.Hour)
	if err != nil {
		t.Fatalf("PutNamed: %v", err)
	}
	return adapter, store, id
}

const jpegContent = "fake jpeg bytes"

// Fixture param names, extracted to keep goconst quiet.
const (
	testParamModel = "model"
	testParamInput = "input"
)

func TestSubstituteBlobHandles(t *testing.T) {
	adapter, store, id := newBlobTestAdapter(t, testBaseURLExample)
	tool := adapter.spec.Backend.Tools["describe_image"]
	wantB64 := base64.StdEncoding.EncodeToString([]byte(jpegContent))

	t.Run("fragments materialize", func(t *testing.T) {
		params := map[string]any{
			testParamModel: "gpt-4o",
			testParamInput: map[string]any{
				"content": []any{
					map[string]any{schemaKeyType: "input_image", "image_url": blob.Handle(id) + "#dataurl"},
					map[string]any{schemaKeyType: "input_text", "text": "see tm-blob://" + id + "#base64 embedded"},
				},
				"raw":  blob.Handle(id) + "#base64",
				"link": blob.Handle(id) + "#url",
			},
		}
		out, err := adapter.substituteBlobHandles(&tool, params)
		if err != nil {
			t.Fatalf("substituteBlobHandles: %v", err)
		}
		input := out[testParamInput].(map[string]any)
		content := input["content"].([]any)
		img := content[0].(map[string]any)
		if img["image_url"] != "data:image/jpeg;base64,"+wantB64 {
			t.Errorf("dataurl = %q", img["image_url"])
		}
		txt := content[1].(map[string]any)
		if !strings.Contains(txt["text"].(string), "tm-blob://") {
			t.Error("embedded handle inside longer string must stay untouched")
		}
		if input["raw"] != wantB64 {
			t.Errorf("base64 = %q", input["raw"])
		}
		if input["link"] != store.URL(id) {
			t.Errorf("url = %q", input["link"])
		}
		// Original params must not be mutated.
		origImg := params[testParamInput].(map[string]any)["content"].([]any)[0].(map[string]any)
		if origImg["image_url"] != blob.Handle(id)+"#dataurl" {
			t.Error("input params were mutated in place")
		}
	})

	t.Run("bare handle in string param fails", func(t *testing.T) {
		_, err := adapter.substituteBlobHandles(&tool, map[string]any{testParamModel: blob.Handle(id)})
		if err == nil || !strings.Contains(err.Error(), "explicit format fragment") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("malformed fragment fails", func(t *testing.T) {
		_, err := adapter.substituteBlobHandles(&tool, map[string]any{testParamModel: blob.Handle(id) + "#hex"})
		if err == nil || !strings.Contains(err.Error(), "unknown fragment") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("unknown blob fails", func(t *testing.T) {
		_, err := adapter.substituteBlobHandles(&tool, map[string]any{testParamModel: "tm-blob://ffffffff#base64"})
		if err == nil || !strings.Contains(err.Error(), "not found or expired") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("file_url param keeps bare handle", func(t *testing.T) {
		fileTool := adapter.spec.Backend.Tools["extract_text"]
		out, err := adapter.substituteBlobHandles(&fileTool, map[string]any{paramTypeFile: blob.Handle(id)})
		if err != nil {
			t.Fatalf("substituteBlobHandles: %v", err)
		}
		if out[paramTypeFile] != blob.Handle(id) {
			t.Errorf("file param = %q, want bare handle preserved", out[paramTypeFile])
		}
	})

	t.Run("no store configured fails", func(t *testing.T) {
		bare, err := NewRESTAdapter(adapter.spec, &testCredStore{}, slog.Default(), testRESTOpts)
		if err != nil {
			t.Fatalf("NewRESTAdapter: %v", err)
		}
		_, err = bare.substituteBlobHandles(&tool, map[string]any{testParamModel: blob.Handle(id) + "#base64"})
		if err == nil || !strings.Contains(err.Error(), "no file broker configured") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestFetchFileURL_BlobHandle(t *testing.T) {
	adapter, _, id := newBlobTestAdapter(t, testBaseURLExample)

	t.Run("bare handle streams from store", func(t *testing.T) {
		fetched, err := adapter.fetchFileURL(context.Background(), paramTypeFile, blob.Handle(id))
		if err != nil {
			t.Fatalf("fetchFileURL: %v", err)
		}
		defer func() { _ = fetched.Body.Close() }()
		data, _ := io.ReadAll(fetched.Body)
		if string(data) != jpegContent || fetched.ContentType != "image/jpeg" || fetched.Filename != "scan.jpg" {
			t.Errorf("fetched = %q %q %q", data, fetched.ContentType, fetched.Filename)
		}
	})

	t.Run("fragment on file_url handle fails", func(t *testing.T) {
		_, err := adapter.fetchFileURL(context.Background(), paramTypeFile, blob.Handle(id)+"#base64")
		if err == nil || !strings.Contains(err.Error(), "must not carry a format fragment") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("unknown blob fails", func(t *testing.T) {
		_, err := adapter.fetchFileURL(context.Background(), paramTypeFile, "tm-blob://ffffffff")
		if err == nil || !strings.Contains(err.Error(), "not found or expired") {
			t.Errorf("err = %v", err)
		}
	})
}

// TestExecute_BlobHandleEndToEnd proves the full path: a tool call whose
// params carry handles produces a backend request with the real bytes — the
// exact flow the Loom OCR session could not achieve.
func TestExecute_BlobHandleEndToEnd(t *testing.T) {
	var gotJSON map[string]any
	var gotRaw []byte
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/describe":
			_ = json.NewDecoder(r.Body).Decode(&gotJSON)
		case "/extract":
			gotRaw, _ = io.ReadAll(r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backendSrv.Close()

	adapter, _, id := newBlobTestAdapter(t, backendSrv.URL)
	wantB64 := base64.StdEncoding.EncodeToString([]byte(jpegContent))

	res, err := adapter.Execute(context.Background(), "describe_image", map[string]any{
		testParamModel: "gpt-4o",
		testParamInput: map[string]any{"image_url": blob.Handle(id) + "#dataurl"},
	})
	if err != nil || res.IsError {
		t.Fatalf("Execute describe_image: err=%v res=%+v", err, res)
	}
	input := gotJSON[testParamInput].(map[string]any)
	if input["image_url"] != "data:image/jpeg;base64,"+wantB64 {
		t.Errorf("backend saw image_url = %q", input["image_url"])
	}

	res, err = adapter.Execute(context.Background(), "extract_text", map[string]any{
		paramTypeFile: blob.Handle(id),
	})
	if err != nil || res.IsError {
		t.Fatalf("Execute extract_text: err=%v res=%+v", err, res)
	}
	if string(gotRaw) != jpegContent {
		t.Errorf("backend saw raw body %q, want blob content", gotRaw)
	}
}
