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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestBinaryResponseHandling(t *testing.T) {
	// Mock backend returns audio/mpeg
	audioData := []byte("fake-mp3-audio-data-for-testing")
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		w.Header().Set("Content-Disposition", `attachment; filename="speech.mp3"`)
		_, _ = w.Write(audioData)
	}))
	defer backendSrv.Close()

	// Mock file broker
	brokerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/files/upload" {
			http.Error(w, "unexpected request", 400)
			return
		}
		if err := r.ParseMultipartForm(32 << 20); err != nil { //nolint:gosec // test
			http.Error(w, err.Error(), 500)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer func() { _ = file.Close() }()
		data, _ := io.ReadAll(file)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"file_id": "f-abc123",
			"url":     "https://files.example.com/f-abc123",
			"expires": "2026-03-30T13:00:00Z",
		})

		// Validate received data
		if header.Filename != "speech.mp3" {
			t.Errorf("file broker received filename = %q, want speech.mp3", header.Filename)
		}
		if !bytes.Equal(data, audioData) {
			t.Errorf("file broker received %d bytes, want %d", len(data), len(audioData))
		}
	}))
	defer brokerSrv.Close()

	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "elevenlabs",
			Type:    "rest",
			BaseURL: backendSrv.URL,
			Tools: map[string]dadl.ToolDef{
				"create_speech": {
					Method: "POST",
					Path:   "/v1/text-to-speech/{voice_id}",
					Params: map[string]dadl.ParamDef{
						"voice_id": {Type: "string", In: "path", Required: true},
						"text":     {Type: "string", In: "body", Required: true},
					},
					Response: &dadl.ResponseConfig{
						Binary:      true,
						ContentType: "audio/mpeg",
						Type:        "file_url",
						TTL:         "1h",
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	adapter.SetFileBroker(&FileBrokerClient{
		BaseURL:    brokerSrv.URL,
		HTTPClient: http.DefaultClient,
	})

	result, err := adapter.Execute(context.Background(), "create_speech", map[string]any{
		"voice_id": "test-voice",
		"text":     "Hallo Welt",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text := extractText(t, result)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse result JSON: %v (raw: %s)", err, text)
	}

	if parsed["file_id"] != "f-abc123" {
		t.Errorf("file_id = %v, want f-abc123", parsed["file_id"])
	}
	if parsed["url"] != "https://files.example.com/f-abc123" {
		t.Errorf("url = %v", parsed["url"])
	}
	if parsed["content_type"] != "audio/mpeg" {
		t.Errorf("content_type = %v, want audio/mpeg", parsed["content_type"])
	}
	sizeBytes, _ := parsed["size_bytes"].(float64)
	if int(sizeBytes) != len(audioData) {
		t.Errorf("size_bytes = %v, want %d", sizeBytes, len(audioData))
	}

	// Check metadata
	if result.Metadata["binary"] != true {
		t.Error("metadata.binary should be true")
	}
}

func TestBinaryResponseFallbackBase64(t *testing.T) {
	audioData := []byte("fake-audio-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write(audioData)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_audio": {
					Method: "GET",
					Path:   "/audio",
					Response: &dadl.ResponseConfig{
						Binary:      true,
						ContentType: "audio/mpeg",
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	// No file broker configured — should fall back to base64

	result, err := adapter.Execute(context.Background(), "get_audio", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text := extractText(t, result)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse result: %v (raw: %s)", err, text)
	}

	dataURL, ok := parsed["data_url"].(string)
	if !ok {
		t.Fatal("missing data_url in result")
	}
	if !strings.HasPrefix(dataURL, "data:audio/mpeg;base64,") {
		t.Errorf("data_url prefix = %s", dataURL[:40])
	}
	if parsed["content_type"] != "audio/mpeg" {
		t.Errorf("content_type = %v", parsed["content_type"])
	}
}

func TestJSONResponseUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"voices": [{"id": "v1", "name": "Rachel"}]}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{"Accept": "application/json"},
			},
			Tools: map[string]dadl.ToolDef{
				"list_voices": {
					Method: "GET",
					Path:   "/voices",
					// No binary config — standard JSON path
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	result, err := adapter.Execute(context.Background(), "list_voices", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "Rachel") {
		t.Errorf("expected Rachel in response: %s", text)
	}
	// Should NOT be base64 encoded or have file_id
	if strings.Contains(text, "data_url") || strings.Contains(text, "file_id") {
		t.Errorf("JSON response should not go through binary handler: %s", text)
	}
}

func TestBinaryResponseLargePayload(t *testing.T) {
	// Generate 11 MB of random data — larger than maxResponseBytes (10 MB)
	// but we test base64 fallback rejects it (>5 MB limit), ensuring no OOM
	largeData := make([]byte, 6*1024*1024) // 6 MB — exceeds base64 limit
	_, _ = rand.Read(largeData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write(largeData)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_pdf": {
					Method: "GET",
					Path:   "/report.pdf",
					Response: &dadl.ResponseConfig{
						Binary:      true,
						ContentType: "application/pdf",
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	// No file broker — base64 fallback should reject large payload gracefully

	result, err := adapter.Execute(context.Background(), "get_pdf", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for oversized base64 payload")
	}
	text := extractText(t, result)
	if !strings.Contains(text, "too large") {
		t.Errorf("expected 'too large' error, got: %s", text)
	}
}

func TestBinaryContentTypeDetection(t *testing.T) {
	// Backend returns Content-Type that differs from DADL config
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/wav") // HTTP says wav
		_, _ = w.Write([]byte("RIFF-fake-wav"))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_audio": {
					Method: "GET",
					Path:   "/audio",
					Response: &dadl.ResponseConfig{
						Binary:      true,
						ContentType: "audio/mpeg", // DADL says mpeg
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	result, err := adapter.Execute(context.Background(), "get_audio", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text := extractText(t, result)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}

	// HTTP Content-Type should take precedence over DADL config
	if parsed["content_type"] != "audio/wav" {
		t.Errorf("content_type = %v, want audio/wav (HTTP header should take precedence)", parsed["content_type"])
	}
}

func TestBinaryStreamingCollect(t *testing.T) {
	// Mock backend sends chunked response
	audioData := bytes.Repeat([]byte("chunk"), 100)
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		w.Header().Set("Transfer-Encoding", "chunked")
		flusher, ok := w.(http.Flusher)
		// Write in chunks
		for i := 0; i < len(audioData); i += 50 {
			end := i + 50
			if end > len(audioData) {
				end = len(audioData)
			}
			_, _ = w.Write(audioData[i:end])
			if ok {
				flusher.Flush()
			}
		}
	}))
	defer backendSrv.Close()

	// Mock file broker that tracks uploaded data
	var uploadedBytes int
	brokerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(32 << 20); err != nil { //nolint:gosec // test
			http.Error(w, err.Error(), 500)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer func() { _ = file.Close() }()
		data, _ := io.ReadAll(file)
		uploadedBytes = len(data)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"file_id":"f-stream","url":"https://files.example.com/f-stream","expires":"2026-03-30T14:00:00Z"}`)
	}))
	defer brokerSrv.Close()

	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "elevenlabs",
			Type:    "rest",
			BaseURL: backendSrv.URL,
			Tools: map[string]dadl.ToolDef{
				"stream_speech": {
					Method: "POST",
					Path:   "/v1/text-to-speech/{voice_id}/stream",
					Params: map[string]dadl.ParamDef{
						"voice_id": {Type: "string", In: "path", Required: true},
					},
					Response: &dadl.ResponseConfig{
						Binary:         true,
						Streaming:      true,
						StreamHandling: "collect",
						ContentType:    "audio/mpeg",
						Type:           "file_url",
						TTL:            "1h",
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	adapter.SetFileBroker(&FileBrokerClient{
		BaseURL:    brokerSrv.URL,
		HTTPClient: http.DefaultClient,
	})

	result, err := adapter.Execute(context.Background(), "stream_speech", map[string]any{
		"voice_id": "test-voice",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text := extractText(t, result)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("parse: %v (raw: %s)", err, text)
	}

	if parsed["file_id"] != "f-stream" {
		t.Errorf("file_id = %v, want f-stream", parsed["file_id"])
	}
	if uploadedBytes != len(audioData) {
		t.Errorf("file broker received %d bytes, want %d", uploadedBytes, len(audioData))
	}
	if result.Metadata["streaming"] != true {
		t.Error("metadata.streaming should be true")
	}
}
