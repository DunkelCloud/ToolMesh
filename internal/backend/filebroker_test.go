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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFileBrokerClient_Upload_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &FileBrokerClient{BaseURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	_, err := c.Upload(context.Background(), "name.bin", "text/plain", strings.NewReader("x"), time.Hour)
	if err == nil {
		t.Error("expected error")
	}
}

func TestFileBrokerClient_Upload_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"file_id": "f1", "url": "https://broker/f1"}`))
	}))
	defer srv.Close()

	c := &FileBrokerClient{BaseURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	r, err := c.Upload(context.Background(), "name.bin", "application/octet-stream", strings.NewReader("hello"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r.URL != "https://broker/f1" {
		t.Errorf("url = %q", r.URL)
	}
}

func TestFilenameFromHeaders(t *testing.T) {
	// Content-Disposition with filename.
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Content-Disposition", `attachment; filename="report.pdf"`)
	if got := filenameFromHeaders(resp, "application/pdf"); got != "report.pdf" {
		t.Errorf("got %q", got)
	}

	// No header → fallback to content type extension.
	resp2 := &http.Response{Header: http.Header{}}
	got := filenameFromHeaders(resp2, "image/png")
	if !strings.HasPrefix(got, "output") {
		t.Errorf("got %q", got)
	}

	// Unknown content type → .bin fallback.
	resp3 := &http.Response{Header: http.Header{}}
	if got := filenameFromHeaders(resp3, "application/x-unknown-xyz"); got != "output.bin" {
		t.Errorf("got %q", got)
	}
}
