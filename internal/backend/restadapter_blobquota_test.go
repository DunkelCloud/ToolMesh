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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// TestRESTAdapter_BinaryResponseCountsAgainstCaller checks that a binary
// response stored in the file broker counts against the calling user's
// quota, and that a response over the quota is a clear error.
func TestRESTAdapter_BinaryResponseCountsAgainstCaller(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, "image/png")
		_, _ = w.Write([]byte(strings.Repeat("p", 6)))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_image": {
					Method: testMethodGET, Path: "/image",
					Response: &dadl.ResponseConfig{Binary: true, ContentType: "image/png"},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blob.NewStore(t.TempDir(), "http://localhost:8080", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	bs.SetQuota(blob.Quota{MaxBytesPerUser: 10})
	a.SetBlobStore(bs)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "caller", Authenticated: true})
	result, err := a.Execute(ctx, "get_image", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("first response refused: %v", result.Content)
	}
	if _, ofCaller := bs.Usage("caller"); ofCaller != 6 {
		t.Errorf("usage of the caller = %d, want 6", ofCaller)
	}

	result, err = a.Execute(ctx, "get_image", nil)
	if err != nil {
		t.Fatal(err)
	}
	if text := fmt.Sprint(result.Content...); !result.IsError || !strings.Contains(text, blob.ErrQuotaExceeded.Error()) {
		t.Errorf("second response: IsError %v, content %s; want the quota error", result.IsError, text)
	}
}
