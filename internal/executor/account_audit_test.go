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

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// TestExecuteTool_AuditNamesTheAccount pins that the audit entry of a call
// to a backend with credentials of users names the account the call was
// made with. The backend reports it in the result; the caller may have
// named none, so the arguments alone do not say.
func TestExecuteTool_AuditNamesTheAccount(t *testing.T) {
	const account = "office@example.com"
	for name, c := range map[string]struct {
		metadata map[string]any
		want     string
		named    bool
	}{
		"the backend names an account": {map[string]any{backend.MetadataKeyAccount: account}, account, true},
		"no account":                   {map[string]any{"other": "x"}, "", false},
		"no metadata":                  {nil, "", false},
		"not a text":                   {map[string]any{backend.MetadataKeyAccount: 7}, "", false},
	} {
		rec := &recordingAudit{}
		mb := &mockBackend{executeFunc: func(context.Context, string, map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content:  []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}},
				Metadata: c.metadata,
			}, nil
		}}
		exec := New(nil, nil, mb, nil, rec, time.Second, newTestLogger(), nil, nil)
		ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testUserID, Authenticated: true})
		if _, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "mail_list_messages"}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, named := rec.last.Metadata[backend.MetadataKeyAccount]
		if got != c.want || named != c.named {
			t.Errorf("%s: audit metadata = %v, want account %q (present: %v)", name, rec.last.Metadata, c.want, c.named)
		}
	}
}
