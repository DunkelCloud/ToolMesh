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

package dadl

import (
	"net/http"
	"testing"
)

func TestPaginator_Cursor(t *testing.T) {
	p := NewPaginator(PaginationConfig{
		Strategy: "cursor",
		Request:  PaginationRequest{CursorParam: "cursor"},
		Response: PaginationResponse{
			NextCursor: "$.meta.next_cursor",
			HasMore:    "$.meta.has_more",
		},
	})

	tests := []struct {
		name    string
		body    string
		wantNil bool
		wantCur string
	}{
		{
			name:    "has more",
			body:    `{"data": [], "meta": {"has_more": true, "next_cursor": "abc"}}`,
			wantCur: "abc",
		},
		{
			name:    "no more",
			body:    `{"data": [], "meta": {"has_more": false, "next_cursor": ""}}`,
			wantNil: true,
		},
		{
			name:    "empty cursor",
			body:    `{"data": [], "meta": {"has_more": true, "next_cursor": ""}}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := p.NextPageParams(200, nil, []byte(tt.body), map[string]string{})
			if tt.wantNil {
				if next != nil {
					t.Errorf("expected nil, got %v", next)
				}
				return
			}
			if next == nil {
				t.Fatal("expected non-nil")
			}
			if next["cursor"] != tt.wantCur {
				t.Errorf("cursor = %q, want %q", next["cursor"], tt.wantCur)
			}
		})
	}
}

func TestPaginator_Offset(t *testing.T) {
	p := NewPaginator(PaginationConfig{
		Strategy: "offset",
		Request: PaginationRequest{
			OffsetParam:  "offset",
			LimitParam:   "limit",
			LimitDefault: 10,
		},
	})

	// Full page (10 items) → should return next
	body := `[1,2,3,4,5,6,7,8,9,10]`
	next := p.NextPageParams(200, nil, []byte(body), map[string]string{})
	if next == nil {
		t.Fatal("expected next page params")
	}
	if next["offset"] != "10" {
		t.Errorf("offset = %q, want 10", next["offset"])
	}

	// Partial page (5 items) → should return nil
	body = `[1,2,3,4,5]`
	next = p.NextPageParams(200, nil, []byte(body), map[string]string{})
	if next != nil {
		t.Errorf("expected nil for partial page, got %v", next)
	}
}

func TestPaginator_Page(t *testing.T) {
	p := NewPaginator(PaginationConfig{
		Strategy: "page",
		Request:  PaginationRequest{PageParam: "page"},
		Response: PaginationResponse{TotalPagesHeader: "X-Total-Pages"},
	})

	headers := http.Header{}
	headers.Set("X-Total-Pages", "3")

	// Page 1 of 3 → next
	next := p.NextPageParams(200, headers, nil, map[string]string{"page": "1"})
	if next == nil {
		t.Fatal("expected next page params")
	}
	if next["page"] != "2" {
		t.Errorf("page = %q, want 2", next["page"])
	}

	// Page 3 of 3 → nil
	next = p.NextPageParams(200, headers, nil, map[string]string{"page": "3"})
	if next != nil {
		t.Errorf("expected nil on last page, got %v", next)
	}
}

func TestPaginator_LinkHeader(t *testing.T) {
	p := NewPaginator(PaginationConfig{Strategy: "link_header"})

	headers := http.Header{}
	headers.Set("Link", `<https://api.example.com/items?page=2>; rel="next", <https://api.example.com/items?page=5>; rel="last"`)

	next := p.NextPageParams(200, headers, nil, nil)
	if next == nil {
		t.Fatal("expected next page params")
	}
	if next["_url"] != "https://api.example.com/items?page=2" {
		t.Errorf("_url = %q", next["_url"])
	}

	// No next link
	headers.Set("Link", `<https://api.example.com/items?page=5>; rel="last"`)
	next = p.NextPageParams(200, headers, nil, nil)
	if next != nil {
		t.Errorf("expected nil when no next link, got %v", next)
	}
}

func TestPaginator_ErrorStatus(t *testing.T) {
	p := NewPaginator(PaginationConfig{Strategy: "page"})
	next := p.NextPageParams(500, nil, nil, nil)
	if next != nil {
		t.Error("expected nil on error status")
	}
}
