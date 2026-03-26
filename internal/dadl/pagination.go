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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Paginator handles automatic multi-page fetching for REST APIs.
type Paginator struct {
	config PaginationConfig
}

// NewPaginator creates a Paginator from a PaginationConfig.
func NewPaginator(config PaginationConfig) *Paginator {
	return &Paginator{config: config}
}

// NextPageParams returns query params for the next page based on the current response,
// or nil if there are no more pages.
func (p *Paginator) NextPageParams(statusCode int, headers http.Header, body []byte, currentParams map[string]string) map[string]string {
	if statusCode < 200 || statusCode >= 300 {
		return nil
	}

	switch p.config.Strategy {
	case "cursor":
		return p.nextCursor(body, currentParams)
	case "offset":
		return p.nextOffset(body, currentParams)
	case "page":
		return p.nextPage(headers, currentParams)
	case "link_header":
		return p.nextLinkHeader(headers)
	default:
		return nil
	}
}

func (p *Paginator) nextCursor(body []byte, currentParams map[string]string) map[string]string {
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	// Check has_more if configured
	if p.config.Response.HasMore != "" {
		jp, err := NewJSONPath(p.config.Response.HasMore)
		if err == nil {
			val, err := jp.Extract(data)
			if err == nil {
				if hasMore, ok := val.(bool); ok && !hasMore {
					return nil
				}
			}
		}
	}

	// Extract next cursor
	if p.config.Response.NextCursor == "" {
		return nil
	}
	jp, err := NewJSONPath(p.config.Response.NextCursor)
	if err != nil {
		return nil
	}
	val, err := jp.Extract(data)
	if err != nil {
		return nil
	}
	cursor := fmt.Sprintf("%v", val)
	if cursor == "" || cursor == "<nil>" {
		return nil
	}

	next := copyParams(currentParams)
	next[p.config.Request.CursorParam] = cursor
	return next
}

func (p *Paginator) nextOffset(body []byte, currentParams map[string]string) map[string]string {
	// Parse current offset
	currentOffset := 0
	if v, ok := currentParams[p.config.Request.OffsetParam]; ok {
		currentOffset, _ = strconv.Atoi(v)
	}

	limit := p.config.Request.LimitDefault
	if limit == 0 {
		limit = 50
	}
	if v, ok := currentParams[p.config.Request.LimitParam]; ok {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
	}

	// Check if we got fewer results than the limit (last page)
	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	if arr, ok := data.([]any); ok {
		if len(arr) < limit {
			return nil
		}
	}

	next := copyParams(currentParams)
	next[p.config.Request.OffsetParam] = strconv.Itoa(currentOffset + limit)
	if p.config.Request.LimitParam != "" {
		next[p.config.Request.LimitParam] = strconv.Itoa(limit)
	}
	return next
}

func (p *Paginator) nextPage(headers http.Header, currentParams map[string]string) map[string]string {
	currentPage := 1
	if v, ok := currentParams[p.config.Request.PageParam]; ok {
		currentPage, _ = strconv.Atoi(v)
	}

	// Check total pages from header
	if p.config.Response.TotalPagesHeader != "" {
		totalStr := headers.Get(p.config.Response.TotalPagesHeader)
		if totalStr != "" {
			total, err := strconv.Atoi(totalStr)
			if err == nil && currentPage >= total {
				return nil
			}
		}
	}

	next := copyParams(currentParams)
	next[p.config.Request.PageParam] = strconv.Itoa(currentPage + 1)
	return next
}

func (p *Paginator) nextLinkHeader(headers http.Header) map[string]string {
	link := headers.Get("Link")
	if link == "" {
		return nil
	}

	// Parse RFC 8288 Link header for rel="next"
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		// Extract URL from <...>
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start {
			// Return the full URL as a special "_url" param
			return map[string]string{"_url": part[start+1 : end]}
		}
	}
	return nil
}

func copyParams(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
