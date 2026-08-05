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

package blob

import (
	"fmt"
	"strings"
)

// HandleScheme is the URL scheme of blob handles (DADL spec §6.2.4).
const HandleScheme = "tm-blob"

const handlePrefix = HandleScheme + "://"

// Format fragments accepted on a blob handle. They select how the blob is
// materialized when substituted into a plain string parameter.
const (
	FragmentNone    = ""        // file_url parameters only: raw content
	FragmentBase64  = "base64"  // raw Base64, no prefix
	FragmentDataURL = "dataurl" // data:<content-type>;base64,<data>
	FragmentURL     = "url"     // the blob's HTTP download URL
)

// Handle returns the tm-blob:// handle for a blob ID.
func Handle(id string) string {
	return handlePrefix + id
}

// IsHandle reports whether s starts with the tm-blob:// prefix. It does not
// validate the remainder — use ParseHandle for that.
func IsHandle(s string) bool {
	return strings.HasPrefix(s, handlePrefix)
}

// ParseHandle splits a tm-blob:// handle into blob ID and format fragment.
// ok is false when s does not carry the tm-blob:// prefix at all. A string
// that is a handle but malformed (empty ID, path separators, unknown
// fragment) returns ok=true together with an error, so callers can
// distinguish "not a handle" from "broken handle" — the latter must fail the
// tool call rather than pass through as a literal string (DADL spec §6.2.4).
func ParseHandle(s string) (id, fragment string, ok bool, err error) {
	if !strings.HasPrefix(s, handlePrefix) {
		return "", "", false, nil
	}
	rest := strings.TrimPrefix(s, handlePrefix)
	id = rest
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		id, fragment = rest[:i], rest[i+1:]
	}
	if id == "" || strings.ContainsAny(id, "/\\?#%") {
		return "", "", true, fmt.Errorf("malformed blob handle %q: invalid blob ID", s)
	}
	switch fragment {
	case FragmentNone, FragmentBase64, FragmentDataURL, FragmentURL:
	default:
		return "", "", true, fmt.Errorf("malformed blob handle %q: unknown fragment %q (use #base64, #dataurl, or #url)", s, fragment)
	}
	return id, fragment, true, nil
}
