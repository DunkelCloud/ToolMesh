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
	"encoding/base64"
	"fmt"
	"io"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// maxInlineBlobBytes caps blobs materialized inline via #base64 / #dataurl.
// Base64 inflates the payload by ~33% and the request body is buffered in
// memory, so the inline ceiling is deliberately far below the general
// file-fetch limit. Larger blobs should use #url or a file_url parameter,
// both of which stream.
const maxInlineBlobBytes = maxResponseBytes // 10 MB

// substituteBlobHandles is called while building the backend request, i.e.
// downstream of authorization and the request-side (pre-execution) policy gate
// in the executor. Those layers and the audit trail see the tm-blob:// handle,
// not the bytes it expands to — a deliberate property matching the outbound
// broker (a binary response is gated as a URL, not as its content). See DADL
// spec §6.2.5. A policy that must inspect content leaving to a backend cannot
// rely on seeing blob-carried payloads.
//
// substituteBlobHandles walks the tool parameters and replaces every string
// value that is, in its entirety, a tm-blob:// handle with an explicit format
// fragment (DADL spec §6.2.4):
//
//	#base64  → raw Base64 of the blob content
//	#dataurl → data:<content-type>;base64,<data>
//	#url     → the blob's HTTP download URL
//
// Handles embedded inside longer strings are left untouched (whole-value
// match only). Malformed, unknown, or expired handles fail the call — they
// are never passed to the backend as literal strings. Top-level file_url
// parameters are skipped: the file_url pipeline accepts bare handles natively
// and streams them (see openBlobHandle).
func (a *RESTAdapter) substituteBlobHandles(tool *dadl.ToolDef, params map[string]any) (map[string]any, error) {
	out := params
	copied := false
	for name, value := range params {
		if def, ok := tool.Params[name]; ok && def.Type == dadl.ParamTypeFileURL {
			continue
		}
		replaced, changed, err := a.substituteBlobValue(value)
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", name, err)
		}
		if changed {
			if !copied {
				out = make(map[string]any, len(params))
				for k, v := range params {
					out[k] = v
				}
				copied = true
			}
			out[name] = replaced
		}
	}
	return out, nil
}

// substituteBlobValue resolves handles inside a single parameter value,
// recursing through nested objects and arrays.
func (a *RESTAdapter) substituteBlobValue(v any) (result any, changed bool, err error) {
	switch val := v.(type) {
	case string:
		if !blob.IsHandle(val) {
			return v, false, nil
		}
		replaced, err := a.materializeBlobHandle(val)
		if err != nil {
			return nil, false, err
		}
		return replaced, true, nil
	case map[string]any:
		out := val
		copied := false
		for k, elem := range val {
			replaced, elemChanged, err := a.substituteBlobValue(elem)
			if err != nil {
				return nil, false, err
			}
			if elemChanged {
				if !copied {
					out = make(map[string]any, len(val))
					for kk, vv := range val {
						out[kk] = vv
					}
					copied = true
				}
				out[k] = replaced
			}
		}
		return out, copied, nil
	case []any:
		out := val
		copied := false
		for i, elem := range val {
			replaced, elemChanged, err := a.substituteBlobValue(elem)
			if err != nil {
				return nil, false, err
			}
			if elemChanged {
				if !copied {
					out = make([]any, len(val))
					copy(out, val)
					copied = true
				}
				out[i] = replaced
			}
		}
		return out, copied, nil
	default:
		return v, false, nil
	}
}

// materializeBlobHandle turns a whole-string handle into its substituted
// value according to the format fragment.
func (a *RESTAdapter) materializeBlobHandle(handle string) (string, error) {
	id, fragment, _, err := blob.ParseHandle(handle)
	if err != nil {
		return "", err
	}
	if fragment == blob.FragmentNone {
		return "", fmt.Errorf("blob handle %q needs an explicit format fragment in this position — append #base64, #dataurl, or #url (bare handles are only valid in file_url parameters)", handle)
	}
	if a.blobStore == nil {
		return "", fmt.Errorf("blob handle %q: this server has no file broker configured", handle)
	}

	if fragment == blob.FragmentURL {
		// Existence check only — the backend fetches the URL itself.
		if _, err := a.blobStore.Stat(id); err != nil {
			return "", err
		}
		return a.blobStore.URL(id), nil
	}

	rc, info, err := a.blobStore.Open(id)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	if info.Size > maxInlineBlobBytes {
		return "", fmt.Errorf("blob %q is %d bytes — too large for inline %s substitution (limit %d); use #url instead", id, info.Size, "#"+fragment, maxInlineBlobBytes)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("read blob %q: %w", id, err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	switch fragment {
	case blob.FragmentBase64:
		return encoded, nil
	case blob.FragmentDataURL:
		return "data:" + info.ContentType + ";base64," + encoded, nil
	default:
		return "", fmt.Errorf("blob handle %q: unsupported fragment %q", handle, fragment)
	}
}

// openBlobHandle resolves a bare tm-blob:// handle in a file_url parameter by
// reading the embedded blob store directly — no HTTP fetch, no network
// reachability requirement (DADL spec §6.2.1).
func (a *RESTAdapter) openBlobHandle(paramName, rawURL string) (*fetchedFile, error) {
	if a.blobStore == nil {
		return nil, fmt.Errorf("file parameter %q: %s requires the built-in file broker, which is not configured on this server", paramName, rawURL)
	}
	id, fragment, _, err := blob.ParseHandle(rawURL)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: %w", paramName, err)
	}
	if fragment != blob.FragmentNone {
		return nil, fmt.Errorf("file parameter %q: blob handle %q must not carry a format fragment — file_url parameters take the bare handle", paramName, rawURL)
	}
	rc, info, err := a.blobStore.Open(id)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: %w", paramName, err)
	}
	if info.Size > maxFileFetchBytes {
		_ = rc.Close()
		return nil, fmt.Errorf("file parameter %q: blob is %d bytes, exceeding the %d byte limit", paramName, info.Size, maxFileFetchBytes)
	}
	return &fetchedFile{
		Body:        rc,
		ContentType: info.ContentType,
		Filename:    info.Filename,
		Size:        info.Size,
	}, nil
}
