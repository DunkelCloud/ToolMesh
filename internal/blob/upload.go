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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// uploadMemoryLimit is the in-memory threshold for multipart parsing; larger
// uploads spill to temporary files that are removed after the request.
const uploadMemoryLimit = 32 << 20 // 32 MB

// uploadFormOverhead is headroom on top of UploadLimits.MaxBytes for
// multipart boundaries, part headers, and the ttl field.
const uploadFormOverhead = 1 << 20 // 1 MB

// UploadLimits bounds HandleUpload.
type UploadLimits struct {
	MaxBytes   int64         // hard cap on the uploaded file size
	DefaultTTL time.Duration // applied when the ttl form field is absent
	MaxTTL     time.Duration // ceiling for caller-supplied ttl values
}

// DefaultUploadLimits returns the standard broker upload limits: 100 MB per
// file (matching the streaming-response ceiling), 1h default TTL, 24h max.
func DefaultUploadLimits() UploadLimits {
	return UploadLimits{
		MaxBytes:   100 << 20,
		DefaultTTL: time.Hour,
		MaxTTL:     24 * time.Hour,
	}
}

// UploadResult is the JSON body of a successful upload. The file_id, url,
// and expires field names match FileBrokerUploadResult in internal/backend,
// so ToolMesh's own broker client can talk to this endpoint.
type UploadResult struct {
	FileID      string    `json:"file_id"`
	Handle      string    `json:"handle"`
	URL         string    `json:"url"`
	Expires     time.Time `json:"expires"`
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type"`
}

// HandleUpload processes POST /files/upload: a multipart form with the file
// in field "file" and an optional "ttl" field (Go duration, e.g. "24h").
// Authentication is the caller's responsibility — this method implements
// only the storage mechanics (DADL spec §6.2.3).
func (s *Store) HandleUpload(w http.ResponseWriter, r *http.Request, limits UploadLimits) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxBytes+uploadFormOverhead)
	if err := r.ParseMultipartForm(uploadMemoryLimit); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, fmt.Sprintf("upload exceeds the %d byte limit", limits.MaxBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `multipart field "file" is required`, http.StatusBadRequest)
		return
	}
	defer func() { _ = file.Close() }()

	if header.Size > limits.MaxBytes {
		http.Error(w, fmt.Sprintf("upload exceeds the %d byte limit", limits.MaxBytes), http.StatusRequestEntityTooLarge)
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	ttl := limits.DefaultTTL
	if v := r.FormValue("ttl"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			http.Error(w, fmt.Sprintf("invalid ttl %q: expected a positive Go duration like 24h", v), http.StatusBadRequest)
			return
		}
		if d > limits.MaxTTL {
			d = limits.MaxTTL
		}
		ttl = d
	}

	id, size, err := s.PutNamed(file, contentType, header.Filename, ttl)
	if err != nil {
		s.logger.Error("blob upload failed", "error", err)
		http.Error(w, "store upload", http.StatusInternalServerError)
		return
	}
	info, err := s.Stat(id)
	if err != nil {
		http.Error(w, "store upload", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(UploadResult{
		FileID:      id,
		Handle:      Handle(id),
		URL:         s.URL(id),
		Expires:     info.ExpiresAt,
		Size:        size,
		ContentType: contentType,
	})
}
