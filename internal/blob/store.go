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

// Package blob provides a local file-backed blob store with TTL-based expiry.
// Binary API responses are stored as files and served via HTTP, allowing LLMs
// to return download URLs instead of inline data.
package blob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store manages binary blobs on disk with TTL-based expiry.
type Store struct {
	dir     string
	baseURL string // e.g. "http://localhost:8080" — used to construct download URLs
	logger  *slog.Logger

	mu    sync.RWMutex
	blobs map[string]*blobEntry
}

type blobEntry struct {
	FilePath    string
	ContentType string
	Size        int64
	ExpiresAt   time.Time
}

// NewStore creates a blob store. baseURL is the externally reachable server URL
// (e.g. "http://localhost:8080"). dir is the on-disk directory for blob files.
func NewStore(dir, baseURL string, logger *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create blob dir %s: %w", dir, err)
	}
	s := &Store{
		dir:     dir,
		baseURL: strings.TrimRight(baseURL, "/"),
		logger:  logger,
		blobs:   make(map[string]*blobEntry),
	}
	go s.cleanupLoop()
	return s, nil
}

// Put writes data to a new blob and returns its ID.
func (s *Store) Put(body io.Reader, contentType string, ttl time.Duration) (id string, size int64, err error) {
	id, err = generateID()
	if err != nil {
		return "", 0, fmt.Errorf("generate blob id: %w", err)
	}

	ext := extensionForType(contentType)
	filename := id + ext
	path := filepath.Join(s.dir, filename)

	f, err := os.Create(path) //nolint:gosec // path is constructed from trusted dir + generated ID
	if err != nil {
		return "", 0, fmt.Errorf("create blob file: %w", err)
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()

	n, err := io.Copy(f, body)
	if err != nil {
		return "", 0, fmt.Errorf("write blob: %w", err)
	}

	s.mu.Lock()
	s.blobs[id] = &blobEntry{
		FilePath:    path,
		ContentType: contentType,
		Size:        n,
		ExpiresAt:   time.Now().Add(ttl),
	}
	s.mu.Unlock()

	s.logger.Info("blob stored",
		"blob_id", id,
		"content_type", contentType,
		"size_bytes", n,
		"ttl", ttl.String(),
	)

	return id, n, nil
}

// URL returns the download URL for a blob.
func (s *Store) URL(id string) string {
	return s.baseURL + "/blobs/" + id
}

// ServeHTTP handles GET /blobs/{id} requests.
func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/blobs/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	s.mu.RLock()
	entry, ok := s.blobs[id]
	s.mu.RUnlock()

	if !ok || time.Now().After(entry.ExpiresAt) {
		http.Error(w, "not found or expired", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", entry.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filepath.Base(entry.FilePath)))

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", entry.Size))
		return
	}

	http.ServeFile(w, r, entry.FilePath)
}

// cleanupLoop removes expired blobs every 60 seconds.
func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, entry := range s.blobs {
			if now.After(entry.ExpiresAt) {
				if err := os.Remove(entry.FilePath); err != nil && !os.IsNotExist(err) {
					s.logger.Warn("failed to remove expired blob", "blob_id", id, "error", err)
				}
				delete(s.blobs, id)
				s.logger.Debug("expired blob removed", "blob_id", id)
			}
		}
		s.mu.Unlock()
	}
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func extensionForType(contentType string) string {
	// Strip parameters (e.g. "audio/mpeg; charset=utf-8" → "audio/mpeg")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "" {
		mediaType = contentType
	}
	exts, _ := mime.ExtensionsByType(mediaType)
	if len(exts) > 0 {
		return exts[0]
	}
	return ".bin"
}
