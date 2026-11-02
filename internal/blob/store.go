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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// blobFileName matches the names Put gives blob files: the 32 hex digits of
// the ID and an optional extension.
var blobFileName = regexp.MustCompile(`^[0-9a-f]{32}(\.[A-Za-z0-9._+-]+)?$`)

// Store manages binary blobs on disk with TTL-based expiry.
type Store struct {
	dir     string
	baseURL string // e.g. "http://localhost:8080" — used to construct download URLs
	logger  *slog.Logger

	mu     sync.RWMutex
	blobs  map[string]*blobEntry
	quota  Quota
	used   int64            // bytes of all blobs on disk, including those being written
	usedBy map[string]int64 // the same per owner; owners without blobs have no entry
}

type blobEntry struct {
	FilePath    string
	ContentType string
	Size        int64
	Filename    string // original upload filename; empty when none was provided
	Owner       string // user the blob counts against in the quota; empty for none
	ExpiresAt   time.Time
}

// BlobInfo describes a stored blob.
type BlobInfo struct {
	ID          string
	ContentType string
	Size        int64
	Filename    string // never empty: falls back to the on-disk name (<id>.<ext>)
	ExpiresAt   time.Time
}

func (e *blobEntry) info(id string) *BlobInfo {
	filename := e.Filename
	if filename == "" {
		filename = filepath.Base(e.FilePath)
	}
	return &BlobInfo{
		ID:          id,
		ContentType: e.ContentType,
		Size:        e.Size,
		Filename:    filename,
		ExpiresAt:   e.ExpiresAt,
	}
}

// NewStore creates a blob store. baseURL is the externally reachable server URL
// (e.g. "http://localhost:8080"). dir is the on-disk directory for blob files.
// Blob files a previous process left in dir are removed: the index of blobs
// lives in memory, so they can no longer be served, and the quota would not
// see them.
func NewStore(dir, baseURL string, logger *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create blob dir %s: %w", dir, err)
	}
	s := &Store{
		dir:     dir,
		baseURL: strings.TrimRight(baseURL, "/"),
		logger:  logger,
		blobs:   make(map[string]*blobEntry),
		usedBy:  make(map[string]int64),
	}
	s.removeLeftovers()
	go s.cleanupLoop()
	return s, nil
}

// removeLeftovers deletes the blob files in s.dir that no index entry knows.
// Only names of the form Put gives are touched.
func (s *Store) removeLeftovers() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		s.logger.Warn("failed to list blob dir for leftover files", "dir", s.dir, "error", err)
		return
	}
	var files, size int64
	for _, e := range entries {
		if !e.Type().IsRegular() || !blobFileName.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, e.Name())); err != nil {
			s.logger.Warn("failed to remove leftover blob file", "file", e.Name(), "error", err)
			continue
		}
		files++
		size += info.Size()
	}
	if files > 0 {
		s.logger.Info("removed blob files left from a previous run", "dir", s.dir, "files", files, "bytes", size)
	}
}

// Put writes data to a new blob and returns its ID.
func (s *Store) Put(body io.Reader, contentType string, ttl time.Duration) (id string, size int64, err error) {
	return s.PutNamed(body, contentType, "", ttl)
}

// PutNamed writes data to a new blob, remembering the original filename so
// downstream multipart uploads can carry it. An empty filename is allowed.
func (s *Store) PutNamed(body io.Reader, contentType, filename string, ttl time.Duration) (id string, size int64, err error) {
	return s.PutOwned(body, contentType, filename, "", ttl)
}

// PutOwned is PutNamed for a blob that counts against owner's share of the
// quota (see Quota). An empty owner counts toward the total only. When the
// blob does not fit, nothing is kept and the error wraps ErrQuotaExceeded.
func (s *Store) PutOwned(body io.Reader, contentType, filename, owner string, ttl time.Duration) (id string, size int64, err error) {
	id, err = generateID()
	if err != nil {
		return "", 0, fmt.Errorf("generate blob id: %w", err)
	}

	ext := extensionForType(contentType)
	diskName := id + ext
	path := filepath.Join(s.dir, diskName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // path is constructed from trusted dir + generated ID
	if err != nil {
		return "", 0, fmt.Errorf("create blob file: %w", err)
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()

	qw := &quotaWriter{s: s, owner: owner, w: f}
	n, err := io.Copy(qw, body)
	if err != nil {
		s.release(owner, qw.reserved)
		if errors.Is(err, ErrQuotaExceeded) {
			s.logger.Warn("blob refused: file broker quota exceeded",
				"owner", owner,
				"content_type", contentType,
				"error", err,
			)
			return "", 0, err
		}
		return "", 0, fmt.Errorf("write blob: %w", err)
	}

	s.mu.Lock()
	s.blobs[id] = &blobEntry{
		FilePath:    path,
		ContentType: contentType,
		Size:        n,
		Filename:    filename,
		Owner:       owner,
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

// Stat returns metadata for a non-expired blob.
func (s *Store) Stat(id string) (*BlobInfo, error) {
	s.mu.RLock()
	entry, ok := s.blobs[id]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil, fmt.Errorf("blob %q not found or expired", id)
	}
	return entry.info(id), nil
}

// Open returns the content of a non-expired blob for reading, along with its
// metadata. The caller must close the reader.
func (s *Store) Open(id string) (io.ReadCloser, *BlobInfo, error) {
	s.mu.RLock()
	entry, ok := s.blobs[id]
	s.mu.RUnlock()
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil, nil, fmt.Errorf("blob %q not found or expired", id)
	}
	f, err := os.Open(entry.FilePath) //nolint:gosec // path is constructed from trusted dir + generated ID
	if err != nil {
		return nil, nil, fmt.Errorf("open blob %q: %w", id, err)
	}
	return f, entry.info(id), nil
}

// Delete removes a blob and its on-disk file. Deleting an unknown ID returns
// an error; deleting a not-yet-cleaned expired blob succeeds.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	entry, ok := s.blobs[id]
	if ok {
		delete(s.blobs, id)
		s.addLocked(entry.Owner, -entry.Size)
	}
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("blob %q not found", id)
	}
	if err := os.Remove(entry.FilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove blob file for %q: %w", id, err)
	}
	s.logger.Info("blob deleted", "blob_id", id)
	return nil
}

// ServeHTTP handles GET/HEAD/DELETE /blobs/{id} requests and performs no
// authentication itself. GET and HEAD are capability-based: the unguessable
// blob ID is the only credential, bounded by the TTL. DELETE must be
// authenticated by the caller before it reaches this handler, as the MCP
// server's /blobs/ route does.
func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/blobs/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodDelete {
		if err := s.Delete(id); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")

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
		s.removeExpired(time.Now())
	}
}

// removeExpired deletes the blobs that have expired at now, files and quota
// usage alike.
func (s *Store) removeExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.blobs {
		if now.After(entry.ExpiresAt) {
			if err := os.Remove(entry.FilePath); err != nil && !os.IsNotExist(err) {
				s.logger.Warn("failed to remove expired blob", "blob_id", id, "error", err)
			}
			delete(s.blobs, id)
			s.addLocked(entry.Owner, -entry.Size)
			s.logger.Debug("expired blob removed", "blob_id", id)
		}
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
