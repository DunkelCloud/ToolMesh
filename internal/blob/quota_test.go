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
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testOwnerAlice = "alice"
	testOwnerBob   = "bob"
)

// onlyReader hides the length of the wrapped reader, like a chunked HTTP
// response body.
type onlyReader struct{ r io.Reader }

func (o onlyReader) Read(p []byte) (int, error) { return o.r.Read(p) }

// putSize stores size bytes for owner.
func putSize(t *testing.T, s *Store, owner string, size int) (string, error) {
	t.Helper()
	id, _, err := s.PutOwned(strings.NewReader(strings.Repeat("x", size)), "text/plain", "", owner, time.Hour)
	return id, err
}

// filesOnDisk counts the blob files in the store's directory.
func filesOnDisk(t *testing.T, s *Store) int {
	t.Helper()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	return len(entries)
}

func assertUsage(t *testing.T, s *Store, owner string, wantTotal, wantOwner int64) {
	t.Helper()
	total, ofOwner := s.Usage(owner)
	if total != wantTotal || ofOwner != wantOwner {
		t.Errorf("Usage(%q) = (%d, %d), want (%d, %d)", owner, total, ofOwner, wantTotal, wantOwner)
	}
}

func TestQuota_Total(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxTotalBytes: 10})

	first, err := putSize(t, s, testOwnerAlice, 6)
	if err != nil {
		t.Fatalf("first blob: %v", err)
	}

	_, err = putSize(t, s, testOwnerBob, 6)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second blob: err = %v, want ErrQuotaExceeded", err)
	}
	// The error names the limit and what other blobs hold, not the partly
	// written refused blob.
	if msg := err.Error(); !strings.Contains(msg, "10 bytes in total and 6 are in use") {
		t.Errorf("error = %q", msg)
	}
	if n := filesOnDisk(t, s); n != 1 {
		t.Errorf("%d files on disk after the refusal, want 1", n)
	}
	assertUsage(t, s, testOwnerBob, 6, 0)

	// A blob that fits exactly is accepted.
	if _, err := putSize(t, s, testOwnerBob, 4); err != nil {
		t.Fatalf("blob that fits exactly: %v", err)
	}
	assertUsage(t, s, testOwnerBob, 10, 4)

	// Deleting gives the space back.
	if err := s.Delete(first); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertUsage(t, s, testOwnerAlice, 4, 0)
	if _, err := putSize(t, s, testOwnerAlice, 6); err != nil {
		t.Fatalf("blob after delete: %v", err)
	}
}

func TestQuota_PerUser(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxBytesPerUser: 5})

	if _, err := putSize(t, s, testOwnerAlice, 4); err != nil {
		t.Fatalf("alice first: %v", err)
	}
	_, err := putSize(t, s, testOwnerAlice, 2)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("alice second: err = %v, want ErrQuotaExceeded", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "each user may hold 5 bytes") || !strings.Contains(msg, "4 are in use by yours") {
		t.Errorf("error = %q", msg)
	}

	// Another user has a share of their own.
	if _, err := putSize(t, s, testOwnerBob, 5); err != nil {
		t.Fatalf("bob: %v", err)
	}
	// A blob without an owner counts toward the total only.
	if _, err := putSize(t, s, "", 50); err != nil {
		t.Fatalf("blob without owner: %v", err)
	}
	assertUsage(t, s, testOwnerAlice, 59, 4)
}

func TestQuota_StopsStreamOfUnknownLength(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxTotalBytes: 100 << 10})

	big := onlyReader{strings.NewReader(strings.Repeat("x", 1<<20))}
	_, _, err := s.PutOwned(big, "application/octet-stream", "big.bin", testOwnerAlice, time.Hour)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	if n := filesOnDisk(t, s); n != 0 {
		t.Errorf("%d files on disk after the refusal, want 0", n)
	}
	assertUsage(t, s, testOwnerAlice, 0, 0)
}

func TestQuota_ExpiryGivesSpaceBack(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxTotalBytes: 10, MaxBytesPerUser: 10})

	if _, err := putSize(t, s, testOwnerAlice, 10); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Expired but not yet removed, the blob still takes its space.
	if err := s.CheckQuota(testOwnerAlice, 1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("CheckQuota before cleanup = %v, want ErrQuotaExceeded", err)
	}
	s.removeExpired(time.Now().Add(2 * time.Hour))
	assertUsage(t, s, testOwnerAlice, 0, 0)
	if err := s.CheckQuota(testOwnerAlice, 10); err != nil {
		t.Errorf("CheckQuota after cleanup = %v", err)
	}
}

func TestQuota_LoweredBelowUsageKeepsBlobs(t *testing.T) {
	s := newTestStore(t)
	id, err := putSize(t, s, testOwnerAlice, 8)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	s.SetQuota(Quota{MaxTotalBytes: 4})
	if _, err := s.Stat(id); err != nil {
		t.Errorf("existing blob gone after lowering the quota: %v", err)
	}
	if _, err := putSize(t, s, testOwnerAlice, 1); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("new blob over the lowered quota: err = %v, want ErrQuotaExceeded", err)
	}
}

func TestQuota_NoLimitByDefault(t *testing.T) {
	s := newTestStore(t)
	for i := range 3 {
		if _, err := putSize(t, s, testOwnerAlice, 1<<20); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	assertUsage(t, s, testOwnerAlice, 3<<20, 3<<20)
}

func TestQuota_HandleUpload(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxBytesPerUser: 16})
	limits := UploadLimits{MaxBytes: 1 << 20, DefaultTTL: time.Hour, MaxTTL: time.Hour}

	upload := func(content string) *httptest.ResponseRecorder {
		body, ct := multipartUpload(t, "a.bin", "application/octet-stream", content, "")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits, testOwnerAlice)
		return rec
	}

	if rec := upload(strings.Repeat("a", 10)); rec.Code != http.StatusCreated {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	assertUsage(t, s, testOwnerAlice, 10, 10)

	rec := upload(strings.Repeat("b", 10))
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("second upload: status %d, want 507; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), ErrQuotaExceeded.Error()) {
		t.Errorf("body = %q, want the quota error", rec.Body.String())
	}
	assertUsage(t, s, testOwnerAlice, 10, 10)
}

// TestNewStore_RemovesLeftovers covers a restart: the files of the previous
// process are no longer indexed, so they would take space the quota does not
// see and that no expiry would ever free.
func TestNewStore_RemovesLeftovers(t *testing.T) {
	dir := t.TempDir()
	leftovers := []string{"0123456789abcdef0123456789abcdef.png", "fedcba9876543210fedcba9876543210"}
	others := []string{"notes.txt", "ABCDEF0123456789ABCDEF0123456789.png", "0123.bin"}
	for _, name := range append(append([]string{}, leftovers...), others...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "abcdefabcdefabcdefabcdefabcdefab"), 0o750); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(dir, "http://localhost:8080", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	for _, name := range leftovers {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("leftover %s still there (stat err %v)", name, err)
		}
	}
	for _, name := range append(others, "abcdefabcdefabcdefabcdefabcdefab") {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was removed although it is no blob file: %v", name, err)
		}
	}
	assertUsage(t, s, "", 0, 0)
}
