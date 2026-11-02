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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testMsgQuotaRefusal is the log message of a blob the quota keeps out.
const testMsgQuotaRefusal = "blob refused: file broker quota exceeded"

// syncBuffer collects log output; the cleanup goroutine may log as well.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// refusals returns the WARN records of quota refusals logged so far.
func (b *syncBuffer) refusals(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["msg"] == testMsgQuotaRefusal {
			out = append(out, rec)
		}
	}
	return out
}

func newLoggedStore(t *testing.T, q Quota) (*Store, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	s, err := NewStore(t.TempDir(), "http://localhost:8080", slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s.SetQuota(q)
	return s, logs
}

// assertOneRefusal checks that exactly one refusal for owner was logged at
// WARN, with the quota error.
func assertOneRefusal(t *testing.T, logs *syncBuffer, owner string) {
	t.Helper()
	recs := logs.refusals(t)
	if len(recs) != 1 {
		t.Fatalf("%d refusal log lines, want 1", len(recs))
	}
	rec := recs[0]
	if rec["level"] != "WARN" || rec["owner"] != owner {
		t.Errorf("refusal logged as %v, want WARN for owner %q", rec, owner)
	}
	if msg, _ := rec["error"].(string); !strings.Contains(msg, ErrQuotaExceeded.Error()) {
		t.Errorf("refusal error = %q, want the quota error", msg)
	}
}

// Every refusal is logged once, whichever check finds it.
func TestQuota_RefusalIsLoggedOnce(t *testing.T) {
	limits := UploadLimits{MaxBytes: 4 << 20, DefaultTTL: time.Hour, MaxTTL: time.Hour}
	upload := func(s *Store, content string) int {
		body, ct := multipartUpload(t, "a.bin", "application/octet-stream", content, "")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits, testOwnerAlice)
		return rec.Code
	}

	t.Run("upload refused by the file size", func(t *testing.T) {
		s, logs := newLoggedStore(t, Quota{MaxBytesPerUser: 600})
		if code := upload(s, strings.Repeat("a", 500)); code != http.StatusCreated {
			t.Fatalf("first upload: status %d", code)
		}
		if n := len(logs.refusals(t)); n != 0 {
			t.Fatalf("%d refusal log lines after an accepted upload, want 0", n)
		}
		if code := upload(s, strings.Repeat("b", 500)); code != http.StatusInsufficientStorage {
			t.Fatalf("second upload: status %d, want 507", code)
		}
		assertOneRefusal(t, logs, testOwnerAlice)
	})

	t.Run("upload refused by the declared length", func(t *testing.T) {
		s, logs := newLoggedStore(t, Quota{MaxTotalBytes: 1 << 20})
		if code := upload(s, strings.Repeat("c", 3<<20)); code != http.StatusInsufficientStorage {
			t.Fatalf("upload: status %d, want 507", code)
		}
		assertOneRefusal(t, logs, testOwnerAlice)
	})

	t.Run("stream refused while it is written", func(t *testing.T) {
		s, logs := newLoggedStore(t, Quota{MaxTotalBytes: 64 << 10})
		big := onlyReader{strings.NewReader(strings.Repeat("x", 1<<20))}
		if _, _, err := s.PutOwned(big, "application/octet-stream", "", testOwnerAlice, time.Hour); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("err = %v, want ErrQuotaExceeded", err)
		}
		assertOneRefusal(t, logs, testOwnerAlice)
	})
}
