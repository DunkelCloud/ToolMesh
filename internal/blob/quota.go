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
	"errors"
	"fmt"
	"io"
)

// Quota bounds the bytes the store keeps on disk. A zero limit is no limit.
// Blobs count from the moment they are written until they are deleted or
// removed after expiry, which happens within a minute of the TTL running out.
type Quota struct {
	// MaxTotalBytes bounds all blobs together.
	MaxTotalBytes int64
	// MaxBytesPerUser bounds the blobs stored for one owner. Blobs stored
	// without an owner count toward MaxTotalBytes only.
	MaxBytesPerUser int64
}

// ErrQuotaExceeded is wrapped by the error a store operation returns when the
// blob would not fit in the quota.
var ErrQuotaExceeded = errors.New("file broker quota exceeded")

// quotaHint tells the caller how to get under the quota again.
const quotaHint = "delete blobs that are no longer needed (DELETE /blobs/<id>) or wait for them to expire"

// SetQuota sets the quota for blobs stored from now on. Blobs already stored
// stay, even when they exceed the new quota; they only keep new ones out.
func (s *Store) SetQuota(q Quota) {
	s.mu.Lock()
	s.quota = q
	s.mu.Unlock()
}

// Usage returns the bytes held by all blobs and by the blobs of owner.
func (s *Store) Usage(owner string) (total, ofOwner int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.used, s.usedBy[owner]
}

// CheckQuota reports whether size more bytes for owner fit in the quota. Put
// enforces the quota on its own while it writes; CheckQuota only lets a caller
// that knows the size in advance turn a request away before reading its body.
// A size that does not fit is logged as a refusal, like one found while
// writing, since every caller turns the file away on an error.
func (s *Store) CheckQuota(owner string, size int64) error {
	s.mu.RLock()
	err := s.fitsLocked(owner, 0, size)
	s.mu.RUnlock()
	if err != nil {
		s.logRefusal(owner, err)
	}
	return err
}

// logRefusal logs a blob the quota keeps out. Every refusal passes here
// exactly once: a failed pre-check ends the request before anything is
// written, and a failed reservation ends the write.
func (s *Store) logRefusal(owner string, err error) {
	s.logger.Warn("blob refused: file broker quota exceeded", "owner", owner, "error", err)
}

// fitsLocked reports whether n more bytes fit for owner, of which pending are
// already reserved for the blob being written. s.mu must be held.
func (s *Store) fitsLocked(owner string, pending, n int64) error {
	if limit := s.quota.MaxTotalBytes; limit > 0 && s.used+n > limit {
		return fmt.Errorf("%w: the file broker may hold %d bytes in total and %d are in use; %s",
			ErrQuotaExceeded, limit, s.used-pending, quotaHint)
	}
	if limit := s.quota.MaxBytesPerUser; limit > 0 && owner != "" && s.usedBy[owner]+n > limit {
		return fmt.Errorf("%w: each user may hold %d bytes in the file broker and %d are in use by yours; %s",
			ErrQuotaExceeded, limit, s.usedBy[owner]-pending, quotaHint)
	}
	return nil
}

// reserve counts n more bytes for owner if they fit in the quota. pending is
// what the same blob has reserved so far, so that the error names only the
// bytes held by other blobs.
func (s *Store) reserve(owner string, pending, n int64) error {
	s.mu.Lock()
	err := s.fitsLocked(owner, pending, n)
	if err == nil {
		s.addLocked(owner, n)
	}
	s.mu.Unlock()
	if err != nil {
		s.logRefusal(owner, err)
	}
	return err
}

// release gives back n bytes counted for owner.
func (s *Store) release(owner string, n int64) {
	s.mu.Lock()
	s.addLocked(owner, -n)
	s.mu.Unlock()
}

// addLocked adds n (which may be negative) to the usage of owner and to the
// total. s.mu must be held.
func (s *Store) addLocked(owner string, n int64) {
	s.used += n
	if owner == "" {
		return
	}
	if v := s.usedBy[owner] + n; v > 0 {
		s.usedBy[owner] = v
	} else {
		delete(s.usedBy, owner)
	}
}

// quotaWriter counts every chunk against the quota before writing it, so a
// blob of unknown length stops at the quota instead of filling the disk.
type quotaWriter struct {
	s        *Store
	owner    string
	w        io.Writer
	reserved int64
}

func (q *quotaWriter) Write(p []byte) (int, error) {
	if err := q.s.reserve(q.owner, q.reserved, int64(len(p))); err != nil {
		return 0, err
	}
	n, err := q.w.Write(p)
	if n < len(p) {
		q.s.release(q.owner, int64(len(p)-n))
	}
	q.reserved += int64(n)
	return n, err
}
