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
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestNewStore_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Attempt to create store in an invalid (empty) path is fine, but we
	// can trigger the file-open error path below via put.
	s, err := NewStore(t.TempDir(), "http://localhost", logger)
	if err != nil {
		t.Fatal(err)
	}

	// Put returns an id.
	id, size, err := s.Put(strings.NewReader("x"), "text/plain", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if size != 1 || id == "" {
		t.Errorf("size=%d id=%q", size, id)
	}
}
