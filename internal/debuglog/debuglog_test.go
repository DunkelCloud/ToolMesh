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

package debuglog

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
)

func TestOpenDebugFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	f, err := OpenDebugFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello\n"); err != nil {
		t.Errorf("write: %v", err)
	}
	_ = f.Close()
}

func TestFilteredTeeHandler_WithGroup(t *testing.T) {
	h1 := slog.NewTextHandler(io.Discard, nil)
	filtered := NewFilteredTeeHandler(h1, io.Discard, map[string]bool{"app": true})
	if filtered.WithGroup("grp") == nil {
		t.Error("WithGroup returned nil")
	}
}
