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

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
)

func TestNewBlobStore_Disabled(t *testing.T) {
	dataDir := t.TempDir()
	store, err := newBlobStore(&config.Config{FileBrokerEnabled: false, DataDir: dataDir}, quietLogger())
	if err != nil {
		t.Fatalf("newBlobStore: %v", err)
	}
	if store != nil {
		t.Fatal("newBlobStore returned a store although the file broker is off")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "blobs")); !os.IsNotExist(err) {
		t.Errorf("blob directory created although the file broker is off (stat err %v)", err)
	}
}

func TestNewBlobStore_EnabledWithQuota(t *testing.T) {
	cfg := &config.Config{
		FileBrokerEnabled:         true,
		DataDir:                   t.TempDir(),
		Issuer:                    "https://toolmesh.example.com/",
		FileBrokerMaxTotalBytes:   8,
		FileBrokerMaxBytesPerUser: 4,
	}
	store, err := newBlobStore(cfg, quietLogger())
	if err != nil {
		t.Fatalf("newBlobStore: %v", err)
	}
	if store == nil {
		t.Fatal("newBlobStore returned no store although the file broker is on")
	}
	if got := store.URL("x"); got != "https://toolmesh.example.com/blobs/x" {
		t.Errorf("URL = %q", got)
	}

	if _, _, err := store.PutOwned(strings.NewReader("abcd"), "text/plain", "", "u1", time.Hour); err != nil {
		t.Fatalf("blob within the quota: %v", err)
	}
	if _, _, err := store.PutOwned(strings.NewReader("e"), "text/plain", "", "u1", time.Hour); !errors.Is(err, blob.ErrQuotaExceeded) {
		t.Errorf("blob over the per-user quota: err = %v, want ErrQuotaExceeded", err)
	}
	if _, _, err := store.PutOwned(strings.NewReader("abcde"), "text/plain", "", "u2", time.Hour); !errors.Is(err, blob.ErrQuotaExceeded) {
		t.Errorf("blob over the total quota: err = %v, want ErrQuotaExceeded", err)
	}
}
