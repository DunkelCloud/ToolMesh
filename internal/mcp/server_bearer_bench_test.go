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

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

// benchAPIKeys is the number of entries in the benchmark's apikeys.yaml.
const benchAPIKeys = 2

func benchAPIKey(i int) string { return fmt.Sprintf("bench-api-key-%d", i) }

// benchBearerServer builds a server the way a deployment with both login
// methods runs: password login with a Redis token store, and an apikeys.yaml.
// With digests the keys are written as key_sha256, otherwise as bcrypt hashes
// at the default cost, as files written for earlier versions have them.
func benchBearerServer(b *testing.B, digests bool) (*http.ServeMux, auth.TokenStore) {
	b.Helper()

	content := "keys:\n"
	for i := range benchAPIKeys {
		if digests {
			sum := sha256.Sum256([]byte(benchAPIKey(i)))
			content += fmt.Sprintf("  - key_sha256: %q\n    user_id: bench-%d\n", hex.EncodeToString(sum[:]), i)
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(benchAPIKey(i)), bcrypt.DefaultCost)
		if err != nil {
			b.Fatal(err)
		}
		content += fmt.Sprintf("  - key_hash: %q\n    user_id: bench-%d\n", hash, i)
	}
	path := filepath.Join(b.TempDir(), "apikeys.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		b.Fatal(err)
	}
	apiKeys, err := auth.NewAPIKeyStore(path, nil)
	if err != nil {
		b.Fatalf("NewAPIKeyStore: %v", err)
	}

	mr := miniredis.RunT(b)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b.Cleanup(func() { _ = rdb.Close() })
	tokens := auth.NewRedisTokenStore(rdb)

	logger := slog.New(slog.DiscardHandler)
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	cfg := &config.Config{AuthPassword: testLoginSecret, AuthUser: testLoginOwner, Issuer: testIssuerToolmesh}
	srv := NewServer(handler, cfg, logger, tokens, nil, apiKeys, nil, nil, metrics.New(metrics.Options{}))
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	return mux, tokens
}

func benchMCPCall(mux *http.ServeMux, bearer string) int {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pathMCP, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w.Code
}

// BenchmarkMCP_Bearer measures POST /mcp for the bearer credentials a server
// sees, against an apikeys.yaml with benchAPIKeys entries.
//
//	go test ./internal/mcp -run '^$' -bench MCP_Bearer -benchtime 20x
//
// "unseen" is a bcrypt-only file right after startup, before any of its keys
// was used; "seen" is the same file once each key has been presented.
func BenchmarkMCP_Bearer(b *testing.B) {
	type setup struct {
		name    string
		digests bool
		seen    bool
	}
	setups := []setup{
		{"bcrypt_only_unseen", false, false},
		{"bcrypt_only_seen", false, true},
		{"key_sha256", true, false},
	}

	for _, st := range setups {
		newServer := func(b *testing.B) (*http.ServeMux, string) {
			b.Helper()
			mux, tokens := benchBearerServer(b, st.digests)
			if st.seen {
				for i := range benchAPIKeys {
					if code := benchMCPCall(mux, benchAPIKey(i)); code != http.StatusOK {
						b.Fatalf("API key %d: status = %d, want 200", i, code)
					}
				}
			}
			token := generateID()
			err := tokens.SaveToken(context.Background(), &auth.TokenInfo{
				AccessToken: token, ClientID: "bench", UserID: testLoginOwner, ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				b.Fatalf("SaveToken: %v", err)
			}
			return mux, token
		}

		b.Run("unknown_bearer/"+st.name, func(b *testing.B) {
			mux, _ := newServer(b)
			b.ResetTimer()
			for range b.N {
				if code := benchMCPCall(mux, "not-a-credential"); code != http.StatusUnauthorized {
					b.Fatalf("status = %d, want 401", code)
				}
			}
		})
		b.Run("access_token/"+st.name, func(b *testing.B) {
			mux, token := newServer(b)
			b.ResetTimer()
			for range b.N {
				if code := benchMCPCall(mux, token); code != http.StatusOK {
					b.Fatalf("status = %d, want 200", code)
				}
			}
		})
		b.Run("api_key/"+st.name, func(b *testing.B) {
			mux, _ := newServer(b)
			last := benchAPIKey(benchAPIKeys - 1)
			b.ResetTimer()
			for range b.N {
				if code := benchMCPCall(mux, last); code != http.StatusOK {
					b.Fatalf("status = %d, want 200", code)
				}
			}
		})
	}
}
