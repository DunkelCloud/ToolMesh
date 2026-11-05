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

package dadl

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
)

// TestRestAuth_TokenErrorHidesQuery pins that a failed token request does
// not put its URL's query into the error text, which reaches tool results.
func TestRestAuth_TokenErrorHidesQuery(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	auth := NewRestAuth(AuthConfig{ //nolint:gosec // test fixture with credential names, not credentials
		Type:                   authTypeOAuth2,
		TokenURL:               "http://" + addr + "/token?tenant_key=" + hardeningSecret,
		ClientIDCredential:     testOAuth2CID,
		ClientSecretCredential: hardeningSecretName,
	}, hardeningBase, mapCreds{testOAuth2CID: "id", hardeningSecretName: "x"}, slog.Default())
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, hardeningBase+"/x", nil)
	err = auth.InjectAuth(context.Background(), req)
	if err == nil {
		t.Fatal("expected the token request to fail")
	}
	if strings.Contains(err.Error(), hardeningSecret) {
		t.Errorf("error text contains the token URL query: %v", err)
	}
}
