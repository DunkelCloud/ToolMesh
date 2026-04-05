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

package backend

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestSSRFSafeTransport_InvalidAddr(t *testing.T) {
	withStrictSSRF(t)

	tr := SSRFSafeTransport(2 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://not-a-real-host.invalid/", nil)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Error("expected dial error for nonexistent host")
	}
}

func TestValidateBaseURL_PublicHostPasses(t *testing.T) {
	withStrictSSRF(t)
	// example.com resolves to a public IP.
	if err := ValidateBaseURL("https://example.com/api"); err != nil {
		t.Errorf("expected public host to pass, got %v", err)
	}
}
