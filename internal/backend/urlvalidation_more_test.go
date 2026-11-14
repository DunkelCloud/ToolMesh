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
	tr := SSRFSafeTransport(2*time.Second, false, false)
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

// TestValidateBaseURL_PublicHostPasses pins that a public destination passes.
// The hosts are address literals: the resolver returns a literal unchanged,
// so the test needs no DNS, and the answer goes through the same checks as
// the addresses of a host name.
func TestValidateBaseURL_PublicHostPasses(t *testing.T) {
	for _, raw := range []string{
		"https://93.184.215.14/api",
		"http://93.184.215.14:8080/api",
		"https://[2606:4700:4700::1111]/api",
	} {
		if err := ValidateBaseURL(raw); err != nil {
			t.Errorf("ValidateBaseURL(%s) = %v, want a public destination to pass", raw, err)
		}
	}
}
