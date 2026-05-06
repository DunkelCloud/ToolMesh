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

// Test-only constants for fixture strings reused across the dadl package
// tests. Extracted only to keep the goconst linter quiet.
const (
	// Common access classification literal asserted by tests.
	testAccessAdmin = "admin"

	// Common test usernames / credential names / token values.
	testUserAlice              = "alice"
	testTokenABC123            = "abc123" //nolint:gosec // test token literal
	testCredMissing            = "MISSING"
	testCredOAuth2ClientID     = "CID"
	testCredOAuth2ClientSecret = "SEC" //nolint:gosec // test credential reference
	testCredAPIKey             = "api-key"
	testKeyValue               = "key-value"

	// JSONPath / format literals reused across error/transform tests.
	testJSONPathMessage = "$.message"
	testJSONFormat      = "json"

	// Fixture retry delay duration string.
	testRetryDelay1ms = "1ms"

	// Common JSON body field name asserted by parser/transform tests.
	testFieldName = "name"
	testParamBody = "body"

	// Common test API key value used in mock credentials.
	testKey123 = "key123" //nolint:gosec // test fixture, not a real credential
)
