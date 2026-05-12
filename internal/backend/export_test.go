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

// testRESTOpts is the default RESTAdapterOptions used by tests. It allows
// private URLs so that tests targeting httptest servers on 127.0.0.1 work
// without tripping SSRF validation.
var testRESTOpts = RESTAdapterOptions{AllowPrivateURL: true}

// Test fixture string constants. These mirror the literals that appear most
// often in fixture DADL specs, HTTP server stubs, and assertion strings — they
// are extracted only to keep the goconst linter quiet, not to encode anything
// semantic that production code depends on.
const (
	// DADL spec URL used by every fixture spec.
	testDADLSpecURL = "https://dadl.ai/spec/dadl-spec-v0.1.md"

	// Fixture backend names.
	testBackendNameAPI     = "api"
	testBackendNameTestAPI = "testapi"
	testBackendNameTest    = "test"
	testBackendNameMy      = "mybackend"
	testBackendNameGitHub  = "github"

	// Fixture base URLs.
	testBaseURLExample = "https://api.example.com"
	testBaseURLGitLab  = "https://gitlab.example.com/api/v4"
	testMCPURLExample  = "https://example.com/mcp"

	// Fixture tool names.
	testToolGetItem   = "get_item"
	testToolListItems = "list_items"
	testToolGetAudio  = "get_audio"
	testToolSearch    = "search"
	testToolWebSearch = "web_search"
	testToolFetchURL  = "fetch_url"
	testDescWebSearch = "search the web"

	// Vendor backend names used across promotion tests.
	testVendorBrave  = "brave"
	testVendorTavily = "tavily"

	// Fixture path literals.
	testPathItems     = "/items"
	testPathItemsByID = "/items/{id}"
	testPathAudio     = "/audio"
	testDescGetItem   = "Get an item"
	testDescListItems = "List items"

	// Fixture HTTP method literals (separate from "GET"/"POST" because tests
	// also assert on them as strings).
	testMethodGET  = "GET"
	testMethodPOST = "POST"

	// Common header names asserted in tests.
	testHeaderContentType = "Content-Type"
	testHeaderAccept      = "Accept"
	testHeaderAuth        = "Authorization"
	testHeaderFieldMask   = "X-Goog-FieldMask"

	// Common query/body param names used in fixtures.
	testParamPage      = "page"
	testParamFilter    = "filter"
	testParamTags      = "tags"
	testParamAccountID = "account_id"

	// Common content-type / token / response literals.
	testContentTypeJSON      = "application/json"
	testContentTypeAudioMPEG = "audio/mpeg"
	testHelloLiteral         = "hello"
	testTokenBearer          = "bearer"
	testTokenValue           = "tok"
	testJSONFormat           = "json"
	testJSONPathMessage      = "$.message"
	testPrivateLoopback      = "private/loopback"
	testVersion01            = "0.1"

	// Common DADL/HTTP body field names asserted in tests.
	testParamName      = "name"
	testParamVoiceID   = "voice_id"
	testParamTextQuery = "textQuery"
)
