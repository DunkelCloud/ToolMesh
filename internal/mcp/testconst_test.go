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

// Test-only constants for fixture strings reused across the mcp package
// tests. Extracted only to keep the goconst linter quiet.
const (
	// Fixture backend / hostname names.
	testBackendNameGitHub  = "github"
	testHintLocalMemory    = "Local memory store"
	testHintDokuWiki       = "DokuWiki JSON-RPC API"
	testHostnameDokuWiki   = "dokuwiki-dunkel.io"
	testHintOPNsense       = "OPNsense REST API"
	testHintBackendAlpha   = "tmtest backend alpha"
	testHintBackendBeta    = "tmtest backend beta"
	testToolGithubListIss  = "github_list_issues"
	testToolGithubCreatePR = "github_create_pull"
	testToolVikunjaList    = "vikunja_list_tasks"
	testToolVikunjaCreate  = "vikunja_create_task"

	// Direct-test tool name fixture.
	testDirectToolName = "test:tool"

	// Origins / URLs.
	testOriginClaudeAI = "https://claude.ai"
	testIssuerToolmesh = "https://toolmesh.io/"
	testIPClaudeAI443  = "10.0.0.1:443"

	// OAuth form fixture password value.
	testFormPassword = "password" //nolint:gosec // test fixture form key, not a credential

	// Additional fixture identifiers / values reused across tests.
	testParamLimit        = "limit"
	testBackendMemorizer  = "memorizer"
	testHostDokuWikiCloud = "dokuwiki-dunkel.cloud"
	testCredOPNsense      = "sha-opn"
	testCredDokuWiki      = "sha-doku"
	testToolTmtestAlpha   = "tmtest_alpha"
	testToolTmtestBeta    = "tmtest_beta"
	testIP198_51_100_7    = "198.51.100.7"

	// Promotion-related test fixtures.
	testToolWebSearch           = "web_search"
	testCanonicalBraveWebSearch = "brave_web_search"

	// OAuth client-registration fixture used by /register handler tests.
	testRegisterBodyExampleCB = `{"redirect_uris": ["https://example.com/cb"], "client_name": "t"}`
)
