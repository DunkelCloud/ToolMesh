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

// JSON Schema and MCP content-block string literals used in many
// places across the package. Centralized so the goconst linter does not
// flag each occurrence.
const (
	// MCP content-block keys / values.
	contentKeyType = "type"
	contentKeyText = "text"

	// JSON Schema property keys used when assembling input schemas.
	schemaKeyProperties  = "properties"
	schemaKeyRequired    = "required"
	schemaKeyDescription = "description"

	// MCP tool argument names referenced in built-in tool schemas.
	argNamePattern = "pattern"
	argNameCode    = "code"
	argNamePayload = "payload"

	// Common debug_generate pattern values.
	debugPatternASCII = "ascii"

	// Outcome / log field literals.
	outcomeError = "error"
	logKeyTool   = "tool"

	// OAuth 2.1 / authorization endpoint fields.
	oauthClientID         = "client_id"
	oauthRedirectURI      = "redirect_uri"
	oauthState            = "state"
	oauthScope            = "scope"
	oauthCode             = "code"
	oauthCodeChallenge    = "code_challenge"
	oauthRefreshToken     = "refresh_token" //nolint:gosec // OAuth field name, not a credential
	oauthGrantAuthCode    = "authorization_code"
	oauthErrorDescription = "error_description"
	oauthErrInvalidRedURI = "invalid_redirect_uri"
	oauthErrServerError   = "server_error"
	invalidGrantError     = "invalid_grant"
	oauthErrInvalidReq    = "invalid_request"

	// DADL ParamDef "in:" value reused in built-in tool fixtures.
	paramInQuery = "query"

	// OAuth 2.1 token-endpoint form field.
	oauthGrantType = "grant_type"

	// Authorization scheme literal.
	authSchemeBearer = "Bearer"

	// Anonymous user identifier and other common MCP literals.
	userAnonymous  = "anonymous"
	userDefault    = "default"
	clientClaudeAI = "claudeai"
)
