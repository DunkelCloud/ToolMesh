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

// JSON Schema and DADL string literals reused across the backend package.
// Centralized here so the goconst linter does not flag each occurrence.
const (
	// JSON Schema "type" values.
	schemaTypeString  = "string"
	schemaTypeNumber  = "number"
	schemaTypeBoolean = "boolean"
	schemaTypeInteger = "integer"
	schemaTypeObject  = "object"
	schemaKeyRequired = "required"

	// JSON Schema property keys used when assembling input schemas.
	schemaKeyType        = "type"
	schemaKeyProperties  = "properties"
	schemaKeyDescription = "description"
	schemaKeyMessage     = "message"
	// schemaKeyAdditionalProperties closes a generated input schema, matching
	// the runtime's rejection of undeclared arguments.
	schemaKeyAdditionalProperties = "additionalProperties"

	// MCP text-content fields.
	contentTypeText = "text"

	// DADL ParamDef "in:" values.
	paramInPath   = "path"
	paramInQuery  = "query"
	paramInBody   = "body"
	paramInHeader = "header"

	// DADL ParamDef "type:" value for file uploads.
	paramTypeFile = "file"

	// Fallback content type for binary payloads of unknown type.
	contentTypeOctetStream = "application/octet-stream"

	// Default content type applied to a JSON request body when the tool,
	// backend defaults, and multipart/raw-file branches leave it unset.
	contentTypeJSON = "application/json"

	// ToolResult metadata keys.
	metadataKeyBackend    = "backend"
	metadataKeyTransport  = "transport"
	metadataKeyStatusCode = "statusCode"

	// Structured error metadata (DADL spec §8.2) set on IsError results so
	// downstream consumers (composite sandbox, Code Mode wire format) can
	// branch on the semantic code without re-parsing the error text.
	metadataKeyErrorCode    = "error_code"
	metadataKeyErrorMessage = "error_message"
	metadataKeyProviderCode = "provider_code"

	// Transport identifiers used in backends.yaml entries.
	transportTypeREST = "rest"
	transportTypeHTTP = "http"

	// File-broker response keys.
	fileKeyID          = "file_id"
	fileKeyURL         = "url"
	fileKeyExpires     = "expires"
	fileKeyContentType = "content_type"
	fileKeySizeBytes   = "size_bytes"

	// Built-in echo backend identifiers.
	echoToolName    = "echo"
	echoBackendName = "builtin:echo"

	// Tool access classifications.
	accessRead = "read"

	// Stringified booleans used when serializing primitive params into URL
	// query strings, headers, and form fields.
	boolTrue  = "true"
	boolFalse = "false"

	// URL scheme & host literals used by SSRF/redirect validation.
	urlSchemeHTTP          = "http"
	hostnameLocalhost      = "localhost"
	hostnameGoogleMetadata = "metadata.google.internal"
)
