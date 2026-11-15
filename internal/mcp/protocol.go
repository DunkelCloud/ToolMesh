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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/version"
)

// The MCP endpoint speaks two generations of the protocol at once.
//
// Up to revision 2025-11-25 a client opens with an initialize handshake and
// the revision is settled there. From revision 2026-07-28 there is no
// handshake: every request names its revision and the client's capabilities
// in the _meta of its params, and repeats the revision, the method and the
// tool name in HTTP headers so that a proxy can route on them without
// reading the body. Which generation a request belongs to is decided per
// request, from the request alone; the server keeps nothing between two
// requests in either of them.
const (
	protocolVersion20260728 = "2026-07-28"
	protocolVersion20251125 = "2025-11-25"
)

// supportedProtocolVersions are the revisions the endpoint answers in,
// newest first. They are what server/discover and the error for an
// unsupported revision name.
var supportedProtocolVersions = []string{protocolVersion20260728, protocolVersion20251125}

// handshakeProtocolVersions are the revisions that open with initialize. A
// request that names one of them in its MCP-Protocol-Version header, and no
// revision in its body, is served the way it always was.
var handshakeProtocolVersions = map[string]bool{
	protocolVersion20251125: true,
	"2025-06-18":            true,
	"2025-03-26":            true,
	"2024-11-05":            true,
}

// protocolEra is the generation of the protocol one request is served in.
type protocolEra int

const (
	// eraHandshake is every revision up to 2025-11-25.
	eraHandshake protocolEra = iota
	// eraStateless is revision 2026-07-28.
	eraStateless
)

// HTTP headers of the stateless revision. net/http stores header names in
// their canonical form, which is the form given here.
const (
	headerProtocolVersion = "Mcp-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"
)

// Keys of _meta that the stateless revision reserves.
const (
	metaKey                   = "_meta"
	metaKeyProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaKeyServerInfo         = "io.modelcontextprotocol/serverInfo"
	metaKeySubscriptionID     = "io.modelcontextprotocol/subscriptionId"
)

// JSON-RPC error codes. The -3202x codes are the ones the MCP specification
// defines in the range it reserves for itself.
const (
	codeInvalidRequest             = -32600
	codeMethodNotFound             = -32601
	codeInvalidParams              = -32602
	codeHeaderMismatch             = -32020
	codeUnsupportedProtocolVersion = -32022
)

// Methods of the endpoint.
const (
	methodInitialize          = "initialize"
	methodPing                = "ping"
	methodDiscover            = "server/discover"
	methodToolsList           = "tools/list"
	methodToolsCall           = "tools/call"
	methodSubscriptionsListen = "subscriptions/listen"
)

// The version member every JSON-RPC message carries.
const (
	jsonRPCKey     = "jsonrpc"
	jsonRPCVersion = "2.0"
)

// Fields the stateless revision adds to results.
const (
	resultKeyResultType = "resultType"
	resultTypeComplete  = "complete"
	resultKeyTTL        = "ttlMs"
	resultKeyCacheScope = "cacheScope"
	// cacheScopePrivate keeps a result out of caches that several callers
	// share. The tool list is filtered by what the caller may use, so it
	// must never be handed to another caller; the discovery result is the
	// same for everyone, but is only given to authenticated callers and
	// stays with them for the same reason.
	cacheScopePrivate = "private"
)

// listResultTTL is how long a client may keep the tool list and the
// discovery result before asking again. The server sends no change
// notifications, so this bounds how stale a client's view gets after
// backends were reloaded or rights changed. It is a hint about freshness
// only: what a caller may do is decided when the tool is called.
const listResultTTL = time.Minute

// Sentinel that marks a header value as Base64 of the UTF-8 text, for values
// that do not fit into a plain header.
const (
	base64HeaderPrefix = "=?base64?"
	base64HeaderSuffix = "?="
)

// maxEchoedHeaderLen bounds a value of the caller that is repeated in an
// error message.
const maxEchoedHeaderLen = 64

// rpcError is a JSON-RPC error together with the HTTP status it is sent
// with.
type rpcError struct {
	status  int
	code    int
	message string
	data    any
}

func headerMismatch(format string, args ...any) *rpcError {
	return &rpcError{
		status:  http.StatusBadRequest,
		code:    codeHeaderMismatch,
		message: "Header mismatch: " + fmt.Sprintf(format, args...),
	}
}

func invalidParams(message string) *rpcError {
	return &rpcError{status: http.StatusBadRequest, code: codeInvalidParams, message: message}
}

func unsupportedProtocolVersion(requested string) *rpcError {
	return &rpcError{
		status:  http.StatusBadRequest,
		code:    codeUnsupportedProtocolVersion,
		message: "Unsupported protocol version",
		data: map[string]any{
			"supported": supportedProtocolVersions,
			"requested": echoValue(requested),
		},
	}
}

// echoValue bounds a value of the caller before it is repeated to them.
func echoValue(v string) string {
	if len(v) <= maxEchoedHeaderLen {
		return strings.ToValidUTF8(v, "")
	}
	return strings.ToValidUTF8(v[:maxEchoedHeaderLen], "") + "…"
}

// paramsObject returns the params of a request as an object, or nil when
// the request has none or they are not an object.
func paramsObject(req *jsonRPCRequest) map[string]any {
	params, _ := req.Params.(map[string]any)
	return params
}

// singleHeader returns the value of a header that may occur once. A header
// sent twice is not read at all: a proxy in front and this server could
// each pick another one of the two values.
func singleHeader(h http.Header, name string) (value string, present, repeated bool) {
	values := h.Values(name)
	switch len(values) {
	case 0:
		return "", false, false
	case 1:
		return values[0], true, false
	default:
		return "", true, true
	}
}

// negotiateProtocol decides which generation of the protocol a request is
// served in, from its MCP-Protocol-Version header and the revision in the
// _meta of its params. It returns an error for a request that names a
// revision in one place and another, or none, in the other, and for a
// revision the endpoint does not speak.
//
// A request that names no revision in its body is one of the handshake
// generation as long as its header names none either, or one of that
// generation: those requests are served as they always were, the header is
// not checked further. Everything else has to hold together.
func negotiateProtocol(r *http.Request, req *jsonRPCRequest) (protocolEra, *rpcError) {
	header, headerPresent, headerRepeated := singleHeader(r.Header, headerProtocolVersion)

	var bodyVersion any
	bodyPresent := false
	if meta, ok := paramsObject(req)[metaKey].(map[string]any); ok {
		bodyVersion, bodyPresent = meta[metaKeyProtocolVersion]
	}

	if !bodyPresent {
		switch {
		case !headerPresent:
			return eraHandshake, nil
		case headerRepeated:
			return 0, headerMismatch("the MCP-Protocol-Version header occurs more than once")
		case handshakeProtocolVersions[header]:
			return eraHandshake, nil
		case header == protocolVersion20260728:
			return 0, invalidParams("Invalid params: _meta is missing the required field " + metaKeyProtocolVersion)
		default:
			return 0, unsupportedProtocolVersion(header)
		}
	}

	revision, ok := bodyVersion.(string)
	if !ok || revision == "" {
		return 0, invalidParams("Invalid params: " + metaKeyProtocolVersion + " in _meta must be a non-empty string")
	}
	switch {
	case !headerPresent:
		return 0, headerMismatch("the MCP-Protocol-Version header is required for a request that names %s in _meta", metaKeyProtocolVersion)
	case headerRepeated:
		return 0, headerMismatch("the MCP-Protocol-Version header occurs more than once")
	case header != revision:
		return 0, headerMismatch("MCP-Protocol-Version header value %q does not match body value %q", echoValue(header), echoValue(revision))
	}

	switch {
	case revision == protocolVersion20260728:
		return eraStateless, nil
	case handshakeProtocolVersions[revision]:
		return eraHandshake, nil
	default:
		return 0, unsupportedProtocolVersion(revision)
	}
}

// validateRequest checks that the routing headers of a request say what
// its body says: Mcp-Method the method and, on a tools/call, Mcp-Name the
// name of the tool.
//
// Revision 2026-07-28 requires both headers, and the client's capabilities
// in _meta. A request of the handshake generation has no such headers, and
// none is asked of it. One that carries them anyway is held to them all the
// same: a proxy that admits requests by these headers without looking at
// the revision would otherwise let through a request that merely leaves
// the revision out.
func validateRequest(r *http.Request, req *jsonRPCRequest, era protocolEra) *rpcError {
	required := era == eraStateless
	params := paramsObject(req)
	if required {
		meta, _ := params[metaKey].(map[string]any)
		if _, ok := meta[metaKeyClientCapabilities].(map[string]any); !ok {
			return invalidParams("Invalid params: _meta is missing the required object " + metaKeyClientCapabilities)
		}
	}
	if perr := checkMethodHeader(r, req.Method, required); perr != nil {
		return perr
	}
	if req.Method != methodToolsCall {
		return nil
	}
	name, isString := params[jsonKeyName].(string)
	if _, present := params[jsonKeyName]; required && present && !isString {
		return invalidParams("Invalid params: name must be a string")
	}
	return checkNameHeader(r, name, required)
}

// checkMethodHeader compares the Mcp-Method header with the method of the
// body. A proxy may have routed, limited or admitted the request by the
// header; a request whose body says something else is refused, never
// executed. With required false a missing header is accepted, a wrong one
// is not.
func checkMethodHeader(r *http.Request, method string, required bool) *rpcError {
	header, present, repeated := singleHeader(r.Header, headerMethod)
	switch {
	case !present && !required:
		return nil
	case !present:
		return headerMismatch("the Mcp-Method header is required")
	case repeated:
		return headerMismatch("the Mcp-Method header occurs more than once")
	case header != method:
		return headerMismatch("Mcp-Method header value %q does not match body value %q", echoValue(header), echoValue(method))
	}
	return nil
}

// checkNameHeader compares the Mcp-Name header of a tools/call with the tool
// name in the body. The header may carry the name as it is or, for a name
// that does not fit into a header, as Base64 between the sentinel marks; it
// is decoded before the comparison. With required false a missing header is
// accepted, a wrong one is not.
func checkNameHeader(r *http.Request, name string, required bool) *rpcError {
	header, present, repeated := singleHeader(r.Header, headerName)
	switch {
	case !present && !required:
		return nil
	case !present:
		return headerMismatch("the Mcp-Name header is required for %s", methodToolsCall)
	case repeated:
		return headerMismatch("the Mcp-Name header occurs more than once")
	}
	decoded, ok := decodeHeaderValue(header)
	if !ok {
		return headerMismatch("the Mcp-Name header value is malformed")
	}
	if decoded != name {
		return headerMismatch("Mcp-Name header value %q does not match body value %q", echoValue(decoded), echoValue(name))
	}
	return nil
}

// decodeHeaderValue returns the text a header value stands for: the value
// itself, or what its Base64 between the sentinel marks decodes to. It
// reports false for Base64 that does not decode and for a plain value with
// characters a header value may not carry unencoded.
func decodeHeaderValue(v string) (string, bool) {
	if rest, ok := strings.CutPrefix(v, base64HeaderPrefix); ok {
		if encoded, ok := strings.CutSuffix(rest, base64HeaderSuffix); ok {
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				return "", false
			}
			return string(decoded), true
		}
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return "", false
		}
	}
	return v, true
}

// rpcErrorStatus is the HTTP status of a JSON-RPC error answer. The
// handshake generation answers every JSON-RPC error with 200, and keeps
// doing so. The stateless revision asks for 404 on an unknown method and
// 400 on a malformed request, so that a client can tell this server from
// one of the older generation by the answer alone.
func rpcErrorStatus(era protocolEra, code int) int {
	if era != eraStateless {
		return http.StatusOK
	}
	switch code {
	case codeMethodNotFound:
		return http.StatusNotFound
	case codeInvalidParams, codeHeaderMismatch, codeUnsupportedProtocolVersion:
		return http.StatusBadRequest
	}
	return http.StatusOK
}

// serverInfo is the name and version the server reports about itself.
func serverInfo() map[string]any {
	return map[string]any{
		jsonKeyName: "toolmesh",
		"version":   version.Version,
	}
}

// serverCapabilities are the capabilities of the endpoint: tools, and no
// notification when their list changes.
func serverCapabilities() map[string]any {
	return map[string]any{
		"tools": map[string]any{
			"listChanged": false,
		},
	}
}

// finishResult adds what revision 2026-07-28 asks of every result: its
// type, and who the server is, since no handshake has said so. Results of
// the handshake generation are left exactly as they were.
func finishResult(req *jsonRPCRequest, result map[string]any) map[string]any {
	if req.era != eraStateless {
		return result
	}
	result[resultKeyResultType] = resultTypeComplete
	meta, _ := result[metaKey].(map[string]any)
	if meta == nil {
		meta = make(map[string]any, 1)
		result[metaKey] = meta
	}
	meta[metaKeyServerInfo] = serverInfo()
	return result
}

// cacheable adds the hints a client may cache a result by.
func cacheable(result map[string]any) map[string]any {
	result[resultKeyTTL] = listResultTTL.Milliseconds()
	result[resultKeyCacheScope] = cacheScopePrivate
	return result
}

// handleDiscover answers server/discover: the revisions the endpoint
// speaks, its capabilities and who it is. A client of the stateless
// revision asks this instead of opening with initialize.
func (s *Server) handleDiscover(w http.ResponseWriter, req *jsonRPCRequest) {
	s.writeResult(w, req, cacheable(map[string]any{
		"supportedVersions": supportedProtocolVersions,
		"capabilities":      serverCapabilities(),
	}))
}

// handleSubscriptionsListen answers subscriptions/listen, the request a
// client opens a stream of change notifications with. The server sends
// none, and says so in its capabilities, so there is nothing to keep a
// connection open for: the subscription is acknowledged with an empty set
// of notifications and then ended in the way the specification gives a
// server for ending one on its own. Nothing is held per caller.
func (s *Server) handleSubscriptionsListen(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	subscription := map[string]any{metaKeySubscriptionID: req.ID}
	result := jsonRPCResultEnvelope(req.ID, finishResult(req, map[string]any{metaKey: subscription}))

	flusher, ok := unwrapFlusher(w)
	if !ok || !acceptsSSE(r) {
		writeJSON(w, http.StatusOK, result)
		return
	}

	h := w.Header()
	h.Set("Content-Type", mimeEventStream)
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	acknowledged := map[string]any{
		jsonRPCKey: jsonRPCVersion,
		"method":   "notifications/subscriptions/acknowledged",
		"params": map[string]any{
			metaKey:         map[string]any{metaKeySubscriptionID: req.ID},
			"notifications": map[string]any{},
		},
	}
	if err := writeSSEMessage(w, flusher, acknowledged); err != nil {
		return
	}
	_ = writeSSEMessage(w, flusher, result) // error is client-disconnect; nothing to do
}

// recordRequest counts one request of the MCP endpoint by method and by the
// revision it was served in.
func (s *Server) recordRequest(r *http.Request, req *jsonRPCRequest, era protocolEra, refused bool) {
	s.metrics.RecordMCPRequest(metricsMethod(req), metricsProtocol(r, era, refused))
}

// metricsMethod maps the method of a request to a closed set of label
// values: the caller chooses the method, and must not be able to create
// label values.
func metricsMethod(req *jsonRPCRequest) string {
	if req.ID == nil {
		return metrics.MCPMethodNotification
	}
	switch req.Method {
	case methodInitialize, methodPing, methodDiscover, methodToolsList, methodToolsCall, methodSubscriptionsListen:
		return req.Method
	}
	return metrics.MCPMethodOther
}

// metricsProtocol names the revision a request was served in: the revision
// of the stateless generation, or for the handshake generation the one the
// request's header names. A request of that generation without the header,
// which is every initialize, counts as "unspecified".
func metricsProtocol(r *http.Request, era protocolEra, refused bool) string {
	switch {
	case refused:
		return metrics.MCPProtocolRefused
	case era == eraStateless:
		return protocolVersion20260728
	}
	if header := r.Header.Get(headerProtocolVersion); handshakeProtocolVersions[header] {
		return header
	}
	return metrics.MCPProtocolUnspecified
}
