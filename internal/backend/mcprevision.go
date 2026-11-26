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
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// An MCP server speaks one of two generations of the protocol. Up to
// revision 2025-11-25 a connection opens with an initialize handshake; from
// revision 2026-07-28 there is none, a client asks server/discover and every
// request stands on its own. The adapter talks to servers of both: it asks
// in the newer way first and falls back to the handshake.
const (
	// mcpRevisionHandshake is the newest revision that opens with
	// initialize, the one the adapter asks for when it falls back.
	mcpRevisionHandshake = "2025-11-25"
	// mcpRevisionStateless is the first revision without the handshake.
	mcpRevisionStateless = "2026-07-28"

	// mcpProbeTimeout bounds the attempt in the newer way. A server of the
	// older generation normally answers the unknown request with an error
	// at once; this is for the one that says nothing.
	mcpProbeTimeout = 10 * time.Second
	// mcpHandshakeTimeout bounds the initialize handshake, as it always did.
	mcpHandshakeTimeout = 15 * time.Second
)

// Requests a server may send to its client. ToolMesh answers none of them:
// it announces no roots, no sampling and no elicitation.
const (
	mcpMethodSampling    = "sampling/createMessage"
	mcpMethodRoots       = "roots/list"
	mcpMethodElicitation = "elicitation/create"
)

// mcpFeatureSSETransport names, in the log, the transport that revision
// 2026-07-28 deprecates.
const mcpFeatureSSETransport = "http+sse transport"

// schemaKeyHeaderAnnotation is the keyword an MCP server marks a tool
// parameter with that its client is to repeat in an HTTP header.
const schemaKeyHeaderAnnotation = "x-mcp-header"

// maxSchemaDepth bounds how deep stripHeaderAnnotations follows a schema a
// backend sent.
const maxSchemaDepth = 64

// usesSSETransport reports whether a backend is reached over the HTTP+SSE
// transport of revision 2024-11-05, which the adapter picks for a url that
// ends in /sse. No server of the stateless revision speaks it.
func usesSSETransport(entry BackendEntry) bool {
	return entry.Transport == transportTypeHTTP && strings.HasSuffix(entry.URL, "/sse")
}

// newClient builds the MCP client for the connection to one backend.
func (a *MCPAdapter) newClient(backendName string) *mcp.Client {
	client := mcp.NewClient(&mcp.Implementation{Name: "toolmesh", Version: "0.1.0"}, &mcp.ClientOptions{
		// Nothing a server could ask its client for is on offer. The empty
		// set is given explicitly: without it the SDK announces roots.
		Capabilities: &mcp.ClientCapabilities{},
		// A result that asks the client for input is answered in Execute,
		// with an error for the caller, instead of the SDK trying to supply
		// the input and repeating the call.
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		// A backend that says its tool list has changed has the list read
		// again. With the handler set, the SDK also asks a server of the
		// stateless revision for these notifications, which such a server
		// sends to a client that subscribed only.
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			a.toolListChanged(backendName)
		},
	})
	client.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case mcpMethodSampling, mcpMethodRoots, mcpMethodElicitation:
				a.flagClientRequest(backendName, method)
			}
			return next(ctx, method, req)
		}
	})
	return client
}

// openSession connects to a backend and settles the protocol revision with
// it. It returns the session and the function that releases what the session
// holds, to be called once the session has ended. The caller holds conn.op.
//
// The SDK asks in the way of the stateless revision first and falls back to
// initialize when the server answers that with an error. Over HTTP that is
// all there is to it: every request is a connection of its own.
//
// A child process is one connection for its whole life, and a server of the
// older generation may say nothing to a request before initialize, or end
// on it. For a stdio backend the handshake is therefore tried again with a
// process of its own when the first attempt fails. A backend that needed
// that is remembered, so that a reconnect goes straight to the handshake;
// the memory is dropped when the handshake fails, and the next connect asks
// anew.
func (a *MCPAdapter) openSession(ctx context.Context, name string, conn *backendConn) (*mcp.ClientSession, context.CancelFunc, error) {
	client := a.newClient(name)

	if conn.entry.Transport != transportTypeSTDIO {
		var opts *mcp.ClientSessionOptions
		if usesSSETransport(conn.entry) {
			// The transport of 2024-11-05: there is nothing newer to ask for.
			opts = &mcp.ClientSessionOptions{ProtocolVersion: mcpRevisionHandshake}
		}
		session, release, err := a.connectOnce(ctx, client, conn.entry, a.currentPace().handshake, opts)
		if err != nil {
			return nil, nil, connectError(name, err)
		}
		return session, release, nil
	}

	var probeErr error
	if !conn.handshakeOnly {
		probeTimeout := mcpProbeTimeout
		if a.probeTimeout > 0 {
			probeTimeout = a.probeTimeout
		}
		session, release, err := a.connectOnce(ctx, client, conn.entry, probeTimeout, nil)
		if err == nil {
			return session, release, nil
		}
		var setup *transportSetupError
		if errors.As(err, &setup) || ctx.Err() != nil {
			return nil, nil, connectError(name, err)
		}
		probeErr = err
		a.logger.Debug("backend did not answer without the initialize handshake, trying the handshake on a new connection",
			"name", name, "error", loggableError(err))
	}

	session, release, err := a.connectOnce(ctx, client, conn.entry, a.currentPace().handshake, &mcp.ClientSessionOptions{ProtocolVersion: mcpRevisionHandshake})
	if err != nil {
		var setup *transportSetupError
		if errors.As(err, &setup) {
			return nil, nil, err
		}
		conn.handshakeOnly = false
		if probeErr != nil {
			return nil, nil, fmt.Errorf("connect to %s: %w (without the initialize handshake: %v)", name, err, probeErr) //nolint:errorlint // one error is the cause, the other is told
		}
		return nil, nil, connectError(name, err)
	}
	conn.handshakeOnly = probeErr != nil || conn.handshakeOnly
	return session, release, nil
}

// connectError names the backend in the error of a failed connect. An error
// about the transport itself says what it is about already.
func connectError(name string, err error) error {
	var setup *transportSetupError
	if errors.As(err, &setup) {
		return err
	}
	return fmt.Errorf("connect to %s: %w", name, err)
}

// sessionRevision returns the protocol revision a session runs in.
func sessionRevision(session *mcp.ClientSession) string {
	if res := session.InitializeResult(); res != nil {
		return res.ProtocolVersion
	}
	return ""
}

// flagDeprecated reports, once per backend, that a connected backend is
// reached over the transport revision 2026-07-28 deprecates. It keeps
// working until a later revision removes it; the line tells the operator
// which backends that will concern.
//
// A backend is not reported for announcing the logging capability, which
// the revision deprecates as well: servers built with an SDK announce it
// whether they log or not, so the line would name nearly every backend.
func (a *MCPAdapter) flagDeprecated(name string, entry BackendEntry) {
	if usesSSETransport(entry) && a.flagOnce(name, mcpFeatureSSETransport) {
		a.logger.Warn("backend uses a part of MCP that revision 2026-07-28 deprecates; it works until a later revision removes it",
			"name", name, "feature", mcpFeatureSSETransport)
	}
}

// flagClientRequest reports, once per backend and method, that a backend
// asked its client for something. ToolMesh announces none of these
// features, so the request is refused; the line is there because roots and
// sampling are deprecated as of revision 2026-07-28, and a backend that
// relies on one of them has to change.
func (a *MCPAdapter) flagClientRequest(name, method string) {
	if a.flagOnce(name, method) {
		a.logger.Warn("backend asked its client for input, which ToolMesh does not provide; the request was refused",
			"name", name, "method", method)
	}
}

// flagOnce reports whether this is the first time key is flagged for a
// backend.
func (a *MCPAdapter) flagOnce(name, key string) bool {
	a.flagMu.Lock()
	defer a.flagMu.Unlock()
	if a.flagged == nil {
		a.flagged = make(map[string]struct{})
	}
	id := name + "\x00" + key
	if _, seen := a.flagged[id]; seen {
		return false
	}
	a.flagged[id] = struct{}{}
	return true
}

// inputRequiredResult turns a result with which a backend asks its client
// for input into an error for the caller. In revision 2026-07-28 a server
// no longer sends such a request on its own; it answers the call with it
// and expects the call again, with the input. ToolMesh has no input to
// give, so the call ends here.
func (a *MCPAdapter) inputRequiredResult(backendName, tool string, result *mcp.CallToolResult) *ToolResult {
	seen := make(map[string]struct{}, len(result.InputRequests))
	for _, request := range result.InputRequests {
		//nolint:staticcheck // SA1019: the deprecated features are what is looked for here
		switch request.(type) {
		case *mcp.ElicitParams:
			seen[mcpMethodElicitation] = struct{}{}
		case *mcp.CreateMessageParams, *mcp.CreateMessageWithToolsParams:
			seen[mcpMethodSampling] = struct{}{}
		case *mcp.ListRootsParams:
			seen[mcpMethodRoots] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return errorToolResult(fmt.Errorf("backend %q did not complete %q and asked for the call to be sent again", backendName, tool))
	}
	methods := make([]string, 0, len(seen))
	for method := range seen {
		methods = append(methods, method)
		a.flagClientRequest(backendName, method)
	}
	sort.Strings(methods)
	return errorToolResult(fmt.Errorf("backend %q did not complete %q: it asks the client for input (%s), which ToolMesh does not provide",
		backendName, tool, strings.Join(methods, ", ")))
}

// stripHeaderAnnotations removes the x-mcp-header keyword from an input
// schema a backend sent, in place. The keyword tells the client of that
// backend, which is ToolMesh, to repeat a parameter in an HTTP header of
// its request to the backend; the SDK does that from its own copy of the
// schema. A caller of ToolMesh must not see it: it would then owe ToolMesh
// such headers, for a hop the keyword was never about.
//
// Only the keyword of a schema is removed, never a property that happens to
// have its name.
func stripHeaderAnnotations(schema map[string]any) {
	stripHeaderAnnotationsAt(schema, 0)
}

func stripHeaderAnnotationsAt(schema map[string]any, depth int) {
	if schema == nil || depth > maxSchemaDepth {
		return
	}
	delete(schema, schemaKeyHeaderAnnotation)

	// Keywords whose value is a map from a name to a schema.
	for _, key := range []string{schemaKeyProperties, "patternProperties", "$defs", "definitions", "dependentSchemas"} {
		if named, ok := schema[key].(map[string]any); ok {
			for _, sub := range named {
				if subSchema, ok := sub.(map[string]any); ok {
					stripHeaderAnnotationsAt(subSchema, depth+1)
				}
			}
		}
	}
	// Keywords whose value is a schema.
	for _, key := range []string{"items", schemaKeyAdditionalProperties, "not", "if", "then", "else", "contains", "propertyNames", "unevaluatedItems", "unevaluatedProperties"} {
		if subSchema, ok := schema[key].(map[string]any); ok {
			stripHeaderAnnotationsAt(subSchema, depth+1)
		}
	}
	// Keywords whose value is a list of schemas.
	for _, key := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		if list, ok := schema[key].([]any); ok {
			for _, sub := range list {
				if subSchema, ok := sub.(map[string]any); ok {
					stripHeaderAnnotationsAt(subSchema, depth+1)
				}
			}
		}
	}
}
