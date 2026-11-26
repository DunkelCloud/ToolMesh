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
	"net/url"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/urlredact"
)

// redactTransportError converts a *url.Error returned by an HTTP client into
// an error that names only scheme and host (see urlredact.TransportError).
func redactTransportError(err error) error {
	return urlredact.TransportError(err)
}

// loggableEndpoint returns the configured URL of a backend for a log line:
// without its query string and fragment and without a password, each of
// which can hold a credential ("https://mcp.example.com/sse?api_key=...").
// A URL that does not parse is reduced to scheme and host.
func loggableEndpoint(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return urlredact.Origin(raw)
	}
	u.RawQuery, u.ForceQuery, u.Fragment = "", false, ""
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}

// maxLoggedErrorLen bounds the text of an error in a log line of the MCP
// adapter. The text can come from a backend, which chooses its length.
const maxLoggedErrorLen = 1000

// loggableError returns the text of an error for a log line, with every
// http(s) URL in it reduced to scheme, host and path, and cut off after
// maxLoggedErrorLen bytes. An error about a connection names the URL that
// was asked, and the URL of a backend can carry a credential in its query
// string or its userinfo.
func loggableError(err error) string {
	if err == nil {
		return ""
	}
	text := urlredact.Text(urlredact.URLErrors(err).Error())
	if len(text) > maxLoggedErrorLen {
		text = strings.ToValidUTF8(text[:maxLoggedErrorLen], "") + "..."
	}
	return text
}

// RedactURLErrors returns an error equivalent to err whose message shows the
// URL of every *url.Error in its chain reduced to scheme://host (see
// urlredact.URLErrors).
func RedactURLErrors(err error) error {
	return urlredact.URLErrors(err)
}
