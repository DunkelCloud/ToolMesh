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

import "github.com/DunkelCloud/ToolMesh/internal/urlredact"

// redactTransportError converts a *url.Error returned by an HTTP client into
// an error that names only scheme and host (see urlredact.TransportError).
func redactTransportError(err error) error {
	return urlredact.TransportError(err)
}

// RedactURLErrors returns an error equivalent to err whose message shows the
// URL of every *url.Error in its chain reduced to scheme://host (see
// urlredact.URLErrors).
func RedactURLErrors(err error) error {
	return urlredact.URLErrors(err)
}
