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

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// UploadConfig makes a tool a resumable upload (ToolDef.Upload). It is a
// ToolMesh extension: DADL spec v0.2 does not define the key.
//
// The tool's request opens an upload session. Its file_url parameter is
// the file; its other body parameters are the metadata sent with the
// session request. ToolMesh then sends the file in chunks, asks the API
// how far it got after an interruption and continues from there, and
// returns the API's final response like the response of any other tool.
type UploadConfig struct {
	// Protocol names the upload protocol. UploadProtocolGoogleResumable is
	// the only one.
	Protocol string `yaml:"protocol"`
}

// UploadProtocolGoogleResumable is Google's resumable upload protocol, as
// spoken by the YouTube Data API, Drive and the Cloud Storage JSON API: a
// session request with uploadType=resumable whose Location header is the
// session URI, PUT requests with Content-Range for the chunks, 308 with a
// Range header while the file is incomplete, and a PUT with
// "Content-Range: bytes */<size>" to ask how much the API has stored.
const UploadProtocolGoogleResumable = "google_resumable"

// FeatureResumableUpload is the requires.features identifier a file must
// list when one of its tools declares upload. A runtime without the
// feature then refuses the file instead of ignoring the key and sending
// the file as an ordinary request body.
const FeatureResumableUpload = "resumable_upload"

// uploadReservedParams are the query parameters the google_resumable
// protocol sets itself. A parameter of the same name would interfere with
// the session request or the session URI.
var uploadReservedParams = []string{"uploadType", "upload_id"}

// validateUpload checks the upload block of a tool. The block needs
// exactly one file_url parameter (the file), a method that can carry the
// session request, and none of the keys whose handling the upload path
// replaces: the response arrives after the last chunk and is processed as
// JSON, the session request is repeated only while it has created nothing,
// and a single upload has no pages.
func validateUpload(name string, tool *ToolDef) error {
	up := tool.Upload
	if up == nil {
		return nil
	}
	// protocol is a behavior-determining enum (spec §15.3).
	if up.Protocol != UploadProtocolGoogleResumable {
		return fmt.Errorf("tool %q: upload.protocol must be %q, got %q", name, UploadProtocolGoogleResumable, up.Protocol)
	}
	switch strings.ToUpper(tool.Method) {
	case httpMethodPOST, httpMethodPUT, httpMethodPATCH:
	default:
		return fmt.Errorf("tool %q: upload needs method POST, PUT or PATCH for the session request, got %s", name, tool.Method)
	}
	files := 0
	for pname, p := range tool.Params {
		if p.Type == ParamTypeFileURL {
			files++
		}
		if slices.Contains(uploadReservedParams, pname) {
			return fmt.Errorf("tool %q: parameter %q is set by the upload protocol and cannot be declared", name, pname)
		}
	}
	if files != 1 {
		return fmt.Errorf("tool %q: upload needs exactly one file_url parameter (the file), found %d", name, files)
	}
	if tool.ContentType == ContentTypeMultipartForm {
		return fmt.Errorf("tool %q: upload cannot be combined with content_type %s; content_type names the media type of the file", name, ContentTypeMultipartForm)
	}
	if i := strings.IndexByte(tool.Path, '?'); i >= 0 {
		q, err := url.ParseQuery(tool.Path[i+1:])
		if err != nil {
			return fmt.Errorf("tool %q: path query: %w", name, err)
		}
		for _, reserved := range uploadReservedParams {
			if q.Has(reserved) {
				return fmt.Errorf("tool %q: the path query names %q, which the upload protocol sets itself", name, reserved)
			}
		}
	}
	if rc := tool.Response; rc != nil && (rc.IsFileURL() || rc.Binary || rc.Streaming) {
		return fmt.Errorf("tool %q: upload cannot be combined with a file_url, binary or streaming response", name)
	}
	if len(tool.NotReadyOn) > 0 {
		return fmt.Errorf("tool %q: upload cannot be combined with not_ready_on", name)
	}
	if tool.Idempotency != nil {
		return fmt.Errorf("tool %q: upload cannot be combined with idempotency; the upload session already keeps a repeated call from creating a second resource", name)
	}
	if tool.Pagination != nil {
		if s, ok := tool.Pagination.(string); !ok || s != "none" {
			return fmt.Errorf("tool %q: upload cannot be combined with pagination", name)
		}
	}
	return nil
}

// validateUploadFeature refuses a file that declares upload on a tool but
// does not list FeatureResumableUpload in requires.features. Without the
// entry a runtime that does not know the key would ignore it and send the
// file as the body of the session request; the key is new, so insisting
// on the entry costs nobody a working file.
func validateUploadFeature(spec *Spec) error {
	if spec.Requires != nil && slices.Contains(spec.Requires.Features, FeatureResumableUpload) {
		return nil
	}
	names := make([]string, 0)
	for name, tool := range spec.Backend.Tools {
		if tool.Upload != nil {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	return fmt.Errorf("tool %q declares upload, so requires.features must list %q", names[0], FeatureResumableUpload)
}
