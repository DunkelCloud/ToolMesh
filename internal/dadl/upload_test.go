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
	"strings"
	"testing"
)

// uploadSpec is the fixture of the upload validation tests. The first %s is
// the requires block, the second the tool's method, the third the tool's
// path, the fourth extra tool lines, the fifth extra params.
const uploadSpec = `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
%s
backend:
  name: tube
  type: rest
  base_url: https://upload.example.com
  tools:
    upload_video:
      method: %s
      path: %s
      upload:
        protocol: google_resumable
      %s
      params:
        snippet:
          type: object
          in: body
        file:
          type: file_url
          in: body
          required: true
%s
`

const (
	uploadRequires = "requires:\n  features: [resumable_upload]"
	uploadPath     = "/upload/videos"
)

func buildUploadSpec(requires, method, path, toolExtra, paramExtra string) []byte {
	return []byte(fmt.Sprintf(uploadSpec, requires, method, path, toolExtra, paramExtra))
}

func TestParseBytes_Upload(t *testing.T) {
	t.Run("loads with the feature listed and without warnings", func(t *testing.T) {
		spec, err := ParseBytes(buildUploadSpec(uploadRequires, httpMethodPOST, uploadPath, "", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(spec.Warnings) != 0 {
			t.Errorf("upload is implemented and must not warn, got: %v", spec.Warnings)
		}
		up := spec.Backend.Tools["upload_video"].Upload
		if up == nil || up.Protocol != UploadProtocolGoogleResumable {
			t.Fatalf("upload = %+v, want protocol %q", up, UploadProtocolGoogleResumable)
		}
	})

	rejected := []struct {
		name                                         string
		requires, method, path, toolExtra, paramXtra string
		protocol                                     string // replaces google_resumable when set
		want                                         string
	}{
		{name: "feature not listed", method: httpMethodPOST, path: uploadPath,
			want: "requires.features must list"},
		{name: "unknown protocol", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			protocol: "tus", want: "upload.protocol must be"},
		{name: "GET cannot carry the session request", requires: uploadRequires, method: httpMethodGET, path: uploadPath,
			want: "method POST, PUT or PATCH"},
		{name: "second file", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			paramXtra: "        thumb:\n          type: file_url\n          in: body",
			want:      "exactly one file_url parameter"},
		{name: "multipart", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			toolExtra: "content_type: multipart/form-data",
			want:      "multipart/form-data"},
		{name: "reserved parameter", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			paramXtra: "        uploadType:\n          type: string\n          in: query",
			want:      "set by the upload protocol"},
		{name: "reserved path query", requires: uploadRequires, method: httpMethodPOST, path: uploadPath + "?upload_id=x",
			want: "sets itself"},
		{name: "binary response", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			toolExtra: "response:\n        binary: true",
			want:      "binary or streaming response"},
		{name: "with an idempotency key", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			toolExtra: "idempotency:\n        header: Idempotency-Key",
			want:      "combined with idempotency"},
		{name: "with pages", requires: uploadRequires, method: httpMethodPOST, path: uploadPath,
			toolExtra: "pagination:\n        strategy: page",
			want:      "combined with pagination"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			data := buildUploadSpec(tc.requires, tc.method, tc.path, tc.toolExtra, tc.paramXtra)
			if tc.protocol != "" {
				data = []byte(strings.Replace(string(data), UploadProtocolGoogleResumable, tc.protocol, 1))
			}
			_, err := ParseBytes(data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}

	t.Run("a plain raw-body tool still takes its file alone", func(t *testing.T) {
		data := buildUploadSpec(uploadRequires, httpMethodPOST, uploadPath, "", "")
		data = []byte(strings.Replace(string(data), "      upload:\n        protocol: google_resumable\n", "", 1))
		_, err := ParseBytes(data)
		if err == nil || !strings.Contains(err.Error(), "must be the only body parameter") {
			t.Fatalf("error = %v, want the raw-body rule", err)
		}
	})
}

// The runtime implements the feature, so a file that requires it loads.
func TestCheckRequires_ResumableUpload(t *testing.T) {
	spec := &Spec{Requires: &RequiresConfig{Features: []string{FeatureResumableUpload}}}
	if err := checkRequires(spec, "dev"); err != nil {
		t.Fatalf("checkRequires: %v", err)
	}
}
