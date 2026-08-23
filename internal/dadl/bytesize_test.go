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
	"strings"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
	}{
		{name: "bare byte count", in: "1048576", want: 1048576},
		{name: "explicit bytes", in: "512B", want: 512},
		{name: "megabytes", in: testSize50MB, want: 50 * 1024 * 1024},
		{name: "kilobytes", in: "10KB", want: 10 * 1024},
		{name: "gigabytes", in: "2GB", want: 2 * 1024 * 1024 * 1024},
		{name: "IEC spelling matches the decimal one", in: "128 KiB", want: 128 * 1024},
		{name: "lower case unit", in: "50mb", want: 50 * 1024 * 1024},
		{name: "space before unit", in: "50 MB", want: 50 * 1024 * 1024},
		{name: "surrounding whitespace", in: "  50MB  ", want: 50 * 1024 * 1024},
		{name: "fractional value", in: "1.5MB", want: 1024 * 1024 * 3 / 2},
		{name: "short unit", in: "5M", want: 5 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseByteSize(tt.in)
			if err != nil {
				t.Fatalf("ParseByteSize(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseByteSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseByteSize_Rejects covers the values that must not resolve to a
// limit. Every one of them would otherwise degrade to a wider cap than the
// author wrote, which is the failure max_body_size exists to prevent.
func TestParseByteSize_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{name: "empty", in: "", wantErr: "empty size"},
		{name: "whitespace only", in: "   ", wantErr: "empty size"},
		{name: "unit only", in: "MB", wantErr: "invalid size"},
		{name: "unknown unit", in: "50TB", wantErr: testErrUnknownUnit},
		{name: "trailing garbage", in: "50MB!", wantErr: testErrUnknownUnit},
		{name: "negative", in: "-5MB", wantErr: testErrUnknownUnit},
		{name: "zero", in: "0", wantErr: "greater than zero"},
		{name: "zero megabytes", in: "0MB", wantErr: "greater than zero"},
		{name: "not a number", in: "banana", wantErr: testErrUnknownUnit},
		{name: "two dots", in: "1.2.3MB", wantErr: "invalid size"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseByteSize(tt.in)
			if err == nil {
				t.Fatalf("ParseByteSize(%q) = %d, want an error", tt.in, got)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseByteSize(%q) error = %v, want containing %q", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestFormatByteSize(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{in: 512, want: "512 bytes"},
		{in: 10 * 1024, want: "10KB"},
		{in: 50 * 1024 * 1024, want: "50MB"},
		{in: 2 * 1024 * 1024 * 1024, want: "2GB"},
		{in: 100*1024*1024 + 1, want: "104857601 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := FormatByteSize(tt.in); got != tt.want {
				t.Errorf("FormatByteSize(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestByteSizeRoundTrip pins the two halves against each other: whatever
// FormatByteSize prints must read back as the same number, so a limit quoted
// in an error message can be pasted into a DADL unchanged.
func TestByteSizeRoundTrip(t *testing.T) {
	for _, n := range []int64{512, 10 * 1024, 50 * 1024 * 1024, 100 * 1024 * 1024, 2 * 1024 * 1024 * 1024} {
		formatted := FormatByteSize(n)
		got, err := ParseByteSize(strings.TrimSuffix(formatted, " bytes"))
		if err != nil {
			t.Fatalf("ParseByteSize(%q) unexpected error: %v", formatted, err)
		}
		if got != n {
			t.Errorf("round trip of %d via %q = %d", n, formatted, got)
		}
	}
}

// TestParseBytes_MaxBodySizeIsKnown guards against the field regressing to an
// unknown key: 42 tools across the shipped DADL corpus declare max_body_size,
// and every one of them warned on every load before it was implemented.
func TestParseBytes_MaxBodySizeIsKnown(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    upload:
      method: POST
      path: /upload
      max_body_size: 50MB
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", spec.Warnings)
	}
	if got := spec.Backend.Tools["upload"].MaxBodySize; got != testSize50MB {
		t.Errorf("MaxBodySize = %q, want %q", got, testSize50MB)
	}
}
