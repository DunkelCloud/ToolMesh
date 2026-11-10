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

package composite

import (
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// testHello is the decoded form of the base64 fixtures.
const testHello = "hello"

// codecRuntime is a locked-down runtime with the text codecs installed, as
// every execution sandbox builds it.
func codecRuntime(t *testing.T) *goja.Runtime {
	t.Helper()
	rt := goja.New()
	LockdownRuntime(rt)
	InstallTextCodecs(rt)
	return rt
}

// runString evaluates script and returns the exported result, failing the
// test on a thrown error.
func runString(t *testing.T, rt *goja.Runtime, script string) any {
	t.Helper()
	v, err := rt.RunString(script)
	if err != nil {
		t.Fatalf("%s: %v", script, err)
	}
	return v.Export()
}

// mustThrow evaluates script and returns the thrown error's message, failing
// the test when the script does not throw.
func mustThrow(t *testing.T, rt *goja.Runtime, script string) string {
	t.Helper()
	_, err := rt.RunString(script)
	if err == nil {
		t.Fatalf("%s: expected an error", script)
	}
	return err.Error()
}

func TestTextCodecs_Base64(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   any
	}{
		{"btoa encodes ASCII", `btoa("hello")`, "aGVsbG8="},
		{"btoa encodes Latin-1 bytes", `btoa("é")`, "6Q=="},
		{"atob decodes", `atob("aGVsbG8=")`, testHello},
		{"atob yields one char per byte", `atob("6Q==").charCodeAt(0)`, int64(0xE9)},
		{"atob tolerates whitespace", "atob(\"aGVs\\n bG8=\\r\\n\")", testHello},
		{"atob tolerates missing padding", `atob("aGVsbG8")`, testHello},
		{"atob of empty string", `atob("")`, ""},
		{"round trip", `btoa(atob("AAEC/w=="))`, "AAEC/w=="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runString(t, codecRuntime(t), tt.script); got != tt.want {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestTextCodecs_Base64Errors(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{"btoa rejects a character above Latin-1", `btoa("€")`, "outside of the Latin1 range"},
		{"atob rejects a character outside the alphabet", `atob("aGVs*G8=")`, "not correctly encoded"},
		{"atob rejects a length that cannot be base64", `atob("aGVsb")`, "not correctly encoded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustThrow(t, codecRuntime(t), tt.script); !strings.Contains(got, tt.want) {
				t.Errorf("error %q does not mention %q", got, tt.want)
			}
		})
	}
}

func TestTextCodecs_EncoderDecoder(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   any
	}{
		{"encoder reports utf-8", `new TextEncoder().encoding`, codecUTF8},
		{"encoder yields UTF-8 bytes", `Array.from(new TextEncoder().encode("é")).join(",")`, "195,169"},
		{"encoder yields a Uint8Array", `new TextEncoder().encode("ab") instanceof Uint8Array`, true},
		{"encoder of undefined is empty", `new TextEncoder().encode().length`, int64(0)},
		{"decoder reports utf-8", `new TextDecoder().encoding`, codecUTF8},
		{"decoder accepts the utf8 label", `new TextDecoder("UTF8").encoding`, codecUTF8},
		{"decoder reads a Uint8Array", `new TextDecoder().decode(new Uint8Array([195, 169]))`, "é"},
		{"decoder reads an ArrayBuffer", `new TextDecoder().decode(new Uint8Array([104, 105]).buffer)`, "hi"},
		{"decoder honors a view's offset", `new TextDecoder().decode(new Uint8Array([120, 104, 105]).subarray(1))`, "hi"},
		{"decoder of undefined is empty", `new TextDecoder().decode()`, ""},
		{"decoder strips the BOM", `new TextDecoder().decode(new Uint8Array([0xEF, 0xBB, 0xBF, 104, 105]))`, "hi"},
		{"decoder keeps the BOM when asked", `new TextDecoder("utf-8", {ignoreBOM: true}).decode(new Uint8Array([0xEF, 0xBB, 0xBF, 104, 105])).length`, int64(3)},
		{"decoder replaces invalid bytes by default", `new TextDecoder().decode(new Uint8Array([104, 0xFF, 105]))`, "h�i"},
		{"round trip", `new TextDecoder().decode(new TextEncoder().encode("grüß Gott €"))`, "grüß Gott €"},
		// The idiom a script reaches for when an API hands it base64 of
		// UTF-8 text, as GitHub's content endpoint does.
		{"base64 of UTF-8 text decodes with the usual idiom",
			`new TextDecoder().decode(Uint8Array.from(atob("Z3LDvMOfIEdvdHQ="), c => c.charCodeAt(0)))`, "grüß Gott"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runString(t, codecRuntime(t), tt.script); got != tt.want {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestTextCodecs_DecoderErrors(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{"unknown label", `new TextDecoder("latin1")`, "not supported"},
		{"fatal mode rejects invalid bytes", `new TextDecoder("utf-8", {fatal: true}).decode(new Uint8Array([0xFF]))`, "not valid utf-8"},
		{"non-buffer input", `new TextDecoder().decode("text")`, "ArrayBuffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustThrow(t, codecRuntime(t), tt.script); !strings.Contains(got, tt.want) {
				t.Errorf("error %q does not mention %q", got, tt.want)
			}
		})
	}
}

// TestTextCodecs_Catchable makes sure a codec error is an ordinary thrown
// value a script can handle, not a runtime abort.
func TestTextCodecs_Catchable(t *testing.T) {
	got := runString(t, codecRuntime(t), `(function(){ try { atob("*"); return "no error"; } catch (e) { return "caught"; } })()`)
	if got != "caught" {
		t.Errorf("got %v, want caught", got)
	}
}
