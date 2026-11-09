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
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// Names of the globals InstallTextCodecs defines, and of the properties the
// codec objects carry. They follow the WHATWG Encoding and HTML standards so
// the idioms scripts already know keep working.
const (
	jsIdentAtob        = "atob"
	jsIdentBtoa        = "btoa"
	jsIdentTextEncoder = "TextEncoder"
	jsIdentTextDecoder = "TextDecoder"
	jsIdentUint8Array  = "Uint8Array"

	codecPropEncoding  = "encoding"
	codecPropFatal     = "fatal"
	codecPropIgnoreBOM = "ignoreBOM"
	codecMethodEncode  = "encode"
	codecMethodDecode  = "decode"
	viewPropBuffer     = "buffer"
	viewPropByteOffset = "byteOffset"
	viewPropByteLength = "byteLength"

	// codecUTF8 is the only encoding the decoder speaks, and the label it
	// reports for itself.
	codecUTF8 = "utf-8"
)

// utf8Labels are the WHATWG labels that name UTF-8; TextDecoder accepts
// them case-insensitively and rejects every other label.
var utf8Labels = map[string]bool{
	"unicode-1-1-utf-8": true,
	"unicode11utf8":     true,
	"unicode20utf8":     true,
	codecUTF8:           true,
	"utf8":              true,
	"x-unicode20utf8":   true,
}

// typedArrayFromShim boxes a primitive string handed to %TypedArray%.from.
// The specification converts the source with ToObject; goja accepts only an
// object there and throws "Value is not an object" for a string, which
// breaks the usual way of turning atob's output into bytes,
// Uint8Array.from(atob(b64), c => c.charCodeAt(0)). Every typed array
// constructor shares the one `from`, so the shim sits on their common
// prototype.
const typedArrayFromShim = `(function () {
	var proto = Object.getPrototypeOf(Uint8Array);
	var from = proto.from;
	Object.defineProperty(proto, "from", {
		value: function (source, mapFn, thisArg) {
			if (typeof source === "string") {
				source = Object(source);
			}
			return from.call(this, source, mapFn, thisArg);
		},
		writable: true,
		configurable: true
	});
})();`

// InstallTextCodecs defines atob, btoa, TextEncoder and TextDecoder in the
// runtime — the standard web globals that goja does not provide on its own.
//
// Before they existed, a base64 payload (the content a GitHub file read
// returns, an attachment, an image block) had to be decoded with a
// hand-written alphabet table inside the script, and UTF-8 text in it was
// a second hand-written step. Scripts written against a browser or Node
// runtime reach for these four names and failed here.
//
// The implementations follow the WHATWG definitions as far as a sandbox
// needs them: atob is forgiving about whitespace and missing padding and
// throws on anything else; btoa throws on a character outside Latin-1;
// TextDecoder speaks UTF-8 only, with the `fatal` and `ignoreBOM` options.
// It also makes %TypedArray%.from accept a string, see typedArrayFromShim.
func InstallTextCodecs(rt *goja.Runtime) {
	_, _ = rt.RunString(typedArrayFromShim)

	_ = rt.Set(jsIdentAtob, func(call goja.FunctionCall) goja.Value {
		decoded, err := forgivingBase64Decode(call.Argument(0).String())
		if err != nil {
			panic(rt.NewGoError(fmt.Errorf("%s: %w", jsIdentAtob, err)))
		}
		return rt.ToValue(binaryString(decoded))
	})

	_ = rt.Set(jsIdentBtoa, func(call goja.FunctionCall) goja.Value {
		raw, err := binaryBytes(call.Argument(0).String())
		if err != nil {
			panic(rt.NewGoError(fmt.Errorf("%s: %w", jsIdentBtoa, err)))
		}
		return rt.ToValue(base64.StdEncoding.EncodeToString(raw))
	})

	_ = rt.Set(jsIdentTextEncoder, func(call goja.ConstructorCall) *goja.Object {
		_ = call.This.Set(codecPropEncoding, codecUTF8)
		_ = call.This.Set(codecMethodEncode, func(inner goja.FunctionCall) goja.Value {
			text := ""
			if arg := inner.Argument(0); !goja.IsUndefined(arg) {
				text = arg.String()
			}
			return newUint8Array(rt, []byte(text))
		})
		return nil
	})

	_ = rt.Set(jsIdentTextDecoder, func(call goja.ConstructorCall) *goja.Object {
		label := codecUTF8
		if arg := call.Argument(0); !goja.IsUndefined(arg) {
			label = strings.ToLower(strings.TrimSpace(arg.String()))
		}
		if !utf8Labels[label] {
			panic(rt.NewGoError(fmt.Errorf("%s: the encoding label %q is not supported; this sandbox decodes %s only",
				jsIdentTextDecoder, label, codecUTF8)))
		}
		fatal, ignoreBOM := false, false
		if opts, ok := call.Argument(1).(*goja.Object); ok {
			fatal = boolProp(opts, codecPropFatal)
			ignoreBOM = boolProp(opts, codecPropIgnoreBOM)
		}
		_ = call.This.Set(codecPropEncoding, codecUTF8)
		_ = call.This.Set(codecPropFatal, fatal)
		_ = call.This.Set(codecPropIgnoreBOM, ignoreBOM)
		_ = call.This.Set(codecMethodDecode, func(inner goja.FunctionCall) goja.Value {
			raw, err := bufferBytes(inner.Argument(0))
			if err != nil {
				panic(rt.NewGoError(fmt.Errorf("%s.%s: %w", jsIdentTextDecoder, codecMethodDecode, err)))
			}
			if !ignoreBOM {
				raw = strings.TrimPrefix(raw, "\xEF\xBB\xBF")
			}
			if !utf8.ValidString(raw) {
				if fatal {
					panic(rt.NewGoError(fmt.Errorf("%s.%s: the encoded data is not valid %s",
						jsIdentTextDecoder, codecMethodDecode, codecUTF8)))
				}
				raw = strings.ToValidUTF8(raw, "\xEF\xBF\xBD")
			}
			return rt.ToValue(raw)
		})
		return nil
	})
}

// boolProp reads an options property as a boolean; an absent property is
// false (Get returns nil for it, not undefined).
func boolProp(obj *goja.Object, name string) bool {
	v := obj.Get(name)
	return v != nil && v.ToBoolean()
}

// forgivingBase64Decode implements the forgiving-base64 decode the HTML
// standard specifies for atob: ASCII whitespace is dropped, padding may be
// left off, and anything else outside the alphabet is an error.
func forgivingBase64Decode(s string) ([]byte, error) {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\f', '\r':
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()
	if len(s)%4 == 0 {
		s = strings.TrimSuffix(strings.TrimSuffix(s, "="), "=")
	}
	if len(s)%4 == 1 {
		return nil, fmt.Errorf("the string to be decoded is not correctly encoded")
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '+' && r != '/' {
			return nil, fmt.Errorf("the string to be decoded is not correctly encoded")
		}
	}
	out, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the string to be decoded is not correctly encoded")
	}
	return out, nil
}

// binaryString renders bytes as the "binary string" atob returns: one
// character per byte, code points U+0000 through U+00FF.
func binaryString(raw []byte) string {
	runes := make([]rune, len(raw))
	for i, c := range raw {
		runes[i] = rune(c)
	}
	return string(runes)
}

// binaryBytes is the inverse of binaryString, for btoa: every character
// must be a code point below 256, or the string is not a byte sequence.
func binaryBytes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return nil, fmt.Errorf("the string to be encoded contains characters outside of the Latin1 range")
		}
		out = append(out, byte(r)) //nolint:gosec // r is at most 0xFF here, checked above
	}
	return out, nil
}

// newUint8Array wraps raw in a fresh Uint8Array, going through the
// runtime's own constructor so the result is a genuine typed array.
func newUint8Array(rt *goja.Runtime, raw []byte) goja.Value {
	ctor := rt.Get(jsIdentUint8Array)
	arr, err := rt.New(ctor, rt.ToValue(rt.NewArrayBuffer(raw)))
	if err != nil {
		panic(rt.NewGoError(fmt.Errorf("%s: %w", jsIdentUint8Array, err)))
	}
	return arr
}

// bufferBytes reads the bytes behind a TextDecoder.decode argument: an
// ArrayBuffer, or any view onto one (a typed array or a DataView), honoring
// the view's offset and length. undefined decodes as the empty string.
func bufferBytes(v goja.Value) (string, error) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return "", nil
	}
	obj, ok := v.(*goja.Object)
	if !ok {
		return "", fmt.Errorf("the argument must be an ArrayBuffer or an ArrayBuffer view")
	}
	// An ArrayBuffer is the buffer; a view carries its buffer as a property.
	if whole, ok := obj.Export().(goja.ArrayBuffer); ok {
		return string(whole.Bytes()), nil
	}
	bufVal := obj.Get(viewPropBuffer)
	if bufVal == nil {
		return "", fmt.Errorf("the argument must be an ArrayBuffer or an ArrayBuffer view")
	}
	buf, ok := bufVal.Export().(goja.ArrayBuffer)
	if !ok {
		return "", fmt.Errorf("the argument must be an ArrayBuffer or an ArrayBuffer view")
	}
	raw := buf.Bytes()
	offset := int(obj.Get(viewPropByteOffset).ToInteger())
	length := int(obj.Get(viewPropByteLength).ToInteger())
	if offset < 0 || length < 0 || offset+length > len(raw) {
		return "", fmt.Errorf("the view does not fit its buffer")
	}
	return string(raw[offset : offset+length]), nil
}
