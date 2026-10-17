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

package grants

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/bip322"
	"github.com/dop251/goja"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck,gosec // reference for the page's RIPEMD-160
)

// The BIP-322 1.0 test vector key and its address, and the signatures it
// makes of the empty message and of "Hello World" without grinding for a
// low R (bip-0322/basic-test-vectors.json).
const (
	vecWIF      = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k" //nolint:gosec // published test vector key, holds nothing
	vecAddress  = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
	vecSigEmpty = "smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
	vecSigHello = "smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
)

// jsSigner runs the page's bip322.js in a JavaScript engine.
type jsSigner struct {
	t  *testing.T
	vm *goja.Runtime
}

func newJSSigner(t *testing.T) *jsSigner {
	t.Helper()
	src, err := webFiles.ReadFile("web/bip322.js")
	if err != nil {
		t.Fatal(err)
	}
	vm := goja.New()
	if _, err := vm.RunScript("bip322.js", string(src)); err != nil {
		t.Fatalf("load bip322.js: %v", err)
	}
	return &jsSigner{t: t, vm: vm}
}

// eval runs an expression with the library bound to B and returns its value
// as a string.
func (j *jsSigner) eval(expr string) string {
	j.t.Helper()
	v, err := j.vm.RunString("(function (B) { return " + expr + "; })(ToolMeshBIP322)")
	if err != nil {
		j.t.Fatalf("%s: %v", expr, err)
	}
	return v.String()
}

// sign signs message with the key (WIF or hex) in JavaScript.
func (j *jsSigner) sign(key, message string) string {
	j.t.Helper()
	return j.eval(fmt.Sprintf("B.signMessage(B.parsePrivateKey(%q), %q)", key, message))
}

// address returns the bc1q address of the key (WIF or hex) in JavaScript.
func (j *jsSigner) address(key, hrp string) string {
	j.t.Helper()
	return j.eval(fmt.Sprintf("B.addressOf(B.publicKey(B.parsePrivateKey(%q)), %q)", key, hrp))
}

func TestBIP322JS_HashesMatchGo(t *testing.T) {
	js := newJSSigner(t)
	for _, n := range []int{0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 128, 1000} {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		h := hex.EncodeToString(b)
		sum := sha256.Sum256(b)
		if got := js.eval(fmt.Sprintf("B.toHex(B.sha256(B.fromHex(%q)))", h)); got != hex.EncodeToString(sum[:]) {
			t.Errorf("sha256 of %d bytes = %s, want %x", n, got, sum)
		}
		r := ripemd160.New() //nolint:gosec // reference for the page's RIPEMD-160
		r.Write(b)
		if got := js.eval(fmt.Sprintf("B.toHex(B.ripemd160(B.fromHex(%q)))", h)); got != hex.EncodeToString(r.Sum(nil)) {
			t.Errorf("ripemd160 of %d bytes = %s, want %x", n, got, r.Sum(nil))
		}
		key := b[:min(n, 100)]
		mac := hmac.New(sha256.New, key)
		mac.Write(b)
		if got := js.eval(fmt.Sprintf("B.toHex(B.hmacSha256(B.fromHex(%q), B.fromHex(%q)))", hex.EncodeToString(key), h)); got != hex.EncodeToString(mac.Sum(nil)) {
			t.Errorf("hmac-sha256 of %d bytes = %s, want %x", n, got, mac.Sum(nil))
		}
	}
	text := "UTF-8 support: öäüéàè 测试文本 \U0001F604"
	if got := js.eval(fmt.Sprintf("B.toHex(B.utf8(%q))", text)); got != hex.EncodeToString([]byte(text)) {
		t.Errorf("utf8 = %s, want %x", got, text)
	}
}

func TestBIP322JS_Vectors(t *testing.T) {
	js := newJSSigner(t)
	if got := js.address(vecWIF, "bc"); got != vecAddress {
		t.Fatalf("address of the vector key = %s, want %s", got, vecAddress)
	}
	// RFC 6979 makes signatures deterministic: the page reproduces the
	// published ones byte for byte.
	if got := js.sign(vecWIF, ""); got != vecSigEmpty {
		t.Errorf("signature of the empty message = %s, want %s", got, vecSigEmpty)
	}
	if got := js.sign(vecWIF, "Hello World"); got != vecSigHello {
		t.Errorf("signature of Hello World = %s, want %s", got, vecSigHello)
	}
}

func TestBIP322JS_SignaturesVerifyInGo(t *testing.T) {
	js := newJSSigner(t)
	messages := []string{"", "x", "ToolMesh grant approval\nline two\n", "UTF-8: öäü 测试 \U0001F604", strings.Repeat("long ", 400)}
	for i := range 8 {
		var seed [32]byte
		_, _ = rand.Read(seed[:])
		key := hex.EncodeToString(seed[:])
		if strings.HasPrefix(key, "ff") {
			continue // could exceed the group order; generateKey refuses those
		}
		hrp := []string{"bc", "tb", "bcrt"}[i%3]
		addr, err := bip322.ParseAddress(js.address(key, hrp))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range messages {
			sig := js.sign(key, m)
			if err := bip322.Verify(addr, []byte(m), sig); err != nil {
				t.Fatalf("key %s, message %.20q: %v", key, m, err)
			}
			if err := bip322.Verify(addr, []byte(m+" "), sig); err == nil {
				t.Fatalf("signature of %.20q verifies for another message", m)
			}
		}
	}
}

func TestBIP322JS_Keys(t *testing.T) {
	js := newJSSigner(t)
	random := "0101010101010101010101010101010101010101010101010101010101010101"
	wif := js.eval(fmt.Sprintf("B.generateKey(B.fromHex(%q), 'bc').wif", random))
	addr := js.eval(fmt.Sprintf("B.generateKey(B.fromHex(%q), 'tb').address", random))
	if got := js.address(wif, "tb"); got != addr {
		t.Errorf("generated key: address %s, parsed back %s", addr, got)
	}
	if got := js.address(random, "tb"); got != addr {
		t.Errorf("hex key: address %s, want %s", got, addr)
	}
	for _, bad := range []string{
		"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", // uncompressed WIF
		vecWIF[:len(vecWIF)-1] + "j",                          // checksum
		"not a key",
		strings.Repeat("0", 64),
	} {
		if _, err := js.vm.RunString(fmt.Sprintf("ToolMeshBIP322.parsePrivateKey(%q)", bad)); err == nil {
			t.Errorf("parsePrivateKey(%q) accepted", bad)
		}
	}
	if got := js.eval(fmt.Sprintf("B.networkOf(%q)", " TB1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX")); got != "tb" {
		t.Errorf("networkOf = %q", got)
	}
	// The witness the page builds is what the Go verifier decodes.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(js.sign(vecWIF, "x"), bip322.PrefixSimple))
	if err != nil || raw[0] != 2 {
		t.Errorf("witness = %x, %v", raw, err)
	}
}
