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

package bip322

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
)

// The test vectors of BIP-322 1.0 (bip-0322/basic-test-vectors.json).
const (
	vecAddress = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
	// vecSigEmpty* sign the empty message, vecSigHello* "Hello World".
	vecSigEmptyLowR = "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
	vecSigEmpty     = "smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
	vecSigHelloLowR = "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI="
	vecSigHello     = "smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
	vecP2WSHAddress = "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9"
	vecP2TRAddress  = "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler"
	vecHello        = "Hello World"
	// bip173Address is the P2WPKH address of the generator point's key
	// (BIP 173 test vectors), another key than vecAddress.
	bip173Address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
)

// toSignTxid returns the txid of the virtual to_sign transaction without its
// witness, for the test vectors.
func toSignTxid(toSpend [32]byte) [32]byte {
	var b bytes.Buffer
	b.Write(le32(0))
	b.WriteByte(1)
	b.Write(toSpend[:])
	b.Write(le32(0))
	b.WriteByte(0) // empty scriptSig
	b.Write(le32(0))
	b.WriteByte(1)
	b.Write(make([]byte, 8))
	b.Write([]byte{0x01, 0x6a})
	b.Write(le32(0))
	return sha256d(b.Bytes())
}

// display renders a transaction hash as block explorers and the test
// vectors do: byte-reversed hex.
func display(h [32]byte) string {
	s := h[:]
	slices.Reverse(s)
	return hex.EncodeToString(s)
}

func mustAddress(t *testing.T, s string) Address {
	t.Helper()
	a, err := ParseAddress(s)
	if err != nil {
		t.Fatalf("ParseAddress(%s): %v", s, err)
	}
	return a
}

func TestCurveConstants(t *testing.T) {
	g := affinePoint(curveGx, curveGy)
	y2 := mulP(curveGy, curveGy)
	if want := addP(mulP(mulP(curveGx, curveGx), curveGx), curveB); y2.Cmp(want) != 0 {
		t.Fatal("G is not on the curve")
	}
	if !twinMult(curveN, g, big.NewInt(0), g).isInfinity() {
		t.Error("n·G is not the point at infinity")
	}
	nMinus1 := new(big.Int).Sub(curveN, big.NewInt(1))
	if !twinMult(nMinus1, g, big.NewInt(1), g).isInfinity() {
		t.Error("(n-1)·G + G is not the point at infinity")
	}
	two := twinMult(big.NewInt(1), g, big.NewInt(1), g)
	if two.affineX().Cmp(double(g).affineX()) != 0 {
		t.Error("G + G differs from 2·G")
	}
}

func TestHashes_Vectors(t *testing.T) {
	addr := mustAddress(t, vecAddress)
	for _, tc := range []struct {
		message, messageHash, toSpend, toSign string
	}{
		{"", "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
			"c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
			"1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6"},
		{vecHello, "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
			"b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
			"88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"},
		{"UTF-8 support: öäüéàè 测试文本 \U0001F604", "43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7",
			"c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0",
			"8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586"},
	} {
		mh := MessageHash([]byte(tc.message))
		if got := hex.EncodeToString(mh[:]); got != tc.messageHash {
			t.Errorf("MessageHash(%q) = %s, want %s", tc.message, got, tc.messageHash)
		}
		toSpend := toSpendTxid(mh, addr)
		if got := display(toSpend); got != tc.toSpend {
			t.Errorf("to_spend(%q) = %s, want %s", tc.message, got, tc.toSpend)
		}
		if got := display(toSignTxid(toSpend)); got != tc.toSign {
			t.Errorf("to_sign(%q) = %s, want %s", tc.message, got, tc.toSign)
		}
	}
}

func TestVerify_Vectors(t *testing.T) {
	addr := mustAddress(t, vecAddress)
	for _, tc := range []struct{ message, sig string }{
		{"", vecSigEmptyLowR},
		{"", vecSigEmpty},
		{vecHello, vecSigHelloLowR},
		{vecHello, vecSigHello},
	} {
		if err := Verify(addr, []byte(tc.message), tc.sig); err != nil {
			t.Errorf("Verify(%q, %.20s…) = %v", tc.message, tc.sig, err)
		}
		// Signatures made before BIP-322 1.0 carry no prefix.
		if err := Verify(addr, []byte(tc.message), strings.TrimPrefix(tc.sig, PrefixSimple)); err != nil {
			t.Errorf("Verify without prefix(%q) = %v", tc.message, err)
		}
	}
}

// mutate decodes the signature of Hello World, lets f change the DER
// signature (with its sighash byte) and the public key, and encodes it again.
func mutate(t *testing.T, f func(der, pub []byte) ([]byte, []byte)) string {
	t.Helper()
	raw, err := decodeSignature(vecSigHello)
	if err != nil {
		t.Fatal(err)
	}
	stack, err := parseWitness(raw)
	if err != nil {
		t.Fatal(err)
	}
	der, pub := f(slices.Clone(stack[0]), slices.Clone(stack[1]))
	out := make([]byte, 0, 3+len(der)+len(pub))
	out = append(out, 2, lenByte(der))
	out = append(out, der...)
	out = append(out, lenByte(pub))
	out = append(out, pub...)
	return PrefixSimple + base64.StdEncoding.EncodeToString(out)
}

// lenByte is the length of test data, all shorter than 256 bytes, as one
// byte.
func lenByte(b []byte) byte { return byte(len(b)) } //nolint:gosec // test data is short

// wantEmpty is what the error for an empty signature says.
const wantEmpty = "empty"

// derInt encodes a minimal non-negative DER integer.
func derInt(n *big.Int) []byte {
	b := n.Bytes()
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return append([]byte{0x02, lenByte(b)}, b...)
}

func TestVerify_Refuses(t *testing.T) {
	addr := mustAddress(t, vecAddress)
	highS := mutate(t, func(der, pub []byte) ([]byte, []byte) {
		r, s, sighash, err := parseDERSignature(der)
		if err != nil {
			t.Fatal(err)
		}
		body := append(derInt(r), derInt(new(big.Int).Sub(curveN, s))...)
		return append(append([]byte{0x30, lenByte(body)}, body...), sighash), pub
	})
	sighashNone := mutate(t, func(der, pub []byte) ([]byte, []byte) {
		der[len(der)-1] = 0x02
		return der, pub
	})
	looseDER := mutate(t, func(der, pub []byte) ([]byte, []byte) {
		der[1]++ // the length no longer matches
		return der, pub
	})
	otherKey := mutate(t, func(der, pub []byte) ([]byte, []byte) {
		pub[0] ^= 0x01 // the other point with this x
		return der, pub
	})

	for _, tc := range []struct {
		name, message, sig, want string
	}{
		{"invalid base64", "", "not-valid-base64!!!", "base64"},
		{"empty", "", "", wantEmpty},
		{"prefix only", "", PrefixSimple, wantEmpty},
		{"wrong message", "Wrong message that was not signed", vecSigEmptyLowR, "does not match"},
		{"empty witness", "", "smpAA==", "holds 0 items"},
		{"unknown prefix", "", "fooAA==", "base64"},
		{"full variant", "", "fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9", "only simple"},
		{"proof of funds", "", "pofAAAA", "only simple"},
		{"high S", vecHello, highS, "low S"},
		{"sighash type", vecHello, sighashNone, "SIGHASH_ALL"},
		{"loose DER", vecHello, looseDER, "DER"},
		{"other key", vecHello, otherKey, "does not belong"},
		{"trailing bytes", "", PrefixSimple + base64.StdEncoding.EncodeToString(append(mustRaw(t, vecSigEmpty), 0)), "follow the witness"},
		{"non-minimal count", "", PrefixSimple + base64.StdEncoding.EncodeToString(append([]byte{0xfd, 0x02, 0x00}, mustRaw(t, vecSigEmpty)[1:]...)), "non-minimal"},
		{"truncated", "", PrefixSimple + base64.StdEncoding.EncodeToString(mustRaw(t, vecSigEmpty)[:40]), "truncated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Verify(addr, []byte(tc.message), tc.sig)
			if !errors.Is(err, ErrInvalidSignature) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Verify = %v, want an invalid-signature error with %q", err, tc.want)
			}
		})
	}

	if err := Verify(mustAddress(t, bip173Address), nil, vecSigEmpty); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("Verify against another address = %v", err)
	}
	if err := Verify(Address{}, nil, vecSigEmpty); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify against the zero address = %v", err)
	}
}

func mustRaw(t *testing.T, sig string) []byte {
	t.Helper()
	raw, err := decodeSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAddress(t *testing.T) {
	for _, s := range []string{vecAddress, strings.ToUpper(vecAddress), " " + bip173Address + " ", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"} {
		a, err := ParseAddress(s)
		if err != nil {
			t.Errorf("ParseAddress(%q) = %v", s, err)
			continue
		}
		if want := strings.ToLower(strings.TrimSpace(s)); a.String() != want {
			t.Errorf("String() = %s, want %s", a, want)
		}
	}
	for _, tc := range []struct{ addr, want string }{
		{vecP2TRAddress, "taproot"},
		{vecP2WSHAddress, "P2WSH"},
		{"bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0m", "checksum"},
		{"bc1Q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", "case"},
		{Address{hrp: "ltc", program: mustAddress(t, bip173Address).program}.String(), "network"},
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "bech32"},
		{"", "bech32"},
	} {
		if _, err := ParseAddress(tc.addr); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseAddress(%q) = %v, want an error with %q", tc.addr, err, tc.want)
		}
	}
	if !(Address{}).IsZero() || mustAddress(t, vecAddress).IsZero() {
		t.Error("IsZero")
	}
}
