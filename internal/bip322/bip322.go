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

// Package bip322 verifies BIP-322 signed messages of native segwit v0
// pay-to-public-key-hash (P2WPKH, "bc1q…") addresses in the simple variant.
//
// A BIP-322 signature proves that the holder of the key behind an address
// signed a message: the signer signs a virtual transaction that spends a
// virtual output locked to the address and committing to the message. Any
// wallet that signs BIP-322 messages for such an address can produce one;
// verifying it takes only the address, the message and the signature. No
// coins, network or blockchain are involved.
//
// Only what the simple variant needs for P2WPKH is implemented: a witness of
// a signature and a compressed public key, checked with the BIP-322 rules
// (SIGHASH_ALL, strict DER, low S). Other address types and the full variant
// are refused.
package bip322

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck,gosec // P2WPKH addresses are defined over RIPEMD-160 (hash160)
)

// Signature prefixes of BIP-322 1.0: the variant a signature was made with.
const (
	PrefixSimple = "smp"
	prefixFull   = "ful"
	prefixFunds  = "pof"
)

// sighashAll is the only sighash type BIP-322 allows for P2WPKH.
const sighashAll = 0x01

// messageTag tags the hash of a signed message (BIP 340 tagged hash).
const messageTag = "BIP0322-signed-message"

// ErrInvalidSignature marks every reason a signature is refused. errors.Is
// reports each error of Verify as ErrInvalidSignature.
var ErrInvalidSignature = errors.New("invalid signature")

// invalidf returns an error that counts as ErrInvalidSignature.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidSignature}, args...)...)
}

// Address is a P2WPKH address: a network and the hash160 of a public key.
type Address struct {
	hrp     string
	program [20]byte
}

// ParseAddress parses a P2WPKH address such as "bc1q…" (main network),
// "tb1q…" (test networks) or "bcrt1q…" (regtest). Other address types are
// refused with an error that names them.
func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	hrp, data, constant, err := bech32Decode(s)
	if err != nil {
		return Address{}, fmt.Errorf("address %q is not a bech32 segwit address: %w", s, err)
	}
	known := false
	for _, h := range segwitHRPs {
		known = known || hrp == h
	}
	if !known {
		return Address{}, fmt.Errorf("address %q: unknown network %q (use a bc1q… address)", s, hrp)
	}
	if len(data) == 0 {
		return Address{}, fmt.Errorf("address %q has no witness program", s)
	}
	version := data[0]
	program, err := convertBits(data[1:], 5, 8, false)
	if err != nil {
		return Address{}, fmt.Errorf("address %q: %w", s, err)
	}
	switch {
	case version == 1 && len(program) == 32:
		return Address{}, fmt.Errorf("address %q is a taproot (P2TR) address; only P2WPKH addresses (%s1q…) are supported", s, hrp)
	case version != 0:
		return Address{}, fmt.Errorf("address %q has witness version %d; only P2WPKH addresses (%s1q…) are supported", s, version, hrp)
	case constant != bech32Const:
		return Address{}, fmt.Errorf("address %q: a witness version 0 address must use the bech32 checksum", s)
	case len(program) == 32:
		return Address{}, fmt.Errorf("address %q is a script (P2WSH) address; only P2WPKH addresses (%s1q…) are supported", s, hrp)
	case len(program) != 20:
		return Address{}, fmt.Errorf("address %q has a %d-byte witness program; a P2WPKH program has 20 bytes", s, len(program))
	}
	a := Address{hrp: hrp}
	copy(a.program[:], program)
	return a, nil
}

// String returns the address in its canonical lower-case form.
func (a Address) String() string {
	data, _ := convertBits(a.program[:], 8, 5, true)
	return bech32Encode(a.hrp, append([]byte{0}, data...))
}

// IsZero reports whether a is the zero Address, which no parsed address is.
func (a Address) IsZero() bool { return a.hrp == "" }

// scriptPubKey returns the output script of the address: OP_0 PUSH20 <hash>.
func (a Address) scriptPubKey() []byte {
	return append([]byte{0x00, 0x14}, a.program[:]...)
}

// MessageHash returns the BIP-322 hash of a message: the tagged SHA-256 with
// the tag "BIP0322-signed-message".
func MessageHash(message []byte) [32]byte {
	tag := sha256.Sum256([]byte(messageTag))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write(message)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify checks a simple-variant BIP-322 signature of message by the key
// behind addr. The signature is the base64 witness, with or without the
// "smp" prefix. Every error counts as ErrInvalidSignature.
func Verify(addr Address, message []byte, signature string) error {
	if addr.IsZero() {
		return invalidf("no address to verify against")
	}
	raw, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	stack, err := parseWitness(raw)
	if err != nil {
		return err
	}
	if len(stack) != 2 {
		return invalidf("a P2WPKH signature holds a signature and a public key, this one holds %d items", len(stack))
	}
	sig, pub := stack[0], stack[1]
	if hash160(pub) != addr.program {
		return invalidf("signed with a key that does not belong to %s", addr)
	}
	q, err := parsePubKey(pub)
	if err != nil {
		return invalidf("%s", err)
	}
	r, s, sighash, err := parseDERSignature(sig)
	switch {
	case err != nil:
		return invalidf("%s", err)
	case sighash != sighashAll:
		return invalidf("sighash type 0x%02x; BIP-322 requires SIGHASH_ALL", sighash)
	case s.Cmp(halfN) > 0:
		return invalidf("high S value; BIP-322 requires low S")
	}
	toSpend := toSpendTxid(MessageHash(message), addr)
	digest := sighashP2WPKH(toSpend, addr.program)
	if !verifyECDSA(q, digest[:], r, s) {
		return invalidf("the signature does not match the message and address")
	}
	return nil
}

// decodeSignature strips the variant prefix and decodes the base64 witness.
// Without a prefix the simple variant is assumed, as BIP-322 allows for
// signatures made before the prefixes were introduced.
func decodeSignature(signature string) ([]byte, error) {
	sig := strings.TrimSpace(signature)
	switch {
	case strings.HasPrefix(sig, prefixFull), strings.HasPrefix(sig, prefixFunds):
		return nil, invalidf("only simple signatures are supported, this is a %q signature", sig[:3])
	case strings.HasPrefix(sig, PrefixSimple):
		sig = sig[len(PrefixSimple):]
	}
	if sig == "" {
		return nil, invalidf("the signature is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, invalidf("the signature is not base64: %s", err)
	}
	return raw, nil
}

// parseWitness decodes a consensus-encoded witness stack: a count, then each
// item with its length. Every byte must belong to it.
func parseWitness(b []byte) ([][]byte, error) {
	count, rest, err := readCompactSize(b)
	if err != nil {
		return nil, err
	}
	// A witness item takes at least one byte, so a count beyond the bytes
	// left is malformed; this also bounds the allocation.
	if count > uint64(len(rest)) {
		return nil, invalidf("the witness is truncated")
	}
	stack := make([][]byte, 0, count)
	for range count {
		var n uint64
		n, rest, err = readCompactSize(rest)
		if err != nil {
			return nil, err
		}
		if n > uint64(len(rest)) {
			return nil, invalidf("the witness is truncated")
		}
		stack = append(stack, rest[:n])
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, invalidf("%d bytes follow the witness", len(rest))
	}
	return stack, nil
}

// readCompactSize reads a minimally encoded Bitcoin CompactSize integer and
// returns it with the bytes that follow.
func readCompactSize(b []byte) (n uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, nil, invalidf("the witness is truncated")
	}
	// size is how many bytes follow the marker, minimum the smallest value
	// that needs them.
	var size int
	var minimum uint64
	switch b[0] {
	case 0xfd:
		size, minimum = 2, 0xfd
	case 0xfe:
		size, minimum = 4, 0x10000
	case 0xff:
		size, minimum = 8, 0x100000000
	default:
		return uint64(b[0]), b[1:], nil
	}
	if len(b) < 1+size {
		return 0, nil, invalidf("the witness is truncated")
	}
	var buf [8]byte
	copy(buf[:], b[1:1+size])
	n = binary.LittleEndian.Uint64(buf[:])
	if n < minimum {
		return 0, nil, invalidf("the witness uses a non-minimal length encoding")
	}
	return n, b[1+size:], nil
}

// hash160 is RIPEMD-160 of SHA-256, the hash a P2WPKH address commits to.
func hash160(b []byte) [20]byte {
	sum := sha256.Sum256(b)
	h := ripemd160.New() //nolint:gosec // the address format requires RIPEMD-160; it is not used for anything else
	h.Write(sum[:])
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

// sha256d is SHA-256 applied twice, Bitcoin's transaction hash.
func sha256d(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// le32 is a 32-bit little-endian integer.
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

// toSpendTxid returns the txid (in internal byte order) of the virtual
// to_spend transaction: version 0, one input spending nothing whose
// scriptSig is OP_0 PUSH32 <message hash>, one output of value 0 locked to
// the address, lock time 0.
func toSpendTxid(messageHash [32]byte, addr Address) [32]byte {
	var b bytes.Buffer
	b.Write(le32(0))                        // nVersion
	b.WriteByte(1)                          // one input
	b.Write(make([]byte, 32))               // prevout hash 000…000
	b.Write([]byte{0xff, 0xff, 0xff, 0xff}) // prevout index 0xFFFFFFFF
	b.WriteByte(34)                         // scriptSig length
	b.Write([]byte{0x00, 0x20})             // OP_0 PUSH32
	b.Write(messageHash[:])                 // message hash
	b.Write(le32(0))                        // nSequence
	b.WriteByte(1)                          // one output
	b.Write(make([]byte, 8))                // value 0
	b.WriteByte(22)                         // scriptPubKey length
	b.Write(addr.scriptPubKey())            // message challenge
	b.Write(le32(0))                        // nLockTime
	return sha256d(b.Bytes())
}

// sighashP2WPKH returns the BIP-143 signature hash (SIGHASH_ALL) of the
// virtual to_sign transaction for a P2WPKH key: version 0, one input
// spending output 0 of to_spend with sequence 0, one output of value 0 with
// the script OP_RETURN, lock time 0.
func sighashP2WPKH(toSpend [32]byte, program [20]byte) [32]byte {
	outpoint := make([]byte, 0, 36)
	outpoint = append(outpoint, toSpend[:]...)
	outpoint = append(outpoint, le32(0)...) // output index 0
	hashPrevouts := sha256d(outpoint)
	hashSequence := sha256d(le32(0))
	hashOutputs := sha256d(append(make([]byte, 8), 0x01, 0x6a)) // value 0, OP_RETURN

	var b bytes.Buffer
	b.Write(le32(0)) // nVersion
	b.Write(hashPrevouts[:])
	b.Write(hashSequence[:])
	b.Write(outpoint)
	// scriptCode: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
	b.Write([]byte{0x19, 0x76, 0xa9, 0x14})
	b.Write(program[:])
	b.Write([]byte{0x88, 0xac})
	b.Write(make([]byte, 8)) // amount of the spent output: 0
	b.Write(le32(0))         // nSequence
	b.Write(hashOutputs[:])
	b.Write(le32(0))          // nLockTime
	b.Write(le32(sighashAll)) // sighash type
	return sha256d(b.Bytes())
}
