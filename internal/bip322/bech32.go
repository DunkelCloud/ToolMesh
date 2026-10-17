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
	"errors"
	"fmt"
	"strings"
)

// bech32Charset maps 5-bit values to the characters of a bech32 string.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// Checksum constants of bech32 (BIP 173, witness version 0) and bech32m
// (BIP 350, witness version 1 and later).
const (
	bech32Const  = 1
	bech32mConst = 0x2bc830a3
)

// segwitHRPs are the human-readable parts of segwit addresses: main network,
// test networks and regtest. An approver's key never touches a chain, so any
// of them identifies it equally well.
var segwitHRPs = []string{"bc", "tb", "bcrt"}

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range gen {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// bech32Decode splits a bech32 or bech32m string into its human-readable part
// and 5-bit data (without the checksum) and reports the checksum constant it
// matched.
func bech32Decode(s string) (hrp string, data []byte, constant uint32, err error) {
	if len(s) > 90 {
		return "", nil, 0, errors.New("longer than 90 characters")
	}
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, 0, errors.New("mixes upper and lower case")
	}
	s = strings.ToLower(s)
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return "", nil, 0, errors.New("no separator or too short")
	}
	hrp = s[:sep]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, 0, errors.New("invalid character in the human-readable part")
		}
	}
	for _, c := range s[sep+1:] {
		v := strings.IndexRune(bech32Charset, c)
		if v < 0 {
			return "", nil, 0, fmt.Errorf("invalid character %q", c)
		}
		data = append(data, byte(v)) //nolint:gosec // v indexes the 32-character charset
	}
	constant = bech32Polymod(append(bech32HRPExpand(hrp), data...))
	if constant != bech32Const && constant != bech32mConst {
		return "", nil, 0, errors.New("checksum mismatch")
	}
	return hrp, data[:len(data)-6], constant, nil
}

// bech32Encode renders a human-readable part and 5-bit data with a bech32
// checksum.
func bech32Encode(hrp string, data []byte) string {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ bech32Const
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, d := range data {
		b.WriteByte(bech32Charset[d])
	}
	for i := range 6 {
		b.WriteByte(bech32Charset[(mod>>(5*(5-i)))&31])
	}
	return b.String()
}

// convertBits regroups bits, from groups of from bits to groups of to bits.
func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	acc, bits := uint32(0), uint(0)
	maxv := uint32(1)<<to - 1
	var out []byte
	for _, v := range data {
		if uint32(v)>>from != 0 {
			return nil, errors.New("invalid data")
		}
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte((acc>>bits)&maxv)) //nolint:gosec // masked to at most 8 bits
		}
	}
	switch {
	case pad && bits > 0:
		out = append(out, byte((acc<<(to-bits))&maxv)) //nolint:gosec // masked to at most 8 bits
	case !pad && (bits >= from || (acc<<(to-bits))&maxv != 0):
		return nil, errors.New("invalid padding")
	}
	return out, nil
}
