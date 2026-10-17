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
	"math/big"
)

// The curve secp256k1, y² = x³ + 7 over the integers modulo p, and its base
// point G of prime order n (SEC 2, section 2.4.1).
var (
	curveP  = hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	curveN  = hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	curveGx = hexInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	curveGy = hexInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	curveB  = big.NewInt(7)

	// halfN bounds the S value of a signature: BIP-322 requires low S.
	halfN = new(big.Int).Rsh(curveN, 1)
	// sqrtExp is (p+1)/4: as p ≡ 3 mod 4, a^sqrtExp is a square root of a
	// square a.
	sqrtExp = new(big.Int).Rsh(new(big.Int).Add(curveP, big.NewInt(1)), 2)
)

// hexInt parses a hexadecimal constant. The constants above are fixed; a test
// checks that G lies on the curve and has order n.
func hexInt(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

// The only verification code here works on public values (a public key, a
// signature, a hash), so it needs no protection against timing attacks; it
// never handles a private key.

// point is a point in Jacobian coordinates (X/Z², Y/Z³); Z = 0 is the point
// at infinity.
type point struct{ x, y, z *big.Int }

func infinity() point { return point{new(big.Int), new(big.Int), new(big.Int)} }

func affinePoint(x, y *big.Int) point {
	return point{new(big.Int).Set(x), new(big.Int).Set(y), big.NewInt(1)}
}

func (p point) isInfinity() bool { return p.z.Sign() == 0 }

// modP, mulP, subP, addP and smallP are the field operations; each result is
// reduced mod p.
func modP(x *big.Int) *big.Int { return x.Mod(x, curveP) }

func mulP(a, b *big.Int) *big.Int { return modP(new(big.Int).Mul(a, b)) }

func subP(a, b *big.Int) *big.Int { return modP(new(big.Int).Sub(a, b)) }

func addP(a, b *big.Int) *big.Int { return modP(new(big.Int).Add(a, b)) }

func smallP(k int64, a *big.Int) *big.Int { return modP(new(big.Int).Mul(big.NewInt(k), a)) }

// double returns 2p (formula dbl-2009-l for a = 0).
func double(p point) point {
	if p.isInfinity() || p.y.Sign() == 0 {
		return infinity()
	}
	a := mulP(p.x, p.x)
	b := mulP(p.y, p.y)
	c := mulP(b, b)
	xb := addP(p.x, b)
	d := smallP(2, subP(subP(mulP(xb, xb), a), c))
	e := smallP(3, a)
	f := mulP(e, e)
	x3 := subP(f, smallP(2, d))
	y3 := subP(mulP(e, subP(d, x3)), smallP(8, c))
	z3 := smallP(2, mulP(p.y, p.z))
	return point{x3, y3, z3}
}

// add returns p + q (formula add-2007-bl).
func add(p, q point) point {
	switch {
	case p.isInfinity():
		return q
	case q.isInfinity():
		return p
	}
	z1z1 := mulP(p.z, p.z)
	z2z2 := mulP(q.z, q.z)
	u1 := mulP(p.x, z2z2)
	u2 := mulP(q.x, z1z1)
	s1 := mulP(mulP(p.y, q.z), z2z2)
	s2 := mulP(mulP(q.y, p.z), z1z1)
	h := subP(u2, u1)
	r := smallP(2, subP(s2, s1))
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return double(p)
		}
		return infinity()
	}
	h2 := smallP(2, h)
	i := mulP(h2, h2)
	j := mulP(h, i)
	v := mulP(u1, i)
	x3 := subP(subP(mulP(r, r), j), smallP(2, v))
	y3 := subP(mulP(r, subP(v, x3)), smallP(2, mulP(s1, j)))
	zz := addP(p.z, q.z)
	z3 := mulP(subP(subP(mulP(zz, zz), z1z1), z2z2), h)
	return point{x3, y3, z3}
}

// affineX returns the affine x coordinate of a point that is not infinity.
func (p point) affineX() *big.Int {
	zinv := new(big.Int).ModInverse(p.z, curveP)
	return mulP(p.x, mulP(zinv, zinv))
}

// twinMult returns a·P + b·Q (Shamir's trick: one pass over the bits).
func twinMult(a *big.Int, p point, b *big.Int, q point) point {
	pq := add(p, q)
	r := infinity()
	for i := max(a.BitLen(), b.BitLen()) - 1; i >= 0; i-- {
		r = double(r)
		switch {
		case a.Bit(i) == 1 && b.Bit(i) == 1:
			r = add(r, pq)
		case a.Bit(i) == 1:
			r = add(r, p)
		case b.Bit(i) == 1:
			r = add(r, q)
		}
	}
	return r
}

// errPubKey is returned for a public key that is not a compressed point on
// the curve.
var errPubKey = errors.New("the public key is not a compressed secp256k1 key")

// parsePubKey parses a compressed public key (33 bytes: 0x02 or 0x03 for the
// parity of y, then x). Segwit v0 allows compressed keys only.
func parsePubKey(b []byte) (point, error) {
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return point{}, errPubKey
	}
	x := new(big.Int).SetBytes(b[1:])
	if x.Cmp(curveP) >= 0 {
		return point{}, errPubKey
	}
	y2 := addP(mulP(mulP(x, x), x), curveB)
	y := new(big.Int).Exp(y2, sqrtExp, curveP)
	if mulP(y, y).Cmp(y2) != 0 {
		return point{}, errPubKey
	}
	if y.Bit(0) != uint(b[0]&1) {
		y.Sub(curveP, y)
	}
	return affinePoint(x, y), nil
}

// verifyECDSA reports whether (r, s) is a signature of the 32-byte hash by
// the public key q.
func verifyECDSA(q point, hash []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(curveN) >= 0 || s.Cmp(curveN) >= 0 {
		return false
	}
	e := new(big.Int).SetBytes(hash)
	w := new(big.Int).ModInverse(s, curveN)
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, curveN)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, curveN)
	pt := twinMult(u1, affinePoint(curveGx, curveGy), u2, q)
	if pt.isInfinity() {
		return false
	}
	x := pt.affineX()
	x.Mod(x, curveN)
	return x.Cmp(r) == 0
}

// errDER is returned for a signature that is not strictly DER-encoded.
var errDER = errors.New("the ECDSA signature is not strictly DER-encoded")

// parseDERSignature parses a strictly DER-encoded signature followed by its
// sighash byte, by the rules of BIP 66: 0x30 len 0x02 rlen r 0x02 slen s
// sighash, with minimal, non-negative integers.
func parseDERSignature(sig []byte) (r, s *big.Int, sighash byte, err error) {
	n := len(sig)
	if n < 9 || n > 73 || sig[0] != 0x30 || int(sig[1]) != n-3 {
		return nil, nil, 0, errDER
	}
	lenR := int(sig[3])
	if 5+lenR >= n {
		return nil, nil, 0, errDER
	}
	lenS := int(sig[5+lenR])
	if lenR+lenS+7 != n {
		return nil, nil, 0, errDER
	}
	if !derInteger(sig[2], sig[4:4+lenR]) || !derInteger(sig[4+lenR], sig[6+lenR:6+lenR+lenS]) {
		return nil, nil, 0, errDER
	}
	r = new(big.Int).SetBytes(sig[4 : 4+lenR])
	s = new(big.Int).SetBytes(sig[6+lenR : 6+lenR+lenS])
	return r, s, sig[n-1], nil
}

// derInteger reports whether tag and value form a minimal, non-negative DER
// INTEGER.
func derInteger(tag byte, v []byte) bool {
	switch {
	case tag != 0x02 || len(v) == 0:
		return false
	case v[0]&0x80 != 0:
		return false
	case len(v) > 1 && v[0] == 0 && v[1]&0x80 == 0:
		return false
	}
	return true
}
