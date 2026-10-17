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

// BIP-322 message signing for P2WPKH (bc1q…) addresses, simple variant, in
// the browser. The private key never leaves this page: it is read from the
// key field, used to sign and dropped.
//
// Everything is in this one file, without other libraries or browser APIs,
// so that what the page runs is what ToolMesh ships and what its tests run:
// the Go tests execute this file and verify its signatures with ToolMesh's
// own verifier, and compare its hashes with Go's. It is plain ES2020 with
// BigInt; it does not try to hide the timing of operations on the key, which
// matters for a server answering many requests, not for one signature made
// in the approver's own browser.
(function (root) {
  'use strict';

  // ---------------------------------------------------------------- bytes

  function concat() {
    let n = 0;
    for (const a of arguments) n += a.length;
    const out = new Uint8Array(n);
    let off = 0;
    for (const a of arguments) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }

  function toHex(b) {
    let s = '';
    for (const x of b) s += (x < 16 ? '0' : '') + x.toString(16);
    return s;
  }

  function fromHex(s) {
    if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error('not hex');
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  // utf8 encodes a string as UTF-8, as the server reads the signed text.
  function utf8(s) {
    const out = [];
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return Uint8Array.from(out);
  }

  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function base64(b) {
    let s = '';
    for (let i = 0; i < b.length; i += 3) {
      const n = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);
      s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
      s += i + 1 < b.length ? B64[(n >> 6) & 63] : '=';
      s += i + 2 < b.length ? B64[n & 63] : '=';
    }
    return s;
  }

  function bytesToBig(b) {
    return b.length === 0 ? 0n : BigInt('0x' + toHex(b));
  }

  function bigToBytes(n, len) {
    let h = n.toString(16);
    if (h.length > len * 2) throw new Error('number too large');
    return fromHex(h.padStart(len * 2, '0'));
  }

  function le32(n) {
    return Uint8Array.of(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
  }

  // ---------------------------------------------------------------- SHA-256

  const K256 = Uint32Array.of(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2);

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256(msg) {
    const H = Uint32Array.of(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
    const len = msg.length;
    const padded = Math.ceil((len + 9) / 64) * 64;
    const buf = new Uint8Array(padded);
    buf.set(msg);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padded - 8, Math.floor(len / 0x20000000));
    dv.setUint32(padded - 4, (len * 8) >>> 0);
    const W = new Uint32Array(64);
    for (let off = 0; off < padded; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = W[i - 15], b = W[i - 2];
        W[i] = W[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + W[i - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10));
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + W[i]) | 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g;
        g = f;
        f = e;
        e = (d + t1) | 0;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) | 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d;
      H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
    return out;
  }

  function sha256d(b) {
    return sha256(sha256(b));
  }

  function hmacSha256(key, msg) {
    if (key.length > 64) key = sha256(key);
    const k = new Uint8Array(64);
    k.set(key);
    const ipad = k.map((x) => x ^ 0x36);
    const opad = k.map((x) => x ^ 0x5c);
    return sha256(concat(opad, sha256(concat(ipad, msg))));
  }

  function taggedHash(tag, msg) {
    const t = sha256(utf8(tag));
    return sha256(concat(t, t, msg));
  }

  // ---------------------------------------------------------------- RIPEMD-160

  const RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
  const RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
  const SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
  const SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
  const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

  function rotl(x, n) {
    return (x << n) | (x >>> (32 - n));
  }

  function f160(j, x, y, z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  function ripemd160(msg) {
    const len = msg.length;
    const padded = Math.ceil((len + 9) / 64) * 64;
    const buf = new Uint8Array(padded);
    buf.set(msg);
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padded - 8, (len * 8) >>> 0, true);
    dv.setUint32(padded - 4, Math.floor(len / 0x20000000), true);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const X = new Array(16);
    for (let off = 0; off < padded; off += 64) {
      for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + i * 4, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        let t = (rotl((al + f160(j, bl, cl, dl) + X[RL[j]] + KL[j >> 4]) | 0, SL[j]) + el) | 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
        t = (rotl((ar + f160(79 - j, br, cr, dr) + X[RR[j]] + KR[j >> 4]) | 0, SR[j]) + er) | 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
      }
      const t = (h1 + cl + dr) | 0;
      h1 = (h2 + dl + er) | 0;
      h2 = (h3 + el + ar) | 0;
      h3 = (h4 + al + br) | 0;
      h4 = (h0 + bl + cr) | 0;
      h0 = t;
    }
    const out = new Uint8Array(20);
    const ov = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((h, i) => ov.setUint32(i * 4, h >>> 0, true));
    return out;
  }

  function hash160(b) {
    return ripemd160(sha256(b));
  }

  // ---------------------------------------------------------------- secp256k1

  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const G = {
    x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    z: 1n,
  };

  function mod(a, m) {
    const r = a % m;
    return r >= 0n ? r : r + m;
  }

  function invert(a, m) {
    a = mod(a, m);
    if (a === 0n) throw new Error('zero has no inverse');
    let lm = 1n, hm = 0n, low = a, high = m;
    while (low > 1n) {
      const r = high / low;
      [lm, hm] = [hm - lm * r, lm];
      [low, high] = [high - low * r, low];
    }
    return mod(lm, m);
  }

  // Points in Jacobian coordinates; z = 0 is the point at infinity.
  function double(p) {
    if (p.z === 0n || p.y === 0n) return { x: 0n, y: 0n, z: 0n };
    const a = mod(p.x * p.x, P), b = mod(p.y * p.y, P), c = mod(b * b, P);
    const d = mod(2n * (mod((p.x + b) * (p.x + b), P) - a - c), P);
    const e = mod(3n * a, P), f = mod(e * e, P);
    const x = mod(f - 2n * d, P);
    return { x, y: mod(e * (d - x) - 8n * c, P), z: mod(2n * p.y * p.z, P) };
  }

  function add(p, q) {
    if (p.z === 0n) return q;
    if (q.z === 0n) return p;
    const z1z1 = mod(p.z * p.z, P), z2z2 = mod(q.z * q.z, P);
    const u1 = mod(p.x * z2z2, P), u2 = mod(q.x * z1z1, P);
    const s1 = mod(p.y * q.z * z2z2, P), s2 = mod(q.y * p.z * z1z1, P);
    const h = mod(u2 - u1, P), r = mod(2n * (s2 - s1), P);
    if (h === 0n) return r === 0n ? double(p) : { x: 0n, y: 0n, z: 0n };
    const i = mod(4n * h * h, P), j = mod(h * i, P), v = mod(u1 * i, P);
    const x = mod(r * r - j - 2n * v, P);
    const y = mod(r * (v - x) - 2n * s1 * j, P);
    const z = mod((mod((p.z + q.z) * (p.z + q.z), P) - z1z1 - z2z2) * h, P);
    return { x, y, z };
  }

  function multiply(k, p) {
    let r = { x: 0n, y: 0n, z: 0n };
    for (let i = BigInt(k.toString(2).length - 1); i >= 0n; i--) {
      r = double(r);
      if ((k >> i) & 1n) r = add(r, p);
    }
    return r;
  }

  function affine(p) {
    const zi = invert(p.z, P);
    const zi2 = mod(zi * zi, P);
    return { x: mod(p.x * zi2, P), y: mod(p.y * zi2 * zi, P) };
  }

  // publicKey returns the compressed public key (33 bytes) of a private key.
  function publicKey(d) {
    const a = affine(multiply(d, G));
    return concat(Uint8Array.of(a.y & 1n ? 0x03 : 0x02), bigToBytes(a.x, 32));
  }

  // rfc6979 yields the deterministic nonces of RFC 6979 (HMAC-SHA256) for the
  // key and the 32-byte hash, the first one first.
  function* rfc6979(d, hash) {
    const x = bigToBytes(d, 32);
    const h1 = bigToBytes(mod(bytesToBig(hash), N), 32);
    let V = new Uint8Array(32).fill(1);
    let K = new Uint8Array(32);
    K = hmacSha256(K, concat(V, Uint8Array.of(0), x, h1));
    V = hmacSha256(K, V);
    K = hmacSha256(K, concat(V, Uint8Array.of(1), x, h1));
    V = hmacSha256(K, V);
    for (;;) {
      V = hmacSha256(K, V);
      const k = bytesToBig(V);
      if (k >= 1n && k < N) yield k;
      K = hmacSha256(K, concat(V, Uint8Array.of(0)));
      V = hmacSha256(K, V);
    }
  }

  function derInteger(n) {
    let b = bigToBytes(n, 32);
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
    return concat(Uint8Array.of(0x02, b.length), b);
  }

  // signECDSA signs the 32-byte hash with low S and returns it DER-encoded.
  function signECDSA(d, hash) {
    const e = mod(bytesToBig(hash), N);
    for (const k of rfc6979(d, hash)) {
      const r = mod(affine(multiply(k, G)).x, N);
      if (r === 0n) continue;
      let s = mod(invert(k, N) * (e + r * d), N);
      if (s === 0n) continue;
      if (s > N >> 1n) s = N - s;
      const body = concat(derInteger(r), derInteger(s));
      return concat(Uint8Array.of(0x30, body.length), body);
    }
  }

  // ---------------------------------------------------------------- keys and addresses

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function base58Decode(s) {
    let n = 0n;
    for (const c of s) {
      const v = B58.indexOf(c);
      if (v < 0) throw new Error('not base58');
      n = n * 58n + BigInt(v);
    }
    let zeros = 0;
    while (zeros < s.length && s[zeros] === '1') zeros++;
    const body = n === 0n ? new Uint8Array(0) : fromHex(n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0'));
    return concat(new Uint8Array(zeros), body);
  }

  function base58Encode(b) {
    let n = bytesToBig(b);
    let s = '';
    while (n > 0n) {
      s = B58[Number(n % 58n)] + s;
      n /= 58n;
    }
    for (const x of b) {
      if (x !== 0) break;
      s = '1' + s;
    }
    return s;
  }

  // parsePrivateKey reads a private key given as WIF (compressed, as wallets
  // export it for bc1q addresses) or as 64 hex characters.
  function parsePrivateKey(text) {
    const s = text.trim();
    let d;
    if (/^[0-9a-fA-F]{64}$/.test(s)) {
      d = BigInt('0x' + s);
    } else {
      let raw;
      try {
        raw = base58Decode(s);
      } catch (e) {
        throw new Error('The key is neither WIF nor 64 hex characters.');
      }
      if (raw.length === 37) throw new Error('This WIF key is for an uncompressed public key; bc1q addresses need a compressed key.');
      if (raw.length !== 38 || raw[33] !== 0x01 || (raw[0] !== 0x80 && raw[0] !== 0xef)) {
        throw new Error('The key is neither WIF nor 64 hex characters.');
      }
      const sum = sha256d(raw.slice(0, 34)).slice(0, 4);
      if (toHex(sum) !== toHex(raw.slice(34))) throw new Error('The WIF checksum does not match: the key is mistyped.');
      d = bytesToBig(raw.slice(1, 33));
    }
    if (d < 1n || d >= N) throw new Error('The key is out of range.');
    return d;
  }

  const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  function polymod(values) {
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= gen[i];
    }
    return chk >>> 0;
  }

  // addressOf returns the P2WPKH address of a public key on the network of
  // the human-readable part (bc, tb or bcrt).
  function addressOf(pub, hrp) {
    const prog = hash160(pub);
    const data = [0];
    let acc = 0, bits = 0;
    for (const v of prog) {
      acc = (acc << 8) | v;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        data.push((acc >>> bits) & 31);
      }
    }
    if (bits > 0) data.push((acc << (5 - bits)) & 31);
    const expand = [];
    for (const c of hrp) expand.push(c.charCodeAt(0) >> 5);
    expand.push(0);
    for (const c of hrp) expand.push(c.charCodeAt(0) & 31);
    const mod32 = polymod(expand.concat(data, [0, 0, 0, 0, 0, 0])) ^ 1;
    let s = hrp + '1';
    for (const d of data) s += BECH32[d];
    for (let i = 0; i < 6; i++) s += BECH32[(mod32 >>> (5 * (5 - i))) & 31];
    return s;
  }

  // networkOf returns the human-readable part of a bech32 address.
  function networkOf(address) {
    const a = address.trim().toLowerCase();
    return a.slice(0, a.lastIndexOf('1'));
  }

  // generateKey makes a new key from 32 random bytes and returns it as WIF
  // (compressed, main network) with its address.
  function generateKey(random32, hrp) {
    const d = bytesToBig(random32);
    if (random32.length !== 32 || d < 1n || d >= N) throw new Error('unusable random bytes, try again');
    const payload = concat(Uint8Array.of(0x80), random32, Uint8Array.of(0x01));
    const wif = base58Encode(concat(payload, sha256d(payload).slice(0, 4)));
    return { wif, address: addressOf(publicKey(d), hrp || 'bc') };
  }

  // ---------------------------------------------------------------- BIP-322

  // signMessage signs the message with the key for its P2WPKH address and
  // returns the simple BIP-322 signature with its "smp" prefix.
  function signMessage(d, message) {
    const pub = publicKey(d);
    const prog = hash160(pub);
    const scriptPubKey = concat(Uint8Array.of(0x00, 0x14), prog);
    const msgHash = taggedHash('BIP0322-signed-message', utf8(message));

    const toSpend = sha256d(concat(
      le32(0), Uint8Array.of(1), new Uint8Array(32), Uint8Array.of(0xff, 0xff, 0xff, 0xff),
      Uint8Array.of(34, 0x00, 0x20), msgHash, le32(0),
      Uint8Array.of(1), new Uint8Array(8), Uint8Array.of(scriptPubKey.length), scriptPubKey, le32(0)));

    const outpoint = concat(toSpend, le32(0));
    const preimage = concat(
      le32(0), sha256d(outpoint), sha256d(le32(0)), outpoint,
      Uint8Array.of(0x19, 0x76, 0xa9, 0x14), prog, Uint8Array.of(0x88, 0xac),
      new Uint8Array(8), le32(0), sha256d(concat(new Uint8Array(8), Uint8Array.of(0x01, 0x6a))),
      le32(0), le32(1));
    const sig = concat(signECDSA(d, sha256d(preimage)), Uint8Array.of(0x01));
    const witness = concat(Uint8Array.of(2, sig.length), sig, Uint8Array.of(pub.length), pub);
    return 'smp' + base64(witness);
  }

  root.ToolMeshBIP322 = {
    sha256, hmacSha256, ripemd160, hash160, utf8, toHex, fromHex,
    parsePrivateKey, publicKey, addressOf, networkOf, generateKey, signMessage,
  };
})(typeof window !== 'undefined' ? window : globalThis);
