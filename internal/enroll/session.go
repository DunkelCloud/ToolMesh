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

package enroll

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// sessionTTL is how long a login on the page lasts. There is no renewal:
// storing a credential takes a minute, and a short session bounds what a
// cookie left in a browser is good for.
const sessionTTL = 15 * time.Minute

// noticeTTL is how long the message of a change waits for the page that
// shows it: the time of one redirect.
const noticeTTL = time.Minute

// Names of the page's cookies. Over https they carry the __Host- prefix
// (see cookieName), which keeps another host of the same domain from
// setting them.
const (
	sessionCookie = "toolmesh_credentials"
	noticeCookie  = "toolmesh_credentials_notice"
	hostPrefix    = "__Host-"
)

// Labels of the keys derived from the user credentials key. Each use gets a
// key of its own, so a cookie of the page is no credential ciphertext and
// the other way round.
const (
	sealKeyInfo = "toolmesh credentials page: cookies v1"
	csrfKeyInfo = "toolmesh credentials page: form token v1"
)

// session is what the session cookie holds, sealed: who signed in, with
// which password, and until when. Nothing but the ids of signed-out
// sessions is kept on the server.
type session struct {
	// ID tells one session from another, so that signing out ends this one.
	ID   string `json:"i"`
	User string `json:"u"`
	// FP is the fingerprint of the password of the login. A session ends
	// when the user's password changes or the user is removed.
	FP  string `json:"f"`
	Exp int64  `json:"e"`
}

// flash is what the notice cookie holds, sealed: the message of a change
// for the page the browser is redirected to, and for whom it is.
type flash struct {
	User string `json:"u"`
	Kind string `json:"k"`
	Text string `json:"t"`
	// Backend and Label refill the account label of a refused save.
	Backend string `json:"b,omitempty"`
	Label   string `json:"l,omitempty"`
	Exp     int64  `json:"e"`
}

// sealer seals the page's cookies and derives the token of its forms.
type sealer struct {
	aead    cipher.AEAD
	csrfKey []byte
}

// newSealer derives the keys of the page from the user credentials key.
func newSealer(key []byte) (*sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("the key of the credentials page is shorter than 32 bytes")
	}
	sealKey, err := hkdf.Key(sha256.New, key, nil, sealKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive cookie key: %w", err)
	}
	csrfKey, err := hkdf.Key(sha256.New, key, nil, csrfKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive form token key: %w", err)
	}
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, fmt.Errorf("cookie key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cookie key: %w", err)
	}
	return &sealer{aead: aead, csrfKey: csrfKey}, nil
}

// newSessionID returns a random id for a session.
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// seal returns the cookie value for v. purpose is bound into the seal, so
// the value of one cookie does not open as another.
func (k *sealer) seal(purpose string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, plain, []byte(purpose))), nil
}

// open decodes a cookie value that this key sealed for purpose into v.
func (k *sealer) open(purpose, value string, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < k.aead.NonceSize() {
		return false
	}
	nonce, sealed := raw[:k.aead.NonceSize()], raw[k.aead.NonceSize():]
	plain, err := k.aead.Open(nil, nonce, sealed, []byte(purpose))
	if err != nil {
		return false
	}
	return json.Unmarshal(plain, v) == nil
}

// openSession returns the session of a cookie value that has not run out
// at now.
func (k *sealer) openSession(value string, now time.Time) (session, bool) {
	var s session
	if !k.open(sessionCookie, value, &s) || s.User == "" || s.ID == "" {
		return session{}, false
	}
	if !now.Before(time.Unix(s.Exp, 0)) {
		return session{}, false
	}
	return s, true
}

// openFlash returns the notice of a cookie value that has not run out at
// now.
func (k *sealer) openFlash(value string, now time.Time) (flash, bool) {
	var f flash
	if !k.open(noticeCookie, value, &f) || !now.Before(time.Unix(f.Exp, 0)) {
		return flash{}, false
	}
	return f, true
}

// formToken returns the token the forms of a session carry: a MAC of the
// session cookie. A request that changes something has to present it, so a
// form built elsewhere, which cannot read the cookie, does not pass.
func (k *sealer) formToken(cookieValue string) string {
	mac := hmac.New(sha256.New, k.csrfKey)
	mac.Write([]byte(cookieValue))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// formTokenValid reports whether token is the form token of the session
// cookie, in constant time.
func (k *sealer) formTokenValid(cookieValue, token string) bool {
	want := k.formToken(cookieValue)
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}
