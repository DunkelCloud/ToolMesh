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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// jwtBearerGrantType is the RFC 7523 grant_type for JWT bearer assertions.
const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // grant type URN, not a credential

// jwtAssertionLifetime is the exp horizon of a signed assertion; spec §5.3
// caps it at one hour.
const jwtAssertionLifetime = time.Hour

// serviceAccountKey is the subset of a service-account key file the
// jwt_bearer flow needs (spec §5.3). Matches Google's JSON key layout.
type serviceAccountKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// parseServiceAccountKey parses the JSON service-account key a
// service_account_credential resolves to.
func parseServiceAccountKey(raw string) (*serviceAccountKey, error) {
	var key serviceAccountKey
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		return nil, fmt.Errorf("parse service account key JSON: %w", err)
	}
	if key.ClientEmail == "" {
		return nil, fmt.Errorf("service account key has no client_email")
	}
	if key.PrivateKey == "" {
		return nil, fmt.Errorf("service account key has no private_key")
	}
	return &key, nil
}

// parseRSAPrivateKey decodes the PEM private key of a service-account key
// file. PKCS#8 is what Google issues; PKCS#1 is accepted for completeness.
func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("service account private_key is not PEM")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("service account private_key is %T, want RSA", parsed)
		}
		return rsaKey, nil
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse service account private_key: %w", err)
	}
	return rsaKey, nil
}

// buildJWTAssertion signs the RFC 7523 assertion for a jwt_bearer token
// request: RS256, iss = service-account email, aud = token URL, scope from
// the declared scopes, optional sub for domain-wide delegation.
func buildJWTAssertion(key *serviceAccountKey, tokenURL, subject string, scopes []string, now time.Time) (string, error) {
	rsaKey, err := parseRSAPrivateKey(key.PrivateKey)
	if err != nil {
		return "", err
	}

	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss": key.ClientEmail,
		"aud": tokenURL,
		"iat": now.Unix(),
		"exp": now.Add(jwtAssertionLifetime).Unix(),
	}
	if len(scopes) > 0 {
		claims["scope"] = strings.Join(scopes, " ")
	}
	if subject != "" {
		claims["sub"] = subject
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	b64 := base64.RawURLEncoding
	signingInput := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt assertion: %w", err)
	}
	return signingInput + "." + b64.EncodeToString(signature), nil
}
