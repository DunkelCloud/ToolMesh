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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testServiceAccountJSON builds a service-account key JSON around a fresh
// RSA key, returning the JSON and the public key for signature checks.
func testServiceAccountJSON(t *testing.T, tokenURI string) (string, *rsa.PublicKey) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	keyJSON, err := json.Marshal(map[string]string{
		"client_email": "svc@example.iam.gserviceaccount.com",
		"private_key":  pemKey,
		"token_uri":    tokenURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(keyJSON), &rsaKey.PublicKey
}

func decodeJWTSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("segment not base64url: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("segment not JSON: %v", err)
	}
	return m
}

func TestBuildJWTAssertion(t *testing.T) {
	keyJSON, pubKey := testServiceAccountJSON(t, "https://oauth2.example.com/token")
	key, err := parseServiceAccountKey(keyJSON)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_754_000_000, 0)
	jwt, err := buildJWTAssertion(key, "https://oauth2.example.com/token", "admin@example.com",
		[]string{"scope.a", "scope.b"}, now)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d segments, want 3", len(parts))
	}
	header := decodeJWTSegment(t, parts[0])
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Errorf("header = %v, want RS256/JWT", header)
	}
	claims := decodeJWTSegment(t, parts[1])
	if claims["iss"] != "svc@example.iam.gserviceaccount.com" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["aud"] != "https://oauth2.example.com/token" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["scope"] != "scope.a scope.b" {
		t.Errorf("scope = %v", claims["scope"])
	}
	if claims["sub"] != "admin@example.com" {
		t.Errorf("sub = %v", claims["sub"])
	}
	if exp := int64(claims["exp"].(float64)); exp != now.Add(time.Hour).Unix() {
		t.Errorf("exp = %d, want iat+1h", exp)
	}

	// Verify the RS256 signature against the public key.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}

	// Without subject, no sub claim is sent (Google token-endpoint profile).
	jwtNoSub, err := buildJWTAssertion(key, "https://oauth2.example.com/token", "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	claimsNoSub := decodeJWTSegment(t, strings.Split(jwtNoSub, ".")[1])
	if _, present := claimsNoSub["sub"]; present {
		t.Error("sub claim must be absent without subject")
	}
	if _, present := claimsNoSub["scope"]; present {
		t.Error("scope claim must be absent without scopes")
	}
}

func TestOAuth2JWTBearerFlow(t *testing.T) {
	var gotGrant, gotAssertion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotGrant = r.PostFormValue("grant_type")
		gotAssertion = r.PostFormValue("assertion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "svc-token-1", "expires_in": 3600}`))
	}))
	defer srv.Close()

	// token_uri in the key points at the test server; no token_url declared,
	// so the key's own endpoint must be used.
	keyJSON, _ := testServiceAccountJSON(t, srv.URL)
	creds := &realMockCreds{creds: map[string]string{"gsc-sa": keyJSON}}

	auth := NewRestAuth(AuthConfig{
		Type:                     authTypeOAuth2,
		Flow:                     oauth2FlowJWTBearer,
		ServiceAccountCredential: "gsc-sa",
		Scopes:                   []string{"https://www.googleapis.com/auth/webmasters.readonly"},
	}, srv.URL, creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/api", http.NoBody)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(headerAuthorization); got != "Bearer svc-token-1" {
		t.Errorf("Authorization = %q, want Bearer svc-token-1", got)
	}
	if gotGrant != jwtBearerGrantType {
		t.Errorf("grant_type = %q, want %q", gotGrant, jwtBearerGrantType)
	}
	if strings.Count(gotAssertion, ".") != 2 {
		t.Errorf("assertion is not a JWT: %q", gotAssertion)
	}
}

func TestOAuth2AuthorizationCodeRenewsLikeRefreshToken(t *testing.T) {
	var gotGrant, gotRefresh, gotClientID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotGrant = r.PostFormValue("grant_type")
		gotRefresh = r.PostFormValue("refresh_token")
		gotClientID = r.PostFormValue("client_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "user-token-1", "expires_in": 3600}`))
	}))
	defer srv.Close()

	creds := &realMockCreds{creds: map[string]string{
		testCredOAuth2ClientID:     "public-client",
		testCredOAuth2RefreshToken: testOAuth2RefreshValue,
	}}

	auth := NewRestAuth(AuthConfig{
		Type:                   authTypeOAuth2,
		Flow:                   oauth2FlowAuthorizationCode,
		TokenURL:               srv.URL,
		AuthorizeURL:           "https://accounts.example.com/auth",
		ClientIDCredential:     testCredOAuth2ClientID,
		RefreshTokenCredential: testCredOAuth2RefreshToken,
	}, srv.URL, creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/api", http.NoBody)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(headerAuthorization); got != "Bearer user-token-1" {
		t.Errorf("Authorization = %q, want Bearer user-token-1", got)
	}
	if gotGrant != oauth2FlowRefreshToken {
		t.Errorf("grant_type = %q, want refresh_token (runtime renewal)", gotGrant)
	}
	if gotRefresh != testOAuth2RefreshValue || gotClientID != "public-client" {
		t.Errorf("refresh_token/client_id = %q/%q", gotRefresh, gotClientID)
	}
}

func TestParseBytes_OAuth2FlowValidation(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  auth:
    type: oauth2
    %s
  tools:
    t:
      method: GET
      path: /x
`
	tests := []struct {
		name    string
		auth    string
		wantErr string
	}{
		{
			name: "jwt_bearer valid",
			auth: "flow: jwt_bearer\n    service_account_credential: sa\n    scopes: [\"a\"]",
		},
		{
			name:    "jwt_bearer requires service account",
			auth:    "flow: jwt_bearer\n    token_url: https://x/token",
			wantErr: "requires auth.service_account_credential",
		},
		{
			name: "authorization_code valid",
			auth: "flow: authorization_code\n    authorize_url: https://x/auth\n    token_url: https://x/token\n    client_id_credential: cid\n    refresh_token_credential: rt\n    authorization_params:\n      access_type: offline",
		},
		{
			name:    "authorization_code requires refresh_token_credential",
			auth:    "flow: authorization_code\n    authorize_url: https://x/auth\n    client_id_credential: cid",
			wantErr: "requires auth.refresh_token_credential",
		},
		{
			name:    "authorization_code requires authorize_url",
			auth:    "flow: authorization_code\n    client_id_credential: cid\n    refresh_token_credential: rt",
			wantErr: "requires auth.authorize_url",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := strings.Replace(base, "%s", tt.auth, 1)
			spec, err := ParseBytes([]byte(yaml))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(spec.Warnings) != 0 {
				t.Errorf("v0.2 oauth2 fields must not warn, got: %v", spec.Warnings)
			}
		})
	}
}
