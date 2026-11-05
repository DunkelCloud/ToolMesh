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
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Rules a DADL can break against the binding of its backend.
const (
	// RuleCredentialNamespace: the DADL reads a credential outside the
	// namespace of its backends.yaml entry.
	RuleCredentialNamespace = "credential_namespace" //nolint:gosec // rule name, not a credential
	// RuleHostBinding: the DADL sends credentials to a host outside the
	// hosts of its backend.
	RuleHostBinding = "host_binding"
)

// ErrCredentialOutOfScope is returned when a backend asks for a credential
// outside its CredentialScope.
var ErrCredentialOutOfScope = errors.New("credential outside the backend's scope")

// NoCredential is the credential name DADLs of APIs without authentication
// use in their required auth block ("credential: none"). It names no
// secret: it is never looked up and needs no binding.
const NoCredential = "none"

// isNoCredential reports whether name is the NoCredential placeholder.
func isNoCredential(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), NoCredential)
}

// CredentialScope is the set of credential names a backend may read. It is
// built from the operator's backends.yaml entry, never from the DADL: the
// namespace CREDENTIAL_<ENTRY>_*, where ENTRY is the entry name upper-cased
// with "-" as "_", the names the entry maps with env:, and the names its
// credentials: list allows. A DADL therefore cannot read the credentials of
// another backend by naming them.
type CredentialScope struct {
	entry  string
	prefix string
	names  map[string]bool
}

// NewCredentialScope builds the credential scope of the backends.yaml entry
// entryName. allowed is its credentials: list, env its env: map (keys
// CREDENTIAL_<NAME>).
func NewCredentialScope(entryName string, allowed []string, env map[string]string) *CredentialScope {
	s := &CredentialScope{
		entry:  entryName,
		prefix: strings.ReplaceAll(strings.ToUpper(entryName), "-", "_") + "_",
		names:  map[string]bool{},
	}
	for _, n := range allowed {
		if k := credentialKey(n); k != "" {
			s.names[k] = true
		}
	}
	for k := range env {
		if name, ok := strings.CutPrefix(strings.ToUpper(strings.TrimSpace(k)), "CREDENTIAL_"); ok && name != "" {
			s.names[name] = true
		}
	}
	return s
}

// credentialKey is the form a logical credential name takes in its
// environment variable (CREDENTIAL_<KEY>).
func credentialKey(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

// Allows reports whether the backend may read the credential name. A nil
// scope allows every name.
func (s *CredentialScope) Allows(name string) bool {
	if s == nil {
		return true
	}
	k := credentialKey(name)
	return k != "" && (strings.HasPrefix(k, s.prefix) || s.names[k])
}

// scopedStore refuses reads outside a CredentialScope. The refusal is no
// ErrCredentialNotFound, so a call fails instead of going out without auth.
type scopedStore struct {
	inner credentials.CredentialStore
	scope *CredentialScope
}

// Get implements credentials.CredentialStore. The NoCredential placeholder
// is answered as not found without a lookup, so such a call goes out without
// auth as it always has.
func (s *scopedStore) Get(ctx context.Context, name string, tenant credentials.TenantInfo) (string, error) {
	if isNoCredential(name) {
		return "", fmt.Errorf("credential %q is the no-secret placeholder: %w", name, credentials.ErrCredentialNotFound)
	}
	if !s.scope.Allows(name) {
		return "", fmt.Errorf("credential %q is not allowed for backend %q: %w", name, s.scope.entry, ErrCredentialOutOfScope)
	}
	return s.inner.Get(ctx, name, tenant)
}

// Healthy implements credentials.CredentialStore.
func (s *scopedStore) Healthy(ctx context.Context) error {
	return s.inner.Healthy(ctx)
}

// HostScope is the set of hosts a backend's credentials may be sent to:
// the host of the effective base_url, every host of its registrable domain
// (eTLD+1 by the public suffix list), and the hosts of the backends.yaml
// entry's allowed_hosts: list ("api.example.com" or "*.example.com"). The
// effective base_url is the backends.yaml url when the entry sets one.
type HostScope struct {
	hosts     map[string]bool
	domains   map[string]bool
	wildcards []string // ".example.com" for "*.example.com"
}

// NewHostScope builds the host scope for a backend whose effective base URL
// is baseURL; allowed is the entry's allowed_hosts: list.
func NewHostScope(baseURL string, allowed []string) (*HostScope, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("base_url %q has no host", baseURL)
	}
	s := &HostScope{hosts: map[string]bool{}, domains: map[string]bool{}}
	base := normalizeHost(u.Hostname())
	s.hosts[base] = true
	if d := registrableDomain(base); d != "" {
		s.domains[d] = true
	}
	for _, a := range allowed {
		a = normalizeHost(strings.TrimSpace(a))
		if suffix, ok := strings.CutPrefix(a, "*."); ok && suffix != "" {
			s.wildcards = append(s.wildcards, "."+suffix)
			continue
		}
		if a != "" {
			s.hosts[a] = true
		}
	}
	return s, nil
}

// Allows reports whether credentials may be sent to host. A nil scope
// allows every host.
func (s *HostScope) Allows(host string) bool {
	if s == nil {
		return true
	}
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if s.hosts[h] {
		return true
	}
	for _, w := range s.wildcards {
		if strings.HasSuffix(h, w) {
			return true
		}
	}
	d := registrableDomain(h)
	return d != "" && s.domains[d]
}

// normalizeHost lower-cases a host name and drops a trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// registrableDomain returns the eTLD+1 of a host name, or "" for an IP
// address or a name without one (such as "localhost"). IP addresses never
// share a domain: the public suffix list would read "10.0.0.5" as a name.
func registrableDomain(host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return d
}

// ScopeViolation is one place where a DADL reaches outside the credentials
// or hosts of its backend.
type ScopeViolation struct {
	// Rule is RuleCredentialNamespace or RuleHostBinding.
	Rule string
	// What names the DADL field and the credential or host.
	What string
	// Fix is the backends.yaml line that allows it, or "" when only a
	// change to the DADL can.
	Fix string
}

// ScopeError lists every violation of one backend; such a backend is not
// loaded.
type ScopeError struct {
	Backend    string
	Violations []ScopeViolation
}

// Error implements error.
func (e *ScopeError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		if v.Fix != "" {
			parts = append(parts, fmt.Sprintf("%s: %s (allow it with `%s` in the backends.yaml entry)", v.Rule, v.What, v.Fix))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s (only a change to the DADL can fix this)", v.Rule, v.What))
		}
	}
	return fmt.Sprintf("backend %q reaches outside the credentials or hosts allowed for it: %s", e.Backend, strings.Join(parts, "; "))
}

// FixLines returns the backends.yaml lines that would allow every violation
// a line can allow, merged per key.
func (e *ScopeError) FixLines() []string {
	var creds, hosts []string
	seen := map[string]bool{}
	for _, v := range e.Violations {
		if v.Fix == "" || seen[v.Fix] {
			continue
		}
		seen[v.Fix] = true
		inner := strings.TrimSuffix(v.Fix[strings.Index(v.Fix, "[")+1:], "]")
		switch v.Rule {
		case RuleCredentialNamespace:
			creds = append(creds, inner)
		case RuleHostBinding:
			hosts = append(hosts, inner)
		}
	}
	var out []string
	if len(creds) > 0 {
		out = append(out, "credentials: ["+strings.Join(creds, ", ")+"]")
	}
	if len(hosts) > 0 {
		out = append(out, "allowed_hosts: ["+strings.Join(hosts, ", ")+"]")
	}
	return out
}

// credentialRef is a credential name the DADL references, and where.
type credentialRef struct {
	where string
	name  string
}

// staticCredentialRefs lists the credential names the runtime reads for the
// configured auth type: the fields of that type and "credential:<name>"
// strings in a session login body.
func staticCredentialRefs(auth AuthConfig) []credentialRef {
	var refs []credentialRef
	add := func(where, name string) {
		if strings.TrimSpace(name) != "" && !isNoCredential(name) {
			refs = append(refs, credentialRef{where: where, name: name})
		}
	}
	t := strings.ToLower(auth.Type)
	if t == authTypeAPIKeyAlias {
		t = authTypeAPIKey
	}
	switch t {
	case authTypeBearer, authTypeAPIKey:
		add("auth.credential", auth.Credential)
	case authTypeBasic:
		add("auth.username_credential", auth.UsernameCredential)
		add("auth.password_credential", auth.PasswordCredential)
	case authTypeOAuth2:
		add("auth.client_id_credential", auth.ClientIDCredential)
		add("auth.client_secret_credential", auth.ClientSecretCredential)
		add("auth.refresh_token_credential", auth.RefreshTokenCredential)
		add("auth.service_account_credential", auth.ServiceAccountCredential)
	case authTypeSession:
		if auth.Login != nil {
			var walk func(v any)
			walk = func(v any) {
				switch val := v.(type) {
				case string:
					if name, ok := strings.CutPrefix(val, "credential:"); ok {
						add("auth.login.body", name)
					}
				case map[string]any:
					for _, child := range val {
						walk(child)
					}
				case []any:
					for _, child := range val {
						walk(child)
					}
				}
			}
			walk(auth.Login.Body)
		}
	}
	return refs
}

// absoluteURLHost returns the host of raw when it is an absolute http(s)
// URL, judged by its "scheme://authority" part alone so that placeholders
// in the path do not matter.
func absoluteURLHost(raw string) (string, bool) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return "", false
	}
	scheme := strings.ToLower(raw[:i])
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	authority := raw[i+3:]
	if j := strings.IndexAny(authority, "/?#"); j >= 0 {
		authority = authority[:j]
	}
	u, err := url.Parse(scheme + "://" + authority)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	return u.Hostname(), true
}

// CheckScope checks everything the DADL names statically against the
// backend's scopes: the credentials its auth type reads (including
// "credential:<name>" in a session login body), and the hosts of base_url,
// token_url, absolute tool paths, an absolute health check path and the
// session login URL. It returns a *ScopeError listing every violation, or
// nil. spec.Backend.BaseURL must be the effective base URL.
func CheckScope(spec *Spec, creds *CredentialScope, hosts *HostScope) error {
	var violations []ScopeViolation
	for _, ref := range staticCredentialRefs(spec.Backend.Auth) {
		if !creds.Allows(ref.name) {
			violations = append(violations, ScopeViolation{
				Rule: RuleCredentialNamespace,
				What: fmt.Sprintf("%s %q", ref.where, ref.name),
				Fix:  fmt.Sprintf("credentials: [%s]", ref.name),
			})
		}
	}
	checkURL := func(where, raw string) {
		host, ok := absoluteURLHost(raw)
		if !ok || hosts.Allows(host) {
			return
		}
		violations = append(violations, ScopeViolation{
			Rule: RuleHostBinding,
			What: fmt.Sprintf("%s host %q", where, host),
			Fix:  fmt.Sprintf("allowed_hosts: [%s]", normalizeHost(host)),
		})
	}
	checkURL("base_url", spec.Backend.BaseURL)
	checkURL("auth.token_url", spec.Backend.Auth.TokenURL)
	for name, tool := range spec.Backend.Tools {
		checkURL(fmt.Sprintf("tool %q path", name), tool.Path)
	}
	if spec.Backend.Health != nil {
		checkURL("health.path", spec.Backend.Health.Path)
	}
	if strings.EqualFold(spec.Backend.Auth.Type, authTypeSession) && spec.Backend.Auth.Login != nil {
		if _, err := sessionLoginURL(spec.Backend.BaseURL, spec.Backend.Auth.Login.Path); err != nil {
			violations = append(violations, ScopeViolation{Rule: RuleHostBinding, What: "auth.login.path: " + err.Error()})
		}
	}
	if len(violations) == 0 {
		return nil
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].What < violations[j].What })
	return &ScopeError{Backend: spec.Backend.Name, Violations: violations}
}
