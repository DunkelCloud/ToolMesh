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
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"

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

// CredentialOwners divides the credential names among the configured
// entries: a name belongs to the entry whose namespace is the longest
// prefix of its key, where the namespace of an entry is its name
// upper-cased, with "-" as "_", followed by "_". CREDENTIAL_GITHUB_
// ENTERPRISE_TOKEN therefore belongs to an entry "github-enterprise", not
// to an entry "github". Every named entry counts, whatever its transport:
// backends.yaml entries, units and the sub-backends of units. Names whose
// longest namespace is shared by entries with different spellings
// ("my-api", "my_api") belong to none of them. Set replaces the entries;
// every CredentialScope built on the same CredentialOwners sees the change
// on its next decision, so a hot reload that adds an entry takes its names
// away from an entry with a shorter namespace at once.
type CredentialOwners struct {
	table atomic.Pointer[map[string][]string] // namespace prefix → entry names
}

// NewCredentialOwners returns the ownership of the credential names among
// the entries named entryNames.
func NewCredentialOwners(entryNames ...string) *CredentialOwners {
	o := &CredentialOwners{}
	o.Set(entryNames)
	return o
}

// Set replaces the entries the credential names are divided among. Empty
// names are skipped.
func (o *CredentialOwners) Set(entryNames []string) {
	t := map[string][]string{}
	for _, n := range entryNames {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		p := namespacePrefix(n)
		if !slices.Contains(t[p], n) {
			t[p] = append(t[p], n)
		}
	}
	for p := range t {
		sort.Strings(t[p])
	}
	o.table.Store(&t)
}

// owners returns the entries whose namespace is the longest prefix of the
// credential key k, or nil when no namespace is. A nil CredentialOwners
// gives no name an owner.
func (o *CredentialOwners) owners(k string) []string {
	if o == nil {
		return nil
	}
	tp := o.table.Load()
	if tp == nil {
		return nil
	}
	best := ""
	var names []string
	for p, ns := range *tp {
		if len(p) > len(best) && strings.HasPrefix(k, p) {
			best, names = p, ns
		}
	}
	return names
}

// namespacePrefix is the key prefix of an entry's credential namespace.
func namespacePrefix(entryName string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(entryName)), "-", "_") + "_"
}

// CredentialScope is the set of credential names a backend may read. It is
// built from the operator's configuration, never from the DADL: the names
// its entry owns (see CredentialOwners), the names the entry maps with
// env:, and the names its credentials: list allows. A DADL therefore cannot
// read the credentials of another backend by naming them.
type CredentialScope struct {
	entry  string
	owners *CredentialOwners
	names  map[string]bool
}

// NewCredentialScope builds the credential scope of the entry entryName.
// allowed is its credentials: list, env its env: map (keys
// CREDENTIAL_<NAME>), and owners the division of the credential names among
// all configured entries; with nil owners the entry owns no names, and only
// the listed ones are allowed. env: keys are compared in the form
// credentials.CanonicalEnvKey gives them, the form the remapping of the
// entry uses, so a key widens the scope exactly when it remaps the read.
// An entry of either list that names no credential, and two env: keys of
// the same credential, are configuration errors.
func NewCredentialScope(entryName string, allowed []string, env map[string]string, owners *CredentialOwners) (*CredentialScope, error) {
	s := &CredentialScope{
		entry:  strings.TrimSpace(entryName),
		owners: owners,
		names:  map[string]bool{},
	}
	for _, n := range allowed {
		k := credentialKey(n)
		if !validCredentialName(k) {
			return nil, fmt.Errorf("credentials: entry %q is not a credential name: use letters, digits and _ only", n)
		}
		s.names[k] = true
	}
	fromEnv := map[string]string{}
	for k := range env {
		name, ok := strings.CutPrefix(credentials.CanonicalEnvKey(k), credentials.EnvKeyPrefix)
		if !ok {
			continue // no credential key; the remapping never reads it
		}
		if !validCredentialName(name) {
			return nil, fmt.Errorf("env: key %q does not name a credential: use %s<NAME> with letters, digits and _", k, credentials.EnvKeyPrefix)
		}
		if other, dup := fromEnv[name]; dup {
			return nil, fmt.Errorf("env: keys %q and %q name the same credential; keep one", other, k)
		}
		fromEnv[name] = k
		s.names[name] = true
	}
	return s, nil
}

// credentialKey is the form a logical credential name takes in its
// environment variable (CREDENTIAL_<KEY>).
func credentialKey(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

// credentialNameRe is the form of a credential name: letters, digits and
// "_", the characters of an environment variable name.
var credentialNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// validCredentialName reports whether name is a credential name. A DADL
// with any other name is refused at parse, so a name never carries text
// into an error message or a suggested backends.yaml line.
func validCredentialName(name string) bool {
	return credentialNameRe.MatchString(name)
}

// Allows reports whether the backend may read the credential name: it is
// listed for the entry, or the entry alone owns it. A nil scope allows
// every name.
func (s *CredentialScope) Allows(name string) bool {
	if s == nil {
		return true
	}
	k := credentialKey(name)
	if !validCredentialName(k) {
		return false
	}
	if s.names[k] {
		return true
	}
	owners := s.owners.owners(k)
	return len(owners) == 1 && owners[0] == s.entry
}

// ownersOf returns the entries that own the credential name, for messages.
func (s *CredentialScope) ownersOf(name string) []string {
	if s == nil {
		return nil
	}
	return s.owners.owners(credentialKey(name))
}

// ownerNote describes whose namespace a credential name is in.
func ownerNote(owners []string) string {
	switch len(owners) {
	case 0:
		return "in no entry's namespace"
	case 1:
		return fmt.Sprintf("in the namespace of entry %q", owners[0])
	}
	q := make([]string, len(owners))
	for i, o := range owners {
		q[i] = strconv.Quote(o)
	}
	return "in the namespace shared by entries " + strings.Join(q, ", ")
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
		return "", fmt.Errorf("credential %q (%s) is not allowed for backend %q: %w",
			name, ownerNote(s.scope.ownersOf(name)), s.scope.entry, ErrCredentialOutOfScope)
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
	// Credential is the name the entry's credentials: list needs to allow
	// it, or "" when only a change to the DADL can.
	Credential string
	// Host is the entry the allowed_hosts: list needs to allow it, or ""
	// when only a change to the DADL can.
	Host string
	// Owners are the entries whose namespace holds Credential; allowing it
	// lets this backend read a credential of theirs.
	Owners []string
}

// fixLine returns the backends.yaml line that allows v, or "".
func (v ScopeViolation) fixLine() string {
	switch {
	case v.Credential != "":
		return yamlFlowLine("credentials", []string{v.Credential}) + ownerComment([]ScopeViolation{v})
	case v.Host != "":
		return yamlFlowLine("allowed_hosts", []string{v.Host})
	}
	return ""
}

// ownerComment returns a YAML comment naming the entries that own the
// credentials of vs, or "" when no other entry owns one. Entry names are
// quoted, so the comment stays on its line.
func ownerComment(vs []ScopeViolation) string {
	var parts []string
	for _, v := range vs {
		if v.Credential != "" && len(v.Owners) > 0 {
			parts = append(parts, v.Credential+" is "+ownerNote(v.Owners))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "  # " + strings.Join(parts, "; ")
}

// yamlFlowLine renders "key: [item, ...]" with the YAML encoder, so every
// item is quoted where YAML needs it and none can add keys or entries of
// its own.
func yamlFlowLine(key string, items []string) string {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, it := range items {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: it})
	}
	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, seq}}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
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
		if fix := v.fixLine(); fix != "" {
			parts = append(parts, fmt.Sprintf("%s: %s (allow it with `%s` in the backends.yaml entry)", v.Rule, v.What, fix))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s (only a change to the DADL can fix this)", v.Rule, v.What))
		}
	}
	return fmt.Sprintf("backend %q reaches outside the credentials or hosts allowed for it: %s", e.Backend, strings.Join(parts, "; "))
}

// FixLines returns the backends.yaml lines that would allow every violation
// a line can allow, merged per key. They are built from the structured
// Credential and Host fields, never from DADL text.
func (e *ScopeError) FixLines() []string {
	var creds, hosts []string
	var credViolations []ScopeViolation
	seen := map[string]bool{}
	for _, v := range e.Violations {
		switch {
		case v.Credential != "" && !seen["c:"+v.Credential]:
			seen["c:"+v.Credential] = true
			creds = append(creds, v.Credential)
			credViolations = append(credViolations, v)
		case v.Host != "" && !seen["h:"+v.Host]:
			seen["h:"+v.Host] = true
			hosts = append(hosts, v.Host)
		}
	}
	var out []string
	if len(creds) > 0 {
		out = append(out, yamlFlowLine("credentials", creds)+ownerComment(credViolations))
	}
	if len(hosts) > 0 {
		out = append(out, yamlFlowLine("allowed_hosts", hosts))
	}
	return out
}

// credentialRef is a credential name the DADL references, and where.
type credentialRef struct {
	where string
	name  string
}

// credentialPrefix marks a value that names a credential to substitute:
// "credential:<name>".
const credentialPrefix = "credential:" //nolint:gosec // reference marker, not a credential

// walkCredentialRefs calls fn with the name of every "credential:<name>"
// string in v, at any depth.
func walkCredentialRefs(v any, fn func(name string)) {
	switch val := v.(type) {
	case string:
		if name, ok := strings.CutPrefix(val, credentialPrefix); ok {
			fn(name)
		}
	case map[string]any:
		for _, child := range val {
			walkCredentialRefs(child, fn)
		}
	case []any:
		for _, child := range val {
			walkCredentialRefs(child, fn)
		}
	}
}

// validateCredentialNames refuses an auth block with a credential name that
// is not one: every *credential field that is set, and every
// "credential:<name>" in a session login body, whatever the auth type.
func validateCredentialNames(auth AuthConfig) error {
	fields := []credentialRef{
		{"auth.credential", auth.Credential},
		{"auth.username_credential", auth.UsernameCredential},
		{"auth.password_credential", auth.PasswordCredential},
		{"auth.client_id_credential", auth.ClientIDCredential},
		{"auth.client_secret_credential", auth.ClientSecretCredential},
		{"auth.refresh_token_credential", auth.RefreshTokenCredential},
		{"auth.service_account_credential", auth.ServiceAccountCredential},
	}
	if auth.Login != nil {
		walkCredentialRefs(auth.Login.Body, func(name string) {
			fields = append(fields, credentialRef{"auth.login.body", name})
		})
	}
	for _, f := range fields {
		if f.where != "auth.login.body" && f.name == "" {
			continue
		}
		if !validCredentialName(f.name) {
			return fmt.Errorf("%s %q is not a credential name: use letters, digits and _ only", f.where, f.name)
		}
	}
	return nil
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
			walkCredentialRefs(auth.Login.Body, func(name string) { add("auth.login.body", name) })
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
		if !validCredentialName(ref.name) {
			// Parse refuses such a name; a spec built in code gets here.
			violations = append(violations, ScopeViolation{
				Rule: RuleCredentialNamespace,
				What: fmt.Sprintf("%s %q is not a credential name", ref.where, ref.name),
			})
			continue
		}
		if !creds.Allows(ref.name) {
			owners := creds.ownersOf(ref.name)
			violations = append(violations, ScopeViolation{
				Rule:       RuleCredentialNamespace,
				What:       fmt.Sprintf("%s %q (%s)", ref.where, ref.name, ownerNote(owners)),
				Credential: strings.ToLower(ref.name),
				Owners:     owners,
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
			Host: normalizeHost(host),
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
