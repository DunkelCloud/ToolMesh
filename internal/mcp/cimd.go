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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// Client ID metadata documents (draft-ietf-oauth-client-id-metadata-document).
//
// A client that has not registered names itself by an https URL as its
// client_id. The URL serves a JSON document with the client's metadata, and
// the authorization endpoint fetches it instead of looking up a registration.
// Nothing is stored for such a client: the document is kept in a cache of
// this process for a while, the authorization code carries what the token
// endpoint needs.
//
// The fetch is something a request without any credential makes the server
// do, to a URL that request chose. Everything here is bounded for that
// reason: which URLs are fetched, where the connection may go, how long it
// may take, how much is read, how many fetches run at once, and what the
// requester learns about the outcome.

const (
	// clientIDURLPrefix marks a client_id as the URL of a metadata document.
	// The identifiers /register hands out are hex strings, so the two kinds
	// of client never share an identifier.
	clientIDURLPrefix = "https://"

	// maxClientIDURLBytes bounds a client_id URL. It ends up in tokens, in
	// the audit log and in log lines.
	maxClientIDURLBytes = 2048

	// cimdFetchTimeout bounds one fetch as a whole: name resolution,
	// connection, TLS handshake, response header and body.
	cimdFetchTimeout = 5 * time.Second

	// maxCIMDDocumentBytes bounds the document. Documents of real clients
	// are a few hundred bytes; the draft recommends a limit of 5 kB.
	maxCIMDDocumentBytes = 16 << 10

	// maxCIMDHeaderBytes bounds the response header of a fetch. The default
	// of the HTTP client is 10 MB.
	maxCIMDHeaderBytes = 16 << 10

	// cimdCacheMin and cimdCacheMax bound how long a fetched document is
	// used. The response's Cache-Control decides within these bounds. The
	// minimum also holds for a response that asks not to be cached: the
	// login page and its submission are two requests that both need the
	// document, and without a minimum every request to the authorization
	// endpoint would cause a fetch. The maximum is how long a redirect URI
	// that was removed from a document can still be used.
	cimdCacheMin = 5 * time.Minute
	cimdCacheMax = 24 * time.Hour

	// maxCIMDCacheEntries bounds the cache. Anyone can publish documents
	// under any number of URLs.
	maxCIMDCacheEntries = 512

	// maxCIMDFetches bounds the fetches in flight, and with them the
	// connections and memory the fetches of all clients take together.
	maxCIMDFetches = 16

	// cimdUserAgent names the fetcher to the server that hosts a document.
	// It carries no version: the request goes to a host of the requester's
	// choice.
	cimdUserAgent = "ToolMesh"

	// Metadata fields of a client ID metadata document (RFC 7591 names).
	cimdFieldClientName      = "client_name"
	cimdFieldRedirectURIs    = "redirect_uris"
	cimdFieldClientSecret    = "client_secret" //nolint:gosec // metadata field name, not a credential
	cimdFieldSecretExpiresAt = "client_secret_expires_at"
	cimdFieldAuthMethod      = "token_endpoint_auth_method"
	cimdFieldAuthMethods     = "token_endpoint_auth_methods_supported"
	cimdFieldGrantTypes      = "grant_types"
	cimdFieldResponseTypes   = "response_types"
	cimdFieldJWKS            = "jwks"
	cimdFieldJWKSURI         = "jwks_uri"

	// cacheDirectiveNoStore and cacheDirectiveNoCache are the Cache-Control
	// directives of a response that asks not to be kept, or not to be used
	// without asking again.
	cacheDirectiveNoStore = "no-store"
	cacheDirectiveNoCache = "no-cache"

	// sharedSecretMethodPrefix starts the names of the client
	// authentication methods that rest on a shared secret
	// (client_secret_basic, client_secret_post, client_secret_jwt). A
	// metadata document is public, so it cannot declare one.
	sharedSecretMethodPrefix = "client_secret_"
)

// isClientIDURL reports whether clientID names a client by the URL of its
// metadata document.
func isClientIDURL(clientID string) bool {
	return strings.HasPrefix(clientID, clientIDURLPrefix)
}

// clientIDURLError returns why raw cannot be used as the URL of a client ID
// metadata document, or "". issuer is the public URL of this server.
//
// The rules of the draft: https, no user information, no fragment, a path
// other than "/", no dot segments. Stricter than the draft, which only
// advises against it, a query is refused as well: the URL is fetched on
// behalf of a requester nobody knows yet, and without a query it at least
// cannot carry parameters to the endpoint it names. A URL on the host of
// this server is refused, because a file a user stored here would otherwise
// be shown to the next user as this server's own word about a client.
func clientIDURLError(raw, issuer string) string {
	if len(raw) > maxClientIDURLBytes {
		return fmt.Sprintf("it is longer than %d bytes", maxClientIDURLBytes)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return "it must be written in ASCII, without spaces, control characters or backslashes"
		}
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "it is not a URL"
	case u.Scheme != schemeHTTPS || u.Opaque != "" || u.Hostname() == "":
		return "it must be an https URL with a host"
	case u.User != nil:
		return "it must not contain user information"
	case !isPlainASCIIHost(u.Host):
		// The raw URL is ASCII, but a host may hide other characters
		// behind percent-encoding. The login page would show them one way
		// and the connection, after IDNA mapping, would go another.
		return "its host must be written in ASCII (punycode), without percent-encoding"
	case strings.Contains(raw, "#"):
		return "it must not contain a fragment"
	case strings.Contains(raw, "?"):
		return "it must not contain a query"
	case u.Path == "" || u.Path == "/":
		return "it must have a path, such as /oauth/client.json"
	}
	// u.Path is decoded, so "%2e%2e" is caught as well.
	for segment := range strings.SplitSeq(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "its path must not contain the segments . or .."
		}
	}
	if own, err := url.Parse(issuer); err == nil && own.Hostname() != "" && normalizeHost(own.Hostname()) == normalizeHost(u.Hostname()) {
		return "it must not be an address of this server"
	}
	return ""
}

// isPlainASCIIHost reports whether host, as url.Parse returns it, consists
// of ASCII only and carries no percent sign (an IPv6 zone would have one).
func isPlainASCIIHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if c := host[i]; c >= 0x80 || c == '%' {
			return false
		}
	}
	return true
}

// clientIDDisplayHost returns the host (with a non-default port) of a
// client_id URL as the login page names it, or "" when clientID is not such
// a URL.
func clientIDDisplayHost(clientID string) string {
	if !isClientIDURL(clientID) {
		return ""
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// clientIDHostAllowed reports whether the metadata document of clientID may
// be fetched under the configured host allowlist. An empty allowlist allows
// every host.
func clientIDHostAllowed(clientID string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return hostListed(u.Hostname(), allowed)
}

// normalizeHost returns host in the form allowlists compare: lower case,
// without the trailing dot of a fully qualified name.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// hostListed reports whether host matches an entry of allowed. Entries match
// the host name exactly, or any subdomain when written as "*.example.com".
func hostListed(host string, allowed []string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, entry := range allowed {
		if suffix, ok := strings.CutPrefix(entry, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

// redirectListed reports whether redirectURI is one of the redirect URIs a
// metadata document lists. The comparison is that of strings, with the one
// exception OAuth makes for native clients (RFC 8252 section 7.3): a
// loopback redirect URI matches with any port. A native client listens on a
// port it is given when it starts, and its document, written once for every
// installation, cannot name that port. The caller has checked the shape and
// the scheme of redirectURI.
func redirectListed(listed []string, redirectURI string) bool {
	if slices.Contains(listed, redirectURI) {
		return true
	}
	u, err := url.Parse(redirectURI)
	if err != nil || !isLoopbackRedirect(u) || u.User != nil {
		return false
	}
	for _, entry := range listed {
		l, err := url.Parse(entry)
		if err != nil || !isLoopbackRedirect(l) || l.User != nil || redirectURIShapeError(entry, l) != "" {
			continue
		}
		if l.Hostname() == u.Hostname() && l.EscapedPath() == u.EscapedPath() && l.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

// clientMetadata is what the server keeps of a client ID metadata document.
type clientMetadata struct {
	// clientName is the client_name: declared by the client, shown as such.
	clientName string
	// redirectURIs are the redirect URIs the document lists.
	redirectURIs []string
}

// cimdErrorKind sorts the ways a document cannot be obtained by what the
// requester is told.
type cimdErrorKind int

const (
	// cimdUnavailable: no document of this client was obtained. The fetch
	// failed, the answer was not a JSON document, or the document does not
	// name the URL as its client_id. The requester is told only that much.
	// Which of these it was would tell a requester things about hosts only
	// this server can reach, so it goes to the log alone.
	cimdUnavailable cimdErrorKind = iota
	// cimdInvalid: the URL serves the document of this client, and the
	// document cannot be used. The requester is told why; the document is
	// public and names itself.
	cimdInvalid
	// cimdBusy: too many fetches are in flight.
	cimdBusy
)

// cimdError is the error of a fetch.
type cimdError struct {
	kind cimdErrorKind
	// reason says what is wrong, in words of this server: no text read
	// from a response is part of it.
	reason string
	// cause is the underlying error, for the log.
	cause error
}

func (e *cimdError) Error() string {
	if e.cause != nil {
		return e.reason + ": " + e.cause.Error()
	}
	return e.reason
}

func (e *cimdError) Unwrap() error { return e.cause }

// present reports whether a metadata field is there and not null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != jsonTypeNull
}

// parseClientMetadata checks the body fetched from the URL clientID and
// returns what the server keeps of it.
func parseClientMetadata(clientID string, body []byte) (*clientMetadata, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return nil, &cimdError{kind: cimdUnavailable, reason: "the response is not a JSON object"}
	}
	// The document must name the URL it was fetched from, compared as
	// strings. This is what ties a document to its client_id: without it
	// any JSON a host serves anywhere could be passed off as a client.
	var id string
	if err := json.Unmarshal(fields[oauthClientID], &id); err != nil || id != clientID {
		return nil, &cimdError{kind: cimdUnavailable, reason: "client_id in the document is not the URL it was fetched from"}
	}
	invalid := func(reason string) (*clientMetadata, error) {
		return nil, &cimdError{kind: cimdInvalid, reason: reason}
	}

	var name string
	if err := json.Unmarshal(fields[cimdFieldClientName], &name); err != nil || strings.TrimSpace(name) == "" {
		return invalid("client_name is missing")
	}
	if len(name) > maxClientNameBytes {
		return invalid(fmt.Sprintf("client_name is longer than %d bytes", maxClientNameBytes))
	}
	var redirects []string
	if err := json.Unmarshal(fields[cimdFieldRedirectURIs], &redirects); err != nil || len(redirects) == 0 {
		return invalid("redirect_uris is missing or empty")
	}
	if present(fields[cimdFieldClientSecret]) || present(fields[cimdFieldSecretExpiresAt]) {
		return invalid("it contains a client secret, which a public document cannot hold")
	}
	if present(fields[cimdFieldJWKS]) && present(fields[cimdFieldJWKSURI]) {
		return invalid("it contains both jwks and jwks_uri")
	}

	// Clients are public clients here: the token endpoint authenticates
	// none. A document that declares only other methods asks for something
	// this server does not do, and is not quietly served without it.
	var methods []string
	if raw := fields[cimdFieldAuthMethod]; present(raw) {
		var method string
		if err := json.Unmarshal(raw, &method); err != nil {
			return invalid(cimdFieldAuthMethod + " is not a string")
		}
		methods = append(methods, method)
	}
	if raw := fields[cimdFieldAuthMethods]; present(raw) {
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return invalid(cimdFieldAuthMethods + " is not a list of strings")
		}
		methods = append(methods, list...)
	}
	for _, method := range methods {
		if strings.HasPrefix(method, sharedSecretMethodPrefix) {
			return invalid("it declares a client authentication method that rests on a shared secret")
		}
	}
	if len(methods) > 0 && !slices.Contains(methods, tokenAuthMethodNone) {
		return invalid("this server serves public clients only: " + cimdFieldAuthMethod + " must be none or absent")
	}

	for _, check := range []struct{ field, want string }{
		{cimdFieldGrantTypes, oauthGrantAuthCode},
		{cimdFieldResponseTypes, oauthCode},
	} {
		raw := fields[check.field]
		if !present(raw) {
			continue // RFC 7591 defaults: authorization_code and code
		}
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil || !slices.Contains(list, check.want) {
			return invalid(check.field + " does not include " + check.want)
		}
	}

	return &clientMetadata{clientName: name, redirectURIs: redirects}, nil
}

// cimdLifetime returns how long a document fetched with the response header
// h is used: what Cache-Control allows (RFC 9111: max-age less the Age the
// response already has), within cimdCacheMin and cimdCacheMax.
func cimdLifetime(h http.Header) time.Duration {
	const maxSeconds = int64(cimdCacheMax / time.Second)
	seconds := func(v string) (int64, bool) {
		n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(v), `"`), 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		return min(n, maxSeconds), true
	}

	maxAge := int64(-1)
	for _, line := range h.Values("Cache-Control") {
		for directive := range strings.SplitSeq(line, ",") {
			name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case cacheDirectiveNoStore, cacheDirectiveNoCache:
				return cimdCacheMin
			case "max-age":
				if n, ok := seconds(value); ok {
					maxAge = n
				}
			}
		}
	}
	if maxAge < 0 {
		return cimdCacheMin
	}
	if age, ok := seconds(h.Get("Age")); ok {
		maxAge -= age
	}
	return min(max(time.Duration(maxAge)*time.Second, cimdCacheMin), cimdCacheMax)
}

// cimdTransport returns the transport documents are fetched through. It
// resolves the host itself and connects only when every address is a public
// one, to the address it checked (backend.SSRFSafeTransport), so a name
// that resolves to a loopback, private, link-local or otherwise reserved
// address is not reached, and neither is one that changes its answer
// between the check and the connection. It uses no proxy and keeps no
// connection open after a fetch.
func cimdTransport() *http.Transport {
	tr := backend.SSRFSafeTransport(cimdFetchTimeout, false, false)
	tr.TLSHandshakeTimeout = cimdFetchTimeout
	tr.ResponseHeaderTimeout = cimdFetchTimeout
	tr.MaxResponseHeaderBytes = maxCIMDHeaderBytes
	tr.DisableKeepAlives = true
	return tr
}

// cimdHTTPClient returns the client documents are fetched with, on the given
// transport. It follows no redirect: the document must be served by the URL
// that is the client_id, and a redirect could lead anywhere, also back to
// http. It has no cookie jar.
func cimdHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   cimdFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// cimdFetcher fetches client ID metadata documents and keeps them for their
// lifetime. The cache belongs to this process. Another replica fetches the
// document itself, so an authorization that starts on one replica and
// continues on another needs no shared state.
type cimdFetcher struct {
	client *http.Client
	now    func() time.Time

	// slots holds one token per fetch in flight.
	slots chan struct{}

	mu       sync.Mutex
	cache    map[string]cimdEntry
	inflight map[string]*cimdCall
}

// cimdEntry is a cached document.
type cimdEntry struct {
	metadata *clientMetadata
	expires  time.Time
}

// cimdCall is a fetch in flight that later requests for the same URL wait
// for instead of starting their own.
type cimdCall struct {
	done     chan struct{}
	metadata *clientMetadata
	err      error
}

// newCIMDFetcher returns a fetcher that uses client for its requests.
func newCIMDFetcher(client *http.Client) *cimdFetcher {
	return &cimdFetcher{
		client:   client,
		now:      time.Now,
		slots:    make(chan struct{}, maxCIMDFetches),
		cache:    make(map[string]cimdEntry),
		inflight: make(map[string]*cimdCall),
	}
}

// cached returns the document of clientID when the cache holds one that has
// not run out.
func (f *cimdFetcher) cached(clientID string) (*clientMetadata, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cachedLocked(clientID)
}

func (f *cimdFetcher) cachedLocked(clientID string) (*clientMetadata, bool) {
	entry, ok := f.cache[clientID]
	if !ok {
		return nil, false
	}
	if !f.now().Before(entry.expires) {
		delete(f.cache, clientID)
		return nil, false
	}
	return entry.metadata, true
}

// storeLocked puts a document into the cache. A full cache first gives up
// what has run out, then the entry closest to running out.
func (f *cimdFetcher) storeLocked(clientID string, metadata *clientMetadata, lifetime time.Duration) {
	now := f.now()
	if _, ok := f.cache[clientID]; !ok && len(f.cache) >= maxCIMDCacheEntries {
		var oldest string
		var oldestExpires time.Time
		for key, entry := range f.cache {
			if !now.Before(entry.expires) {
				delete(f.cache, key)
				continue
			}
			if oldest == "" || entry.expires.Before(oldestExpires) {
				oldest, oldestExpires = key, entry.expires
			}
		}
		if len(f.cache) >= maxCIMDCacheEntries {
			delete(f.cache, oldest)
		}
	}
	f.cache[clientID] = cimdEntry{metadata: metadata, expires: now.Add(lifetime)}
}

// fetch returns the document of clientID, from the cache or from its URL.
// Requests for one URL that arrive while it is being fetched share that
// fetch. Only a document that passed every check is cached; a failure is
// never remembered. The caller has checked clientID with clientIDURLError.
func (f *cimdFetcher) fetch(ctx context.Context, clientID string) (*clientMetadata, error) {
	f.mu.Lock()
	if metadata, ok := f.cachedLocked(clientID); ok {
		f.mu.Unlock()
		return metadata, nil
	}
	if call, ok := f.inflight[clientID]; ok {
		f.mu.Unlock()
		select {
		case <-call.done:
			return call.metadata, call.err
		case <-ctx.Done():
			return nil, &cimdError{kind: cimdUnavailable, reason: "the request ended before the document arrived", cause: ctx.Err()}
		}
	}
	select {
	case f.slots <- struct{}{}:
	default:
		f.mu.Unlock()
		return nil, &cimdError{kind: cimdBusy, reason: "too many documents are being fetched"}
	}
	call := &cimdCall{
		done: make(chan struct{}),
		err:  &cimdError{kind: cimdUnavailable, reason: "the fetch did not complete"},
	}
	f.inflight[clientID] = call
	f.mu.Unlock()

	var lifetime time.Duration
	defer func() {
		f.mu.Lock()
		delete(f.inflight, clientID)
		if call.err == nil {
			f.storeLocked(clientID, call.metadata, lifetime)
		}
		f.mu.Unlock()
		<-f.slots
		close(call.done)
	}()

	// The fetch serves everyone waiting for this URL, so it does not end
	// when the request that started it does. Its own timeout bounds it.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cimdFetchTimeout)
	defer cancel()
	call.metadata, lifetime, call.err = f.get(fetchCtx, clientID)
	return call.metadata, call.err
}

// get fetches and checks the document at the URL clientID.
func (f *cimdFetcher) get(ctx context.Context, clientID string) (*clientMetadata, time.Duration, error) {
	unavailable := func(reason string, cause error) error {
		return &cimdError{kind: cimdUnavailable, reason: reason, cause: cause}
	}

	// Fetching a URL the requester names is what this function is for. What
	// bounds it: the caller has checked the URL (clientIDURLError), and the
	// transport of f.client connects to public addresses only.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, http.NoBody) //nolint:gosec // G704: see above
	if err != nil {
		return nil, 0, unavailable("the request could not be built", nil)
	}
	req.Header.Set("Accept", mimeJSON)
	req.Header.Set("User-Agent", cimdUserAgent)

	resp, err := f.client.Do(req) //nolint:gosec // G704: see above
	if err != nil {
		// A url.Error repeats the whole URL; the log line has it already.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, 0, unavailable("the request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Also every redirect: the client follows none.
		return nil, 0, unavailable(fmt.Sprintf("the server answered with status %d", resp.StatusCode), nil)
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil ||
		(mediaType != mimeJSON && (!strings.HasPrefix(mediaType, "application/") || !strings.HasSuffix(mediaType, "+json"))) {
		return nil, 0, unavailable("the response is not served as JSON", nil)
	}
	if resp.ContentLength > maxCIMDDocumentBytes {
		return nil, 0, unavailable(fmt.Sprintf("the document is longer than %d bytes", maxCIMDDocumentBytes), nil)
	}
	// One byte more than the limit tells a document at the limit from one
	// over it when the response does not state its length.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDDocumentBytes+1))
	if err != nil {
		return nil, 0, unavailable("the response could not be read", err)
	}
	if len(body) > maxCIMDDocumentBytes {
		return nil, 0, unavailable(fmt.Sprintf("the document is longer than %d bytes", maxCIMDDocumentBytes), nil)
	}

	metadata, err := parseClientMetadata(clientID, body)
	if err != nil {
		return nil, 0, err
	}
	return metadata, cimdLifetime(resp.Header), nil
}
