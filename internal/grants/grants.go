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

// Package grants lets a caller ask for a kit and an approver grant it for a
// limited time.
//
// A caller asks with the meta-tool request_grant; the request waits under a
// short id until an approver approves or denies it, or it lapses. Approvers
// decide on the approver API with a key of their own, or on the approval
// page by signing a statement of what they approve with the key of their
// BIP-322 address; either way an approver can grant part of the kit and for
// less time than asked. An approved request becomes a grant of the kit to
// the caller that asked, the requesting user as the caller it connected as,
// until the grant ends. Requests and
// grants live in a [Store] that forgets them when they expire, so a grant
// ends without anything to clean up and revoking it is deleting it. The
// authorization engine stays the only place that decides: at every check the
// caller's granted kits are passed to it ([Service.HeldKits]).
package grants

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// States of a Grant.
const (
	// StatePending: the request waits for an approver.
	StatePending = "pending"
	// StateActive: an approver approved it, the caller holds the kit.
	StateActive = "active"
)

// Grant is a request for a kit and, once an approver approved it, the grant
// of the kit. It keeps its id from the request to the end of the grant.
type Grant struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Kit   string `json:"kit"`

	// The caller the kit is for: the requesting user as the caller it
	// connected as (an API key's caller_id or an OAuth client). CallerName
	// is the caller's own, unverified, name for itself.
	UserID     string `json:"user_id"`
	CallerID   string `json:"caller_id"`
	CallerName string `json:"caller_name,omitempty"`
	CompanyID  string `json:"company_id,omitempty"`
	// GrantKey, when set, binds the grant to one credential instead of to
	// CallerID: an API key without caller_id ([userctx.UserContext.GrantKey]).
	GrantKey string `json:"grant_key,omitempty"`

	// Reason is the requester's own statement; nothing verifies it.
	Reason string `json:"reason"`
	// TTL is how long the kit is granted for, counted from the approval.
	TTL         time.Duration `json:"ttl"`
	RequestedAt time.Time     `json:"requested_at"`

	// Nonce is a random value of the request. A signed approval names it,
	// so that a signature approves this one request and no other.
	Nonce string `json:"nonce,omitempty"`
	// Coverage tells for each entry of the kit how many tools it covers and
	// how many of them the caller could not call when it asked. ToolMesh
	// computes it; nil when it could not.
	Coverage []EntryCoverage `json:"coverage,omitempty"`

	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`
	// ApprovedWith is how the approver approved: ApprovedWithKey or
	// ApprovedWithSignature.
	ApprovedWith string `json:"approved_with,omitempty"`
	// Part, when set, is the part of the kit the approver granted: these
	// entries only. Nil for the whole kit.
	Part *Part `json:"part,omitempty"`

	// ExpiresAt is when a pending request lapses or an active grant ends.
	ExpiresAt time.Time `json:"expires_at"`
}

// How an approver approved a request (Grant.ApprovedWith).
const (
	// ApprovedWithKey: with an approver key on the approver API.
	ApprovedWithKey = "key"
	// ApprovedWithSignature: with a BIP-322 signature on the approval page.
	ApprovedWithSignature = "signature"
)

// Part is the part of a kit an approver granted when not the whole kit: some
// of its entries, the scopes of its grants and names of its tools as the kit
// lists them.
type Part struct {
	Grants []string `json:"grants,omitempty"`
	Tools  []string `json:"tools,omitempty"`
}

// EntryCoverage is what one entry of a kit gives the caller.
type EntryCoverage struct {
	// Entry is a scope of the kit's grants or, with Tool set, a tool it lists.
	Entry string `json:"entry"`
	Tool  bool   `json:"tool,omitempty"`
	// Access is the access classification of a tool entry.
	Access string `json:"access,omitempty"`
	// Tools is how many tools the entry covers, New how many of them the
	// caller could not call before.
	Tools int `json:"tools"`
	New   int `json:"new"`
}

// Fingerprint returns a short digest of the request (id, nonce, kit, whom it
// is for, duration and reason) in four groups of four characters. The answer
// of request_grant and the approval page show it, so that whoever approves
// can check over a second channel that the page shows the request the agent
// made.
func (g Grant) Fingerprint() string {
	h := sha256.New()
	for _, f := range []string{"toolmesh grant request", g.ID, g.Nonce, g.Kit, g.UserID, g.Subject().Binding, FormatTTL(g.TTL), g.Reason} {
		_, _ = fmt.Fprintf(h, "%d:%s\n", len(f), f)
	}
	s := strings.ToUpper(hex.EncodeToString(h.Sum(nil)[:8]))
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// newNonce returns 128 random bits as hex.
func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate request nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Subject identifies whom a grant is for: the user, as the connection it is
// bound to.
type Subject struct {
	UserID string
	// Binding is the caller id, or the grant key of an API key without
	// caller_id ([userctx.UserContext.GrantBinding]).
	Binding string
}

// Subject returns whom the grant is for.
func (g Grant) Subject() Subject {
	binding := g.CallerID
	if g.GrantKey != "" {
		binding = g.GrantKey
	}
	return Subject{UserID: g.UserID, Binding: binding}
}

// key renders the subject as one string. Both parts are escaped, so the
// separator is the only '|' and distinct subjects never share a key.
func (s Subject) key() string {
	return url.QueryEscape(s.UserID) + "|" + url.QueryEscape(s.Binding)
}

// idEncoding renders grant ids in lower case without padding.
var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// idBytes is the randomness of a grant id: 50 bits in 10 characters. The id
// is short enough to read out and type; it is not a secret, as approving
// takes an approver's key.
const idBytes = 7

// newID returns a random grant id of 10 characters.
func newID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate grant id: %w", err)
	}
	return strings.ToLower(idEncoding.EncodeToString(b))[:10], nil
}

// FormatTTL renders a duration without zero units ("4h", "90m"); "" for zero
// or less.
func FormatTTL(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}

// ParseTTL parses a duration such as "4h" or "90m". An empty string is zero:
// the kit's default applies.
func ParseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("ttl %q: give a positive duration such as \"30m\" or \"4h\"", s)
	}
	return d, nil
}
