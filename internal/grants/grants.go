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
// short id until an approver approves or denies it, or it lapses. An approved
// request becomes a grant of the kit to the caller that asked, the requesting
// user as the caller it connected as, until the grant ends. Requests and
// grants live in a [Store] that forgets them when they expire, so a grant
// ends without anything to clean up and revoking it is deleting it. The
// authorization engine stays the only place that decides: at every check the
// caller's granted kits are passed to it ([Service.HeldKits]).
package grants

import (
	"crypto/rand"
	"encoding/base32"
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
	// connected as (an API key's caller_id or an OAuth client).
	UserID     string `json:"user_id"`
	CallerID   string `json:"caller_id"`
	CallerName string `json:"caller_name,omitempty"`
	CompanyID  string `json:"company_id,omitempty"`

	// Reason is the requester's own statement; nothing verifies it.
	Reason string `json:"reason"`
	// TTL is how long the kit is granted for, counted from the approval.
	TTL         time.Duration `json:"ttl"`
	RequestedAt time.Time     `json:"requested_at"`

	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`

	// ExpiresAt is when a pending request lapses or an active grant ends.
	ExpiresAt time.Time `json:"expires_at"`
}

// Subject identifies whom a grant is for.
type Subject struct {
	UserID   string
	CallerID string
}

// Subject returns whom the grant is for.
func (g Grant) Subject() Subject {
	return Subject{UserID: g.UserID, CallerID: g.CallerID}
}

// key renders the subject as one string. Both parts are escaped, so the
// separator is the only '|' and distinct subjects never share a key.
func (s Subject) key() string {
	return url.QueryEscape(s.UserID) + "|" + url.QueryEscape(s.CallerID)
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
