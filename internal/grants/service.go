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

package grants

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/google/uuid"
)

// Limits and defaults of requests and grants.
const (
	// DefaultTTL is how long a kit without ttl_default is granted when the
	// request names no duration.
	DefaultTTL = time.Hour
	// MaxTTL is the longest a kit without ttl_max is granted for.
	MaxTTL = authz.KitTTLLimit
	// RequestTTL is how long a request waits for an approver.
	RequestTTL = 30 * time.Minute
	// MaxPending is how many requests one caller may have waiting at a time.
	MaxPending = 5
	// MaxReasonLen bounds the reason of a request, in characters.
	MaxReasonLen = 500
	// MaxCallerNameLen bounds the caller name stored with a request, in
	// characters. An OAuth client chooses its own name.
	MaxCallerNameLen = 128
)

// Names under which the grant lifecycle is recorded in the audit trail.
const (
	// ToolRequestGrant is the meta-tool a caller asks for a kit with.
	ToolRequestGrant = "request_grant"
	auditApprove     = "grant_approve"
	auditDeny        = "grant_deny"
	auditRevoke      = "grant_revoke"
	auditBackend     = "toolmesh"
)

// Audit statuses of grant actions.
const (
	statusSuccess = "success"
	statusError   = "error"
)

// ErrInvalid marks an error in what a caller or approver asked for, as
// opposed to a failure of the store. errors.Is reports such errors as
// ErrInvalid; their message is meant for whoever asked.
var ErrInvalid = errors.New("invalid grant request")

// invalidError is an error in what was asked for.
type invalidError struct{ msg string }

// Error returns the message for whoever asked.
func (e invalidError) Error() string { return e.msg }

// Is reports the error as ErrInvalid.
func (e invalidError) Is(target error) bool { return target == ErrInvalid }

// invalidf returns an error that counts as ErrInvalid.
func invalidf(format string, args ...any) error {
	return invalidError{msg: fmt.Sprintf(format, args...)}
}

// Options configures a Service.
type Options struct {
	Store     Store
	Kits      authz.KitCatalog
	Approvers authz.ApproverRegistry
	// Audit records every request, approval, denial and revocation; nil
	// records nothing.
	Audit  audit.AuditStore
	Logger *slog.Logger
}

// Service handles requests for kits and the grants that follow from them.
type Service struct {
	store     Store
	kits      authz.KitCatalog
	approvers authz.ApproverRegistry
	audit     audit.AuditStore
	logger    *slog.Logger
	now       func() time.Time
}

// New returns a service with the given options.
func New(opts Options) *Service {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		store:     opts.Store,
		kits:      opts.Kits,
		approvers: opts.Approvers,
		audit:     opts.Audit,
		logger:    logger,
		now:       time.Now,
	}
}

// Kits returns the kits in effect, sorted by name.
func (s *Service) Kits() []authz.Kit {
	if s.kits == nil {
		return nil
	}
	return s.kits.Kits()
}

// kit returns the kit with the name.
func (s *Service) kit(name string) (authz.Kit, bool) {
	for _, k := range s.Kits() {
		if k.Name == name {
			return k, true
		}
	}
	return authz.Kit{}, false
}

// HasApprovers reports whether anyone may approve requests.
func (s *Service) HasApprovers() bool {
	return s.approvers != nil && len(s.approvers.Approvers()) > 0
}

// Approver returns the approver whose key this is.
func (s *Service) Approver(key string) (authz.Approver, bool) {
	if s.approvers == nil || key == "" {
		return authz.Approver{}, false
	}
	sum := sha256.Sum256([]byte(key))
	got := []byte(hex.EncodeToString(sum[:]))
	var found authz.Approver
	ok := false
	// Every entry is compared, so the time taken does not tell which one
	// matched.
	for _, a := range s.approvers.Approvers() {
		if subtle.ConstantTimeCompare(got, []byte(a.KeySHA256)) == 1 {
			found, ok = a, true
		}
	}
	return found, ok
}

// RequestInput is what a caller asks for.
type RequestInput struct {
	Kit    string
	Reason string
	// TTL as a duration ("4h"); empty for the kit's default.
	TTL string
}

// RequestResult is the outcome of a request.
type RequestResult struct {
	Grant Grant
	// Existing is set when the caller already had a pending request for the
	// kit; Grant is that request.
	Existing bool
	// Capped is set when the duration asked for exceeded the kit's maximum
	// and was cut to it.
	Capped bool
	// HeldUntil is when the caller's current grant of the kit ends, zero
	// when it holds none.
	HeldUntil time.Time
}

// Request records the caller's request for a kit. Every call is audited.
func (s *Service) Request(ctx context.Context, uc *userctx.UserContext, in RequestInput) (RequestResult, error) {
	start := s.now()
	res, err := s.request(ctx, uc, in)
	entry := s.entry(ToolRequestGrant, start, res.Grant)
	if uc != nil {
		entry.UserID, entry.CompanyID, entry.CallerID, entry.CallerName, entry.CallerClass = uc.UserID, uc.CompanyID, uc.CallerID, uc.CallerName, uc.CallerClass
	}
	entry.Params = map[string]any{"kit": in.Kit, "reason": in.Reason, "ttl": in.TTL}
	if res.Existing {
		entry.Metadata["existing"] = "true"
	}
	s.record(ctx, entry, err)
	return res, err
}

func (s *Service) request(ctx context.Context, uc *userctx.UserContext, in RequestInput) (RequestResult, error) {
	if uc == nil || !uc.Authenticated || uc.UserID == "" {
		return RequestResult{}, invalidf("only an authenticated caller can ask for a kit")
	}
	name := strings.TrimSpace(in.Kit)
	if name == "" {
		return RequestResult{}, invalidf("name the kit to ask for; %s lists the kits that cover the tools your task needs", "tell_me_my_rights")
	}
	kit, ok := s.kit(name)
	if !ok {
		return RequestResult{}, invalidf("there is no kit %q; tell_me_my_rights lists the kits that cover the tools your task needs", name)
	}
	if !s.HasApprovers() {
		return RequestResult{}, invalidf("no approver is configured in this ToolMesh, so no kit can be granted; ask its administrator")
	}
	reason, err := cleanReason(in.Reason)
	if err != nil {
		return RequestResult{}, err
	}
	asked, err := ParseTTL(in.TTL)
	if err != nil {
		return RequestResult{}, invalidf("%s", err)
	}
	ttl, capped := kitTTL(kit, asked)

	res := RequestResult{Capped: capped}
	active, err := s.store.ForSubject(ctx, StateActive, Subject{UserID: uc.UserID, Binding: uc.GrantBinding()})
	if err != nil {
		return RequestResult{}, err
	}
	for _, g := range active {
		if g.Kit == kit.Name && g.ExpiresAt.After(res.HeldUntil) {
			res.HeldUntil = g.ExpiresAt
		}
	}

	id, err := newID()
	if err != nil {
		return RequestResult{}, err
	}
	now := s.now()
	g := Grant{
		ID:          id,
		State:       StatePending,
		Kit:         kit.Name,
		UserID:      uc.UserID,
		CallerID:    uc.CallerID,
		CallerName:  truncateRunes(cleanText(uc.CallerName), MaxCallerNameLen),
		CompanyID:   uc.CompanyID,
		GrantKey:    uc.GrantKey,
		Reason:      reason,
		TTL:         ttl,
		RequestedAt: now,
		ExpiresAt:   now.Add(RequestTTL),
	}
	existing, found, err := s.store.AddPending(ctx, g, MaxPending)
	switch {
	case errors.Is(err, ErrLimit):
		return RequestResult{}, invalidf("you have %d requests waiting for an approver, the most at a time; wait until they are decided or lapse (after %s)",
			MaxPending, FormatTTL(RequestTTL))
	case err != nil:
		return RequestResult{}, err
	case found:
		res.Grant, res.Existing, res.Capped = existing, true, false
		return res, nil
	}
	res.Grant = g
	s.logger.InfoContext(ctx, "kit requested", "id", id, "kit", kit.Name, "user", uc.UserID, "caller", uc.CallerID, "ttl", FormatTTL(ttl))
	return res, nil
}

// kitTTL returns how long the kit is granted for when asked for d (zero: the
// default), and whether d exceeded the maximum: the kit's ttl_max, or MaxTTL
// for a kit without one.
func kitTTL(k authz.Kit, d time.Duration) (time.Duration, bool) {
	limit := k.TTLMax
	if limit <= 0 {
		limit = MaxTTL
	}
	if d <= 0 {
		d = k.TTLDefault
		if d <= 0 {
			d = DefaultTTL
		}
		return min(d, limit), false
	}
	if d > limit {
		return limit, true
	}
	return d, false
}

// cleanText turns text a caller chose into one plain line: line breaks and
// tabs become spaces, runs of spaces one, and control and format characters
// (bidirectional overrides and isolates, zero-width characters) are
// dropped, so that what an approver reads is what it looks like.
func cleanText(s string) string {
	s = strings.Map(func(c rune) rune {
		switch {
		case c == '\n' || c == '\t':
			return ' '
		case unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == utf8.RuneError:
			return -1
		}
		return c
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// truncateRunes cuts s to at most n characters.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// cleanReason cleans the reason with cleanText and checks that it is there
// and not too long.
func cleanReason(r string) (string, error) {
	r = cleanText(r)
	switch {
	case r == "":
		return "", invalidf("give a reason: the task and, if there is one, the ticket; the approver reads it")
	case utf8.RuneCountInString(r) > MaxReasonLen:
		return "", invalidf("the reason has more than %d characters", MaxReasonLen)
	}
	return r, nil
}

// Approve turns a pending request into a grant of its kit, for the duration
// requested or, with ttl, for less. A grant of the same kit the caller holds
// already is replaced. Every call is audited.
func (s *Service) Approve(ctx context.Context, approver, id string, ttl time.Duration) (Grant, error) {
	start := s.now()
	g, err := s.approve(ctx, approver, id, ttl)
	if g.ID == "" {
		g.ID = id
	}
	entry := s.entry(auditApprove, start, g)
	entry.Metadata["approver"] = approver
	s.record(ctx, entry, err)
	return g, err
}

func (s *Service) approve(ctx context.Context, approver, id string, ttl time.Duration) (Grant, error) {
	req, err := s.store.Get(ctx, StatePending, id)
	if err != nil {
		return Grant{}, notPending(id, err)
	}
	kit, ok := s.kit(req.Kit)
	if !ok {
		return req, invalidf("the kit %q of request %s is no longer defined", req.Kit, id)
	}
	switch {
	case ttl < 0:
		return req, invalidf("ttl must be positive")
	case ttl > req.TTL:
		return req, invalidf("ttl %s exceeds the %s requested; an approval can shorten a grant, not extend it", FormatTTL(ttl), FormatTTL(req.TTL))
	case ttl == 0:
		ttl = req.TTL
	}
	// The kit's maximum may have been lowered since the request.
	ttl, _ = kitTTL(kit, ttl)
	req, err = s.store.Take(ctx, StatePending, id)
	if err != nil {
		return Grant{}, notPending(id, err)
	}

	now := s.now()
	g := req
	g.State = StateActive
	g.TTL = ttl
	g.ApprovedBy = approver
	g.ApprovedAt = now
	g.ExpiresAt = now.Add(ttl)
	held, err := s.store.ForSubject(ctx, StateActive, g.Subject())
	if err != nil {
		return g, err
	}
	if err := s.store.Put(ctx, g); err != nil {
		return g, err
	}
	for _, old := range held {
		if old.Kit == g.Kit && old.ID != g.ID {
			if _, err := s.store.Take(ctx, StateActive, old.ID); err != nil && !errors.Is(err, ErrNotFound) {
				s.logger.WarnContext(ctx, "could not remove the grant a new one replaces", "id", old.ID, "error", err)
			}
		}
	}
	s.logger.InfoContext(ctx, "kit granted", "id", id, "kit", g.Kit, "user", g.UserID, "caller", g.CallerID, "approver", approver, "expires", g.ExpiresAt)
	return g, nil
}

// Deny rejects a pending request. Every call is audited.
func (s *Service) Deny(ctx context.Context, approver, id string) (Grant, error) {
	return s.end(ctx, auditDeny, StatePending, approver, id)
}

// Revoke ends an active grant at once. Every call is audited.
func (s *Service) Revoke(ctx context.Context, approver, id string) (Grant, error) {
	return s.end(ctx, auditRevoke, StateActive, approver, id)
}

// end removes a request or grant on an approver's word.
func (s *Service) end(ctx context.Context, action, state, approver, id string) (Grant, error) {
	start := s.now()
	g, err := s.store.Take(ctx, state, id)
	switch {
	case errors.Is(err, ErrNotFound) && state == StatePending:
		err = notPending(id, err)
	case errors.Is(err, ErrNotFound):
		err = fmt.Errorf("%w: no active grant %s: it may have ended or been revoked", ErrNotFound, id)
	}
	if g.ID == "" {
		g.ID = id
	}
	entry := s.entry(action, start, g)
	entry.Metadata["approver"] = approver
	s.record(ctx, entry, err)
	if err == nil {
		s.logger.InfoContext(ctx, action, "id", id, "kit", g.Kit, "user", g.UserID, "caller", g.CallerID, "approver", approver)
	}
	return g, err
}

// notPending explains a request that is not, or no longer, pending.
func notPending(id string, err error) error {
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w: no pending request %s: it may have lapsed or been decided", ErrNotFound, id)
	}
	return err
}

// Lookup returns the request or grant with the id.
func (s *Service) Lookup(ctx context.Context, id string) (Grant, error) {
	g, err := s.store.Get(ctx, StatePending, id)
	if errors.Is(err, ErrNotFound) {
		g, err = s.store.Get(ctx, StateActive, id)
	}
	if errors.Is(err, ErrNotFound) {
		return Grant{}, fmt.Errorf("%w: no request or grant %s: it may have lapsed, ended or been decided", ErrNotFound, id)
	}
	return g, err
}

// List returns the pending requests and the active grants.
func (s *Service) List(ctx context.Context) (pending, active []Grant, err error) {
	if pending, err = s.store.List(ctx, StatePending); err != nil {
		return nil, nil, err
	}
	if active, err = s.store.List(ctx, StateActive); err != nil {
		return nil, nil, err
	}
	return pending, active, nil
}

// ForCaller returns the caller's pending requests and active grants. binding
// is what grants are bound to besides the user
// ([userctx.UserContext.GrantBinding]).
func (s *Service) ForCaller(ctx context.Context, userID, binding string) (pending, active []Grant, err error) {
	if pending, err = s.store.ForSubject(ctx, StatePending, Subject{UserID: userID, Binding: binding}); err != nil {
		return nil, nil, err
	}
	if active, err = s.activeFor(ctx, userID, binding); err != nil {
		return nil, nil, err
	}
	return pending, active, nil
}

// activeFor returns the caller's active grants. Grants of kits that are no
// longer defined are left out, as they allow nothing.
func (s *Service) activeFor(ctx context.Context, userID, binding string) ([]Grant, error) {
	active, err := s.store.ForSubject(ctx, StateActive, Subject{UserID: userID, Binding: binding})
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(active, func(g Grant) bool {
		_, ok := s.kit(g.Kit)
		return !ok
	}), nil
}

// HeldKits returns the kits the caller holds now; it reads the active grants
// only, as it runs at every check. binding is what grants are bound to
// besides the user ([userctx.UserContext.GrantBinding]). A store that fails
// contributes nothing: the caller then has its steady-state rights only.
func (s *Service) HeldKits(ctx context.Context, userID, binding string) []string {
	if userID == "" {
		return nil
	}
	active, err := s.activeFor(ctx, userID, binding)
	if err != nil {
		s.logger.WarnContext(ctx, "grant store failed, checking without granted kits", "user", userID, "error", err)
		return nil
	}
	var out []string
	for _, g := range active {
		if !slices.Contains(out, g.Kit) {
			out = append(out, g.Kit)
		}
	}
	return out
}

// entry starts the audit entry of a grant action.
func (s *Service) entry(action string, start time.Time, g Grant) audit.AuditEntry {
	md := map[string]string{"grant_id": g.ID}
	if g.Kit != "" {
		md["kit"] = g.Kit
	}
	if g.TTL > 0 {
		md["ttl"] = FormatTTL(g.TTL)
	}
	if !g.ExpiresAt.IsZero() {
		md["expires_at"] = g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return audit.AuditEntry{
		TraceID:    uuid.New().String(),
		Timestamp:  start,
		UserID:     g.UserID,
		CompanyID:  g.CompanyID,
		CallerID:   g.CallerID,
		CallerName: g.CallerName,
		Tool:       action,
		Backend:    auditBackend,
		Metadata:   md,
	}
}

// record completes the audit entry with the outcome and stores it.
func (s *Service) record(ctx context.Context, entry audit.AuditEntry, err error) {
	if s.audit == nil {
		return
	}
	entry.DurationMs = s.now().Sub(entry.Timestamp).Milliseconds()
	entry.Status = statusSuccess
	if err != nil {
		entry.Status = statusError
		entry.Error = err.Error()
	}
	if rerr := s.audit.Record(ctx, entry); rerr != nil {
		s.logger.ErrorContext(ctx, "failed to record audit entry", "traceId", entry.TraceID, "tool", entry.Tool, "error", rerr)
	}
}
