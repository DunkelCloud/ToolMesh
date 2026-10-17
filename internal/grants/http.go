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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
)

// PathPrefix is where the approver API is served.
const PathPrefix = "/grants"

// jsonKeyError holds the message of an error answer.
const jsonKeyError = "error"

// maxBodyBytes bounds the body of an approval.
const maxBodyBytes = 4096

// viewNote tells an approver which parts of a request come from where.
const viewNote = "The description, warning, scope and coverage come from the ToolMesh configuration and its tools. " +
	"The reason and the caller_name are the requester's own statements; ToolMesh does not verify them."

// grantView is a request or grant as the approver API shows it.
type grantView struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Kit         string          `json:"kit"`
	Description string          `json:"description,omitempty"`
	Warning     string          `json:"warning,omitempty"`
	Grants      []string        `json:"grants,omitempty"`
	Tools       []string        `json:"tools,omitempty"`
	Coverage    []EntryCoverage `json:"coverage,omitempty"`
	UserID      string          `json:"user_id"`
	CallerID    string          `json:"caller_id"`
	CallerName  string          `json:"caller_name,omitempty"`
	CompanyID   string          `json:"company_id,omitempty"`
	GrantKey    string          `json:"grant_key,omitempty"`
	Reason      string          `json:"reason"`
	TTL         string          `json:"ttl"`
	RequestedAt time.Time       `json:"requested_at"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	ApprovalURL string          `json:"approval_url,omitempty"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
	ApprovedAt  time.Time       `json:"approved_at,omitzero"`
	// ApprovedWith is "key" or "signature".
	ApprovedWith string `json:"approved_with,omitempty"`
	// Part lists the entries granted when the grant covers part of the kit.
	Part      *Part     `json:"part,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// listView is the answer of GET /grants.
type listView struct {
	Pending []grantView `json:"pending"`
	Active  []grantView `json:"active"`
	Note    string      `json:"note"`
}

// singleView is the answer for one request or grant.
type singleView struct {
	grantView
	Note string `json:"note"`
}

// Handler returns the approver API. Every route needs an approver's key as
// a bearer credential; the credentials callers connect with do not work
// here.
//
//	GET  /grants              pending requests and active grants
//	GET  /grants/{id}         one request or grant
//	POST /grants/{id}/approve grant the kit; optional body {"ttl": "2h"} to
//	                          shorten, {"grants": [...], "tools": [...]} to
//	                          grant only these entries of the kit
//	POST /grants/{id}/deny    reject a pending request
//	POST /grants/{id}/revoke  end an active grant now
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathPrefix, s.handleList)
	mux.HandleFunc("GET "+PathPrefix+"/{id}", s.handleGet)
	mux.HandleFunc("POST "+PathPrefix+"/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST "+PathPrefix+"/{id}/deny", s.handleDeny)
	mux.HandleFunc("POST "+PathPrefix+"/{id}/revoke", s.handleRevoke)
	return s.requireApprover(mux)
}

// approverKey is the context key of the authenticated approver.
type approverKey struct{}

// requireApprover lets a request through only with an approver's key.
func (s *Service) requireApprover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		approver, found := s.Approver(strings.TrimSpace(key))
		if !ok || !found {
			s.logger.WarnContext(r.Context(), "grant API: request without a valid approver key", "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer realm="toolmesh grants"`)
			writeError(w, http.StatusUnauthorized, "an approver key is required (Authorization: Bearer <key>)")
			return
		}
		next.ServeHTTP(w, r.WithContext(withApprover(r.Context(), approver)))
	})
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	pending, active, err := s.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := listView{Pending: []grantView{}, Active: []grantView{}, Note: viewNote}
	for _, g := range pending {
		out.Pending = append(out.Pending, s.view(g))
	}
	for _, g := range active {
		out.Active = append(out.Active, s.view(g))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	g, err := s.Lookup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, singleView{grantView: s.view(g), Note: viewNote})
}

func (s *Service) handleApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTL    string   `json:"ttl"`
		Grants []string `json:"grants"`
		Tools  []string `json:"tools"`
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "the body is too large")
		return
	}
	if strings.TrimSpace(string(data)) != "" {
		if err := json.Unmarshal(data, &body); err != nil {
			writeError(w, http.StatusBadRequest, "the body must be empty or JSON such as {\"ttl\": \"2h\", \"grants\": [\"graylog:read\"]}")
			return
		}
	}
	ttl, err := ParseTTL(body.TTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := s.ApproveWith(r.Context(), approverFrom(r).Name, r.PathValue("id"), Approval{TTL: ttl, Grants: body.Grants, Tools: body.Tools})
	s.answer(w, r, g, err)
}

func (s *Service) handleDeny(w http.ResponseWriter, r *http.Request) {
	g, err := s.Deny(r.Context(), approverFrom(r).Name, r.PathValue("id"))
	s.answer(w, r, g, err)
}

func (s *Service) handleRevoke(w http.ResponseWriter, r *http.Request) {
	g, err := s.Revoke(r.Context(), approverFrom(r).Name, r.PathValue("id"))
	s.answer(w, r, g, err)
}

// answer writes the request or grant an action resulted in, or its error.
func (s *Service) answer(w http.ResponseWriter, r *http.Request, g Grant, err error) {
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, singleView{grantView: s.view(g), Note: viewNote})
}

// fail writes an error with the status it calls for.
func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.logger.ErrorContext(r.Context(), "grant API failed", "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "the grant store failed; see the ToolMesh log")
	}
}

// view renders g with what its kit says in the configuration.
func (s *Service) view(g Grant) grantView {
	v := grantView{
		ID:           g.ID,
		State:        g.State,
		Kit:          g.Kit,
		Coverage:     g.Coverage,
		UserID:       g.UserID,
		CallerID:     g.CallerID,
		CallerName:   g.CallerName,
		CompanyID:    g.CompanyID,
		GrantKey:     g.GrantKey,
		Reason:       g.Reason,
		TTL:          FormatTTL(g.TTL),
		RequestedAt:  g.RequestedAt,
		ApprovedBy:   g.ApprovedBy,
		ApprovedAt:   g.ApprovedAt,
		ApprovedWith: g.ApprovedWith,
		ExpiresAt:    g.ExpiresAt,
	}
	if g.State == StatePending {
		v.Fingerprint, v.ApprovalURL = g.Fingerprint(), s.ApprovalURL(g.ID)
	}
	if k, ok := s.kit(g.Kit); ok {
		v.Description, v.Warning, v.Grants, v.Tools = k.Description, k.Warning, k.Grants, k.Tools
		if !s.IsWhole(g) {
			v.Part = g.Part
		}
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{jsonKeyError: msg})
}

// withApprover records the authenticated approver in the request context.
func withApprover(ctx context.Context, a authz.Approver) context.Context {
	return context.WithValue(ctx, approverKey{}, a)
}

// approverFrom returns the approver requireApprover authenticated.
func approverFrom(r *http.Request) authz.Approver {
	a, _ := r.Context().Value(approverKey{}).(authz.Approver)
	return a
}
