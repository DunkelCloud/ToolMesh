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
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

// ApprovePathPrefix is where the approval page is served: /approve/{id} for
// a request, /approve/ for setting up a signing key.
const ApprovePathPrefix = "/approve"

// approvePageCSP lets the page load its own style sheet and scripts and call
// its own endpoints, and nothing else: no inline script, no other origin, no
// framing.
const approvePageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// approveNote tells the approver which parts of the page come from where.
const approveNote = "The description, warning, entries and tool counts come from this ToolMesh. " +
	"The reason and the client name are the requester's own statements; ToolMesh does not verify them."

// scriptType is the content type of the page's scripts.
const scriptType = "text/javascript; charset=utf-8"

// approveAssets are the files the page loads, by name, with their type.
var approveAssets = map[string]string{
	"approve.css":    "text/css; charset=utf-8",
	"approve.js":     scriptType,
	"bip322.js":      scriptType,
	approveI18nAsset: scriptType,
}

// approveTmpl is the page. Everything a request contributes to it is escaped
// by html/template; the script fills in the rest from the JSON endpoint.
var approveTmpl = template.Must(template.ParseFS(webFiles, "web/approve.html"))

// ttlChoices are the durations the page offers below the one requested.
var ttlChoices = []time.Duration{5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 12 * time.Hour, 24 * time.Hour}

// ApprovalHandler returns the approval page and its endpoints. They need no
// credential: the page shows a pending request to whoever has its link, and
// approving takes a signature by the key of an approver's address.
//
//	GET  /approve/                 setting up a signing key
//	GET  /approve/{id}             the page for a request
//	GET  /approve/{id}/request     the request as the page shows it (JSON)
//	POST /approve/{id}/statement   the statement to sign for the choices made
//	POST /approve/{id}             approve with a signed statement
func (s *Service) ApprovalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+ApprovePathPrefix+"/{$}", s.handleApprovePage)
	mux.HandleFunc("GET "+ApprovePathPrefix+"/{id}", s.handleApprovePage)
	mux.HandleFunc("GET "+ApprovePathPrefix+"/{id}/request", s.handleApproveRequest)
	mux.HandleFunc("POST "+ApprovePathPrefix+"/{id}/statement", s.handleApproveStatement)
	mux.HandleFunc("POST "+ApprovePathPrefix+"/{id}", s.handleApproveSigned)
	return mux
}

// pageData fills the page template.
type pageData struct {
	ID string
	// Found is set when the page is for a pending request.
	Found bool
	// Title and Summary are the page title and the link preview messengers
	// show (Open Graph).
	Title   string
	Summary string
	URL     string
	// Status is the page's HTTP status: the page tells a request that is no
	// longer pending (404) from a store that failed.
	Status int
}

func (s *Service) handleApprovePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if ctype, ok := approveAssets[id]; ok {
		s.serveAsset(w, r, id, ctype)
		return
	}
	data := pageData{ID: id, Title: "ToolMesh approval", Summary: "Approve a request for a kit of tools in ToolMesh."}
	status := http.StatusOK
	if id != "" {
		data.URL = s.audience(r) + ApprovePathPrefix + "/" + id
		req, err := s.store.Get(r.Context(), StatePending, id)
		switch {
		case err == nil:
			data.Found = true
			data.Title, data.Summary = s.preview(req)
		case errors.Is(err, ErrNotFound):
			status = http.StatusNotFound
			data.Summary = "This request is no longer pending: it lapsed or was decided."
		default:
			s.logger.ErrorContext(r.Context(), "approval page: grant store failed", "error", err)
			status = http.StatusInternalServerError
		}
	}
	data.Status = status
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", approvePageCSP)
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(status)
	if err := approveTmpl.Execute(w, data); err != nil {
		s.logger.ErrorContext(r.Context(), "approval page render failed", "error", err)
	}
}

// preview returns the title and summary of a request for link previews:
// what the kit is (from the configuration), for whom, for how long and how
// many tools, never the requester's own words.
func (s *Service) preview(g Grant) (title, summary string) {
	desc := g.Kit
	if k, ok := s.kit(g.Kit); ok {
		desc = cleanText(k.Description)
	}
	title = "Approve: " + desc
	summary = fmt.Sprintf("%s asks for the kit %q for %s", g.UserID, g.Kit, FormatTTL(g.TTL))
	if len(g.Coverage) > 0 {
		tools, fresh := 0, 0
		for _, c := range g.Coverage {
			tools += c.Tools
			fresh += c.New
		}
		summary += fmt.Sprintf(", %d tools, %d of them new to %s", tools, fresh, g.UserID)
	}
	return title, summary + fmt.Sprintf(". Request %s, fingerprint %s.", g.ID, g.Fingerprint())
}

func (s *Service) serveAsset(w http.ResponseWriter, r *http.Request, name, ctype string) {
	data := approveI18nScript
	if name != approveI18nAsset {
		var err error
		if data, err = webFiles.ReadFile("web/" + name); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data) //nolint:gosec // a file embedded in the binary, not request data
}

// audience is how statements name this ToolMesh: its public URL or, without
// one, the origin the page was loaded from. The page asks for the statement
// and sends the signature from the same origin, so both name the same.
func (s *Service) audience(r *http.Request) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// entryView is one entry of a kit as the page shows it.
type entryView struct {
	Entry string `json:"entry"`
	// Kind is "grant" for a scope of the kit's grants, "tool" for a tool.
	Kind string `json:"kind"`
	// Backend and Access of a scope; "" for every backend or classification.
	// For a tool, Access is its classification.
	Backend string `json:"backend,omitempty"`
	Access  string `json:"access,omitempty"`
	// Effect groups entries by what they let the caller do, Rank orders the
	// groups with the most far-reaching first.
	Effect string `json:"effect"`
	Rank   int    `json:"rank"`
	// Tools the entry covers and how many of them are new to the caller;
	// absent when unknown.
	Tools *int `json:"tools,omitempty"`
	New   *int `json:"new,omitempty"`
}

// signerView is an approver who can sign.
type signerView struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// approvalView is a pending request as the page shows it.
type approvalView struct {
	ID            string       `json:"id"`
	Kit           string       `json:"kit"`
	Description   string       `json:"description"`
	Warning       string       `json:"warning,omitempty"`
	Entries       []entryView  `json:"entries"`
	CoverageKnown bool         `json:"coverage_known"`
	TTL           string       `json:"ttl"`
	TTLChoices    []string     `json:"ttl_choices"`
	RequestedAt   time.Time    `json:"requested_at"`
	LapsesAt      time.Time    `json:"lapses_at"`
	User          string       `json:"user"`
	Connection    string       `json:"connection"`
	ClientName    string       `json:"client_name,omitempty"`
	Reason        string       `json:"reason"`
	Fingerprint   string       `json:"fingerprint"`
	Approvers     []signerView `json:"approvers"`
	Note          string       `json:"note"`
}

func (s *Service) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, err := s.store.Get(r.Context(), StatePending, id)
	if err != nil {
		s.fail(w, r, notPending(id, err))
		return
	}
	kit, ok := s.kit(req.Kit)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("the kit %q of request %s is no longer defined", req.Kit, id))
		return
	}
	v := approvalView{
		ID:            req.ID,
		Kit:           kit.Name,
		Description:   cleanText(kit.Description),
		Warning:       cleanText(kit.Warning),
		CoverageKnown: len(req.Coverage) > 0,
		TTL:           FormatTTL(req.TTL),
		RequestedAt:   req.RequestedAt,
		LapsesAt:      req.ExpiresAt,
		User:          req.UserID,
		Connection:    connection(req),
		Reason:        req.Reason,
		Fingerprint:   req.Fingerprint(),
		Approvers:     []signerView{},
		Note:          approveNote,
	}
	if req.CallerName != req.CallerID {
		v.ClientName = req.CallerName
	}
	v.TTLChoices = append(v.TTLChoices, v.TTL)
	for _, d := range slices.Backward(ttlChoices) {
		if d < req.TTL {
			v.TTLChoices = append(v.TTLChoices, FormatTTL(d))
		}
	}
	v.Entries = entryViews(kit.Grants, kit.Tools, req.Coverage)
	// Only approvers who may approve this kit are offered; the statement
	// and the approval refuse the others anyway.
	for _, a := range s.Signers() {
		if a.MayApprove(kit.Name) {
			v.Approvers = append(v.Approvers, signerView{Name: a.Name, Address: a.Address})
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// entryViews describes the entries of a kit, the most far-reaching first.
func entryViews(scopes, tools []string, coverage []EntryCoverage) []entryView {
	find := func(entry string, tool bool) *EntryCoverage {
		for i := range coverage {
			if coverage[i].Entry == entry && coverage[i].Tool == tool {
				return &coverage[i]
			}
		}
		return nil
	}
	out := make([]entryView, 0, len(scopes)+len(tools))
	for _, sc := range scopes {
		b, a, _ := strings.Cut(sc, ":")
		v := entryView{Entry: sc, Kind: "grant", Backend: strings.TrimSpace(b), Access: strings.TrimSpace(a)}
		if v.Backend == "*" {
			v.Backend = ""
		}
		if v.Access == "*" {
			v.Access = ""
		}
		v.Effect, v.Rank = effectOf(v.Access, true)
		if c := find(sc, false); c != nil {
			v.Tools, v.New = &c.Tools, &c.New
		}
		out = append(out, v)
	}
	for _, t := range tools {
		v := entryView{Entry: t, Kind: "tool"}
		if c := find(t, true); c != nil {
			v.Access, v.Tools, v.New = c.Access, &c.Tools, &c.New
		}
		v.Effect, v.Rank = effectOf(v.Access, false)
		out = append(out, v)
	}
	slices.SortStableFunc(out, func(a, b entryView) int { return a.Rank - b.Rank })
	return out
}

// effectOf names the group of an access classification and its rank. A
// scope without a classification covers every one, dangerous ones included,
// so it comes first; an unclassified tool may do anything its API allows.
func effectOf(access string, scope bool) (effect string, rank int) {
	switch access {
	case "":
		if scope {
			return "all", 0
		}
		return "unclassified", 3
	case "dangerous":
		return "dangerous", 1
	case "admin":
		return "admin", 2
	case "write":
		return "write", 4
	case "read":
		return "read", 5
	default:
		return "other", 3
	}
}

// approvalBody is what the page sends: the approver's choices and, to
// approve, the signature.
type approvalBody struct {
	Approver  string   `json:"approver"`
	TTL       string   `json:"ttl"`
	Grants    []string `json:"grants"`
	Tools     []string `json:"tools"`
	Signature string   `json:"signature,omitempty"`
}

// readApprovalBody decodes the body; it writes the error answer and returns
// false when it cannot.
func readApprovalBody(w http.ResponseWriter, r *http.Request) (body approvalBody, a Approval, ok bool) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "the body is too large")
		return body, Approval{}, false
	}
	if err := json.Unmarshal(data, &body); err != nil {
		writeError(w, http.StatusBadRequest, "the body must be JSON: {approver, ttl, grants, tools, signature}")
		return body, Approval{}, false
	}
	ttl, err := ParseTTL(body.TTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return body, Approval{}, false
	}
	return body, Approval{TTL: ttl, Grants: body.Grants, Tools: body.Tools}, true
}

// statementView is the answer of POST /approve/{id}/statement.
type statementView struct {
	Statement   string `json:"statement"`
	TTL         string `json:"ttl"`
	Whole       bool   `json:"whole"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Service) handleApproveStatement(w http.ResponseWriter, r *http.Request) {
	body, a, ok := readApprovalBody(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	st, err := s.Statement(r.Context(), id, body.Approver, a, s.audience(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req, err := s.store.Get(r.Context(), StatePending, id)
	if err != nil {
		s.fail(w, r, notPending(id, err))
		return
	}
	writeJSON(w, http.StatusOK, statementView{Statement: st.Text, TTL: FormatTTL(st.TTL), Whole: st.Whole, Fingerprint: req.Fingerprint()})
}

// signedView is the answer of a signed approval.
type signedView struct {
	Status    string    `json:"status"`
	ID        string    `json:"id"`
	Kit       string    `json:"kit"`
	TTL       string    `json:"ttl"`
	Part      *Part     `json:"part,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) handleApproveSigned(w http.ResponseWriter, r *http.Request) {
	body, a, ok := readApprovalBody(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(body.Signature) == "" {
		writeError(w, http.StatusBadRequest, "the signature is missing")
		return
	}
	id, ip := r.PathValue("id"), auth.ClientIP(r)
	attempt := s.throttle.Acquire(r.Context(), id, ip)
	if !attempt.Allowed {
		s.logger.WarnContext(r.Context(), "signed approval throttled", "id", id, "remote", ip, "scope", attempt.Scope)
		secs := max(int((attempt.RetryAfter+time.Second-1)/time.Second), 1)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many refused signatures; try again in %d seconds", secs))
		return
	}
	g, err := s.ApproveSigned(r.Context(), id, SignedApproval{Approver: body.Approver, Approval: a, Audience: s.audience(r), Signature: body.Signature})
	switch {
	case err == nil:
		s.throttle.Success(r.Context(), attempt)
	case errors.Is(err, ErrInvalid):
		// A refusal keeps its slot: it counts against the limits.
		s.logger.WarnContext(r.Context(), "signed approval refused", "id", id, "approver", cleanText(body.Approver), "remote", ip, "error", err)
	default:
		// A request that is not pending, or a store that failed, says
		// nothing about the signature.
		s.throttle.Cancel(r.Context(), attempt)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := signedView{Status: g.State, ID: g.ID, Kit: g.Kit, TTL: FormatTTL(g.TTL), ExpiresAt: g.ExpiresAt}
	if !s.IsWhole(g) {
		v.Part = g.Part
	}
	writeJSON(w, http.StatusOK, v)
}
