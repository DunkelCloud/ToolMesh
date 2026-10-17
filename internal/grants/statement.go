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
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/bip322"
)

// StatementVersion is the first line of every statement. A change of what a
// statement says or how it is laid out gets a new version.
const StatementVersion = "ToolMesh grant approval, version 1"

// Statement is the text an approver signs on the approval page to approve a
// request, and what it approves.
//
// ToolMesh alone writes it, from the stored request, the kit in the
// configuration and the approver's choices; the page shows it as it is and
// signs it as it is, and ToolMesh writes it again to verify the signature.
// So the text needs no canonical form shared with the browser, and every
// value comes from ToolMesh: the requester's own words appear marked as such
// and reduced to one plain line.
type Statement struct {
	Text string
	// TTL is the duration granted, Entries the entries of the kit granted.
	TTL     time.Duration
	Entries Part
	// Whole is set when Entries are every entry of the kit.
	Whole bool
}

// SignedApproval is an approval made on the approval page.
type SignedApproval struct {
	// Approver is the name of the approver who signed.
	Approver string
	Approval
	// Audience is the ToolMesh the statement names: its public URL.
	Audience string
	// Signature is the BIP-322 signature of the statement by the key of the
	// approver's address.
	Signature string
}

// Statement returns the statement an approver signs to approve the pending
// request with the given choices. audience names this ToolMesh.
func (s *Service) Statement(ctx context.Context, id, approver string, a Approval, audience string) (Statement, error) {
	st, _, _, err := s.statement(ctx, id, approver, a, audience)
	return st, err
}

// statement builds the statement and returns it with the approver and the
// address the signature must come from.
func (s *Service) statement(ctx context.Context, id, approverName string, a Approval, audience string) (Statement, authz.Approver, bip322.Address, error) {
	approver, addr, err := s.signer(approverName)
	if err != nil {
		return Statement{}, authz.Approver{}, bip322.Address{}, err
	}
	req, err := s.store.Get(ctx, StatePending, id)
	if err != nil {
		return Statement{}, authz.Approver{}, bip322.Address{}, notPending(id, err)
	}
	kit, ok := s.kit(req.Kit)
	if !ok {
		return Statement{}, authz.Approver{}, bip322.Address{}, invalidf("the kit %q of request %s is no longer defined", req.Kit, id)
	}
	ttl, part, err := resolveApproval(kit, req, a)
	if err != nil {
		return Statement{}, authz.Approver{}, bip322.Address{}, err
	}
	entries := Part{Grants: slices.Clone(kit.Grants), Tools: slices.Clone(kit.Tools)}
	if part != nil {
		entries = *part
	}
	st := Statement{TTL: ttl, Entries: entries, Whole: kit.IsWhole(entries.kitPart(kit.Name))}
	st.Text = renderStatement(statementInput{
		audience: audience, req: req, approver: approver.Name, address: addr.String(),
		kit: kit, ttl: ttl, entries: entries,
	})
	return st, approver, addr, nil
}

// signer returns the approver with the name and its signing address.
func (s *Service) signer(name string) (authz.Approver, bip322.Address, error) {
	for _, a := range s.Signers() {
		if a.Name == name {
			addr, _ := a.SigningAddress()
			return a, addr, nil
		}
	}
	return authz.Approver{}, bip322.Address{}, invalidf("there is no approver %q with a signing address", name)
}

// ApproveSigned approves a pending request on the strength of a signed
// statement: ToolMesh writes the statement for the approver's choices again
// and approves only if the signature is the approver's signature of exactly
// that text. The grant holds the entries the statement lists and no others,
// even if the kit gains entries later. The statement names the request and
// its nonce, and approving takes the request from the store, so a signature
// approves once. Every call is audited, with the signature and the statement.
func (s *Service) ApproveSigned(ctx context.Context, id string, sa SignedApproval) (Grant, error) {
	start := s.now()
	st, approver, addr, err := s.statement(ctx, id, sa.Approver, sa.Approval, sa.Audience)
	if err == nil {
		if verr := bip322.Verify(addr, []byte(st.Text), sa.Signature); verr != nil {
			err = invalidf("the signature does not approve this request: %s", verr)
		}
	}
	if err != nil {
		entry := s.entry(auditApprove, start, Grant{ID: id})
		entry.Metadata["approver"] = truncateRunes(cleanText(sa.Approver), maxAuditArgLen)
		entry.Metadata["approved_with"] = ApprovedWithSignature
		s.record(ctx, entry, err)
		return Grant{}, err
	}
	digest := sha256.Sum256([]byte(st.Text))
	md := map[string]string{
		"address":          addr.String(),
		"signature":        strings.TrimSpace(sa.Signature),
		"statement":        st.Text,
		"statement_sha256": hex.EncodeToString(digest[:]),
	}
	return s.approveAudited(ctx, approver.Name, id, Approval{TTL: st.TTL, Grants: st.Entries.Grants, Tools: st.Entries.Tools}, ApprovedWithSignature, md)
}

// statementInput is what a statement is written from.
type statementInput struct {
	audience, approver, address string
	req                         Grant
	kit                         authz.Kit
	ttl                         time.Duration
	entries                     Part
}

// renderStatement writes the statement: one "Name: value" line per fact, in
// a fixed order, blocks separated by an empty line, every value reduced to
// one plain line, LF line ends, UTF-8.
func renderStatement(in statementInput) string {
	var b strings.Builder
	line := func(name, value string) {
		if v := cleanText(value); v != "" {
			b.WriteString(name + ": " + v + "\n")
		}
	}
	b.WriteString(StatementVersion + "\n\n")
	b.WriteString("I approve the request below with the key of my address.\n\n")
	line("ToolMesh", in.audience)
	line("Request", in.req.ID)
	line("Nonce", in.req.Nonce)
	line("Approver", in.approver)
	line("Address", in.address)
	b.WriteString("\n")
	line("Kit", in.kit.Name)
	line("Description", in.kit.Description)
	line("Warning", in.kit.Warning)
	line("Grants", strings.Join(in.entries.Grants, ", "))
	line("Tools", strings.Join(in.entries.Tools, ", "))
	line("Left out grants", strings.Join(missing(in.kit.Grants, in.entries.Grants), ", "))
	line("Left out tools", strings.Join(missing(in.kit.Tools, in.entries.Tools), ", "))
	line("Duration", FormatTTL(in.ttl)+" from the approval")
	line("Approve before", in.req.ExpiresAt.UTC().Format(time.RFC3339))
	b.WriteString("\n")
	line("User", in.req.UserID)
	line("Connection", connection(in.req))
	line("Client name, as the client states it", in.req.CallerName)
	line("Reason, as the requester states it", in.req.Reason)
	return b.String()
}

// missing returns the entries of all that are not in kept.
func missing(all, kept []string) []string {
	var out []string
	for _, e := range all {
		if !slices.Contains(kept, e) {
			out = append(out, e)
		}
	}
	return out
}

// connection describes what the grant is bound to besides the user.
func connection(g Grant) string {
	if g.GrantKey != "" {
		return "API key " + g.GrantKey
	}
	return g.CallerID
}
