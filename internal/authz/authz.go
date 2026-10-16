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

// Package authz decides whether a caller may execute a tool.
//
// Two engines implement [Authorizer]. [Embedded] runs OpenFGA inside the
// ToolMesh process on a SQLite file in the data directory, creates its store
// and model on first start and takes its grants from a preset or from
// config/authz.yaml. [External] asks an OpenFGA server that is operated
// separately and never writes to it.
package authz

import (
	"context"
	"strings"
	"unicode"
)

// relCanExecute is the relation every check asks for, in both engines.
const relCanExecute = "can_execute"

// Authorizer checks whether a caller may execute a tool.
type Authorizer interface {
	// Check reports whether the caller in req may execute req.Tool. An error
	// means no decision was reached; callers must treat it as a denial.
	Check(ctx context.Context, req Request) (bool, error)
	// Healthy reports whether the engine can answer checks.
	Healthy(ctx context.Context) error
	// Close releases the engine's resources.
	Close() error
}

// BatchChecker is implemented by authorizers that answer many requests faster
// than one Check each. A request whose check fails is reported as not allowed;
// the error describes the failures.
type BatchChecker interface {
	CheckBatch(ctx context.Context, reqs []Request) ([]bool, error)
}

// KitCatalog is implemented by authorizers that know kits: named bundles of
// tools a caller can be granted as a whole. Only the embedded engine does.
type KitCatalog interface {
	// Kits returns the kits in effect, sorted by name. The slice is shared
	// and must not be modified.
	Kits() []Kit
}

// ApproverRegistry is implemented by authorizers that know who may approve
// requests for kits. Only the embedded engine does.
type ApproverRegistry interface {
	// Approvers returns the approvers in effect. The slice is shared and must
	// not be modified.
	Approvers() []Approver
}

// Request is one authorization question: may this caller execute this tool?
type Request struct {
	// Caller, as authentication established it.
	UserID    string
	CompanyID string
	Plan      string
	Roles     []string
	// Kits the caller holds at the time of the check. Only the embedded
	// engine knows kits; External ignores them.
	Kits []string

	// Tool is the canonical "<backend>_<tool>" name.
	Tool string
	// Backend is the backend the call is routed to. Empty when unknown, in
	// which case grants on a backend do not cover the tool.
	Backend string
	// Access is the DADL access classification of the tool ("read", "write",
	// ...). Empty when the backend declares none.
	Access string
}

// escapeID turns a name into an OpenFGA object or user id. OpenFGA ids must
// not contain ':', '#', whitespace or control characters, and '*' is the
// wildcard, so these characters and '%' itself are percent-encoded. Distinct
// names therefore always yield distinct ids.
func escapeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '%' || r == ':' || r == '#' || r == '*' || unicode.IsSpace(r) || unicode.IsControl(r):
			for _, c := range []byte(string(r)) {
				b.WriteByte('%')
				b.WriteByte("0123456789ABCDEF"[c>>4])
				b.WriteByte("0123456789ABCDEF"[c&0x0F])
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
