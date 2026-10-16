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

package authz

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// approverNamePattern restricts approver names to what reads well in the
// audit trail: a slug or an e-mail address.
var approverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Approver is a person who may approve requests for kits. Approvers are
// defined in the authz config file (approvers:) and identify themselves with
// a key of their own, never with the credential an agent connects with, so
// that an agent cannot approve what it asked for.
type Approver struct {
	// Name identifies the approver in the audit trail.
	Name string `yaml:"name"`
	// KeySHA256 is the SHA-256 of the approver's key as 64 hex characters.
	// The key itself is never stored; generate it randomly
	// (openssl rand -hex 32).
	KeySHA256 string `yaml:"key_sha256"`
}

// Validate checks the approver's name and key hash.
func (a Approver) Validate() error {
	if !approverNamePattern.MatchString(a.Name) {
		return fmt.Errorf("approver name %q: use letters, digits, '.', '_', '@' and '-', starting with a letter or digit, at most 64 characters", a.Name)
	}
	if b, err := hex.DecodeString(a.KeySHA256); err != nil || len(b) != 32 {
		return fmt.Errorf("approver %q: key_sha256 must be 64 hex characters", a.Name)
	}
	return nil
}

// validateApprovers validates each approver and that no two share a name or
// a key.
func validateApprovers(approvers []Approver) error {
	names := make(map[string]bool, len(approvers))
	keys := make(map[string]string, len(approvers))
	for _, a := range approvers {
		if err := a.Validate(); err != nil {
			return err
		}
		if names[a.Name] {
			return fmt.Errorf("approver %q is defined twice", a.Name)
		}
		names[a.Name] = true
		sum := strings.ToLower(a.KeySHA256)
		if other, dup := keys[sum]; dup {
			return fmt.Errorf("approvers %q and %q have the same key", other, a.Name)
		}
		keys[sum] = a.Name
	}
	return nil
}

// CheckApproverKeys refuses approvers whose key is a credential that callers
// connect with. reserved maps the SHA-256 (64 hex characters, lower case) of
// each such credential to a description of where it is configured.
func CheckApproverKeys(approvers []Approver, reserved map[string]string) error {
	for _, a := range approvers {
		if where, ok := reserved[strings.ToLower(a.KeySHA256)]; ok {
			return fmt.Errorf("approver %q: its key is also a credential callers connect with (%s); give the approver a key of its own", a.Name, where)
		}
	}
	return nil
}

// normalizeApprovers returns the approvers with their key hashes in lower
// case, as the lookup compares them.
func normalizeApprovers(approvers []Approver) []Approver {
	out := make([]Approver, len(approvers))
	for i, a := range approvers {
		a.KeySHA256 = strings.ToLower(a.KeySHA256)
		out[i] = a
	}
	return out
}
