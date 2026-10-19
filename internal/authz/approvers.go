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
	"slices"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/bip322"
)

// approverNamePattern restricts approver names to what reads well in the
// audit trail: a slug or an e-mail address.
var approverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Approver is a person who may approve requests for kits. Approvers are
// defined in the authz config file (approvers:) and identify themselves with
// a key of their own, never with the credential an agent connects with, so
// that an agent cannot approve what it asked for: a bearer key for the
// approver API, a signing key for the approval page, or both.
type Approver struct {
	// Name identifies the approver in the audit trail.
	Name string `yaml:"name"`
	// KeySHA256 is the SHA-256 of the approver's bearer key for the approver
	// API, as 64 hex characters. The key itself is never stored; generate it
	// randomly (openssl rand -hex 32). Optional when Address is set.
	KeySHA256 string `yaml:"key_sha256,omitempty"`
	// Address is the approver's signing address, a P2WPKH address (bc1q…).
	// On the approval page the approver signs what it approves with the key
	// of this address (BIP-322); the key stays with the approver. Optional
	// when KeySHA256 is set.
	Address string `yaml:"address,omitempty"`
	// Kits, when set, are the only kits the approver may approve, by name.
	// Empty means every kit. Each name must be a kit the same file defines.
	Kits []string `yaml:"kits,omitempty"`
}

// Validate checks the approver's name, key hash and address. An approver
// needs at least one of the two.
func (a Approver) Validate() error {
	if !approverNamePattern.MatchString(a.Name) {
		return fmt.Errorf("approver name %q: use letters, digits, '.', '_', '@' and '-', starting with a letter or digit, at most 64 characters", a.Name)
	}
	if a.KeySHA256 == "" && a.Address == "" {
		return fmt.Errorf("approver %q: give a key_sha256 (approver API), an address (approval page) or both", a.Name)
	}
	if a.KeySHA256 != "" {
		if b, err := hex.DecodeString(a.KeySHA256); err != nil || len(b) != 32 {
			return fmt.Errorf("approver %q: key_sha256 must be 64 hex characters", a.Name)
		}
	}
	if a.Address != "" {
		if _, err := bip322.ParseAddress(a.Address); err != nil {
			return fmt.Errorf("approver %q: %w", a.Name, err)
		}
	}
	for _, k := range a.Kits {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("approver %q: kits must not contain empty names", a.Name)
		}
	}
	return nil
}

// MayApprove reports whether the approver may approve requests for the kit:
// it names no kits, or names this one.
func (a Approver) MayApprove(kit string) bool {
	return len(a.Kits) == 0 || slices.Contains(a.Kits, kit)
}

// SigningAddress returns the approver's parsed signing address and whether it
// has one.
func (a Approver) SigningAddress() (bip322.Address, bool) {
	if a.Address == "" {
		return bip322.Address{}, false
	}
	addr, err := bip322.ParseAddress(a.Address)
	return addr, err == nil
}

// validateApprovers validates each approver, that no two share a name, a
// key or an address, and that the kits an approver is limited to are among
// kits.
func validateApprovers(approvers []Approver, kits []Kit) error {
	names := make(map[string]bool, len(approvers))
	keys := make(map[string]string, len(approvers))
	addresses := make(map[string]string, len(approvers))
	for _, a := range approvers {
		if err := a.Validate(); err != nil {
			return err
		}
		if names[a.Name] {
			return fmt.Errorf("approver %q is defined twice", a.Name)
		}
		names[a.Name] = true
		for _, name := range a.Kits {
			if !slices.ContainsFunc(kits, func(k Kit) bool { return k.Name == name }) {
				return fmt.Errorf("approver %q: there is no kit %q to limit it to", a.Name, name)
			}
		}
		if a.KeySHA256 != "" {
			sum := strings.ToLower(a.KeySHA256)
			if other, dup := keys[sum]; dup {
				return fmt.Errorf("approvers %q and %q have the same key", other, a.Name)
			}
			keys[sum] = a.Name
		}
		if addr, ok := a.SigningAddress(); ok {
			if other, dup := addresses[addr.String()]; dup {
				return fmt.Errorf("approvers %q and %q have the same address", other, a.Name)
			}
			addresses[addr.String()] = a.Name
		}
	}
	return nil
}

// CheckApproverKeys refuses approvers whose key is a credential that callers
// connect with. reserved maps the SHA-256 (64 hex characters, lower case) of
// each such credential to a description of where it is configured.
func CheckApproverKeys(approvers []Approver, reserved map[string]string) error {
	for _, a := range approvers {
		if a.KeySHA256 == "" {
			continue // signs on the approval page only
		}
		if where, ok := reserved[strings.ToLower(a.KeySHA256)]; ok {
			return fmt.Errorf("approver %q: its key is also a credential callers connect with (%s); give the approver a key of its own", a.Name, where)
		}
	}
	return nil
}

// normalizeApprovers returns the approvers with their key hashes in lower
// case, as the lookup compares them, and their addresses in canonical form.
func normalizeApprovers(approvers []Approver) []Approver {
	out := make([]Approver, len(approvers))
	for i, a := range approvers {
		a.KeySHA256 = strings.ToLower(a.KeySHA256)
		if addr, ok := a.SigningAddress(); ok {
			a.Address = addr.String()
		}
		out[i] = a
	}
	return out
}
