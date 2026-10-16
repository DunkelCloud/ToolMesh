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
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// scopeAny stands for every backend or every access classification in a kit
// scope; on its own it stands for every tool.
const scopeAny = "*"

// KitTTLLimit is the longest a kit without ttl_max is granted for.
const KitTTLLimit = 24 * time.Hour

// kitNamePattern restricts kit names to slugs, so that they read the same in
// the config file, in tool output and in the audit trail.
var kitNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Kit is a named bundle of tools that a caller is granted as a whole and for
// a limited time, instead of tool by tool. Kits are defined in the authz
// config file (kits:). In the authorization model a kit is a role whose
// holders get what the kit covers; holding it is a contextual tuple per
// check ([Request.Kits]), so it ends without anything to clean up.
type Kit struct {
	// Name is the key under kits: in the config file.
	Name string `yaml:"-"`
	// Description says in plain language what the kit is for. It is what
	// callers and approvers see; required.
	Description string `yaml:"description"`
	// Warning, when set, is shown with the description.
	Warning string `yaml:"warning,omitempty"`
	// Grants lists what the kit covers, as scopes: "*" for every tool,
	// "<backend>" for every tool of a backend, "<backend>:<access>" for the
	// tools of a backend with this DADL access classification and
	// "*:<access>" for the tools with this classification on any backend.
	Grants []string `yaml:"grants,omitempty"`
	// Tools lists single tools by their full name, <backend>_<tool>.
	Tools []string `yaml:"tools,omitempty"`
	// TTLDefault is how long the kit is granted when the request names no
	// duration, TTLMax the longest it may be granted for. Zero means not set.
	TTLDefault time.Duration `yaml:"ttl_default,omitempty"`
	TTLMax     time.Duration `yaml:"ttl_max,omitempty"`
}

// kitScope is one parsed entry of Kit.Grants. An empty field matches any
// value.
type kitScope struct {
	backend string
	access  string
}

// parseKitScope parses a scope of Kit.Grants.
func parseKitScope(s string) (kitScope, error) {
	s = strings.TrimSpace(s)
	b, a, hasAccess := strings.Cut(s, ":")
	b, a = strings.TrimSpace(b), strings.TrimSpace(a)
	switch {
	case b == "":
		return kitScope{}, fmt.Errorf("scope %q names no backend (use %q for every backend)", s, scopeAny)
	case hasAccess && a == "":
		return kitScope{}, fmt.Errorf("scope %q names no access classification after the colon", s)
	case strings.Contains(a, ":"):
		return kitScope{}, fmt.Errorf("scope %q has more than one colon", s)
	}
	if b == scopeAny {
		b = ""
	}
	if a == scopeAny {
		a = ""
	}
	return kitScope{backend: b, access: a}, nil
}

// covers reports whether the scope covers a tool routed to backend with the
// access classification access. Like the authorization model, an unknown
// backend or classification is covered only by a scope that does not name
// one.
func (s kitScope) covers(backend, access string) bool {
	if s.backend != "" && s.backend != backend {
		return false
	}
	if s.access != "" && s.access != access {
		return false
	}
	return true
}

// object returns the OpenFGA object a grant of the scope is written on.
func (s kitScope) object() string {
	switch {
	case s.backend == "" && s.access == "":
		return objInstance
	case s.access == "":
		return "backend:" + escapeID(s.backend)
	case s.backend == "":
		return "access_class:" + escapeID(s.access)
	default:
		return "backend_access:" + backendAccessID(s.backend, s.access)
	}
}

// backendAccessID is the id of the object that stands for the tools of one
// backend with one access classification. Both names are escaped first, so
// the colon between them is the only one and distinct pairs never share an
// id.
func backendAccessID(backend, access string) string {
	return escapeID(escapeID(backend) + ":" + escapeID(access))
}

// Validate checks the kit's name and description, that it covers at least
// one tool and that its scopes and durations are well-formed.
func (k Kit) Validate() error {
	if !kitNamePattern.MatchString(k.Name) {
		return fmt.Errorf("kit name %q: use letters, digits, '.', '_' and '-', starting with a letter or digit, at most 64 characters", k.Name)
	}
	if strings.TrimSpace(k.Description) == "" {
		return errors.New("description is required: it is what callers and approvers see")
	}
	if len(k.Grants) == 0 && len(k.Tools) == 0 {
		return errors.New("name at least one of grants or tools")
	}
	for _, g := range k.Grants {
		if _, err := parseKitScope(g); err != nil {
			return err
		}
	}
	for _, t := range k.Tools {
		if strings.TrimSpace(t) == "" {
			return errors.New("tools must not contain empty names")
		}
	}
	if k.TTLDefault < 0 || k.TTLMax < 0 {
		return errors.New("ttl_default and ttl_max must not be negative")
	}
	if k.TTLDefault > 0 && k.TTLMax > 0 && k.TTLDefault > k.TTLMax {
		return fmt.Errorf("ttl_default %s exceeds ttl_max %s", k.TTLDefault, k.TTLMax)
	}
	if k.TTLMax == 0 && k.TTLDefault > KitTTLLimit {
		return fmt.Errorf("ttl_default %s exceeds the %s a kit without ttl_max is granted for at most; set ttl_max", k.TTLDefault, KitTTLLimit)
	}
	return nil
}

// Covers reports whether the kit covers a tool routed to backend with the
// access classification access. It is the static answer from the kit's
// definition; a deny can still block the tool for a caller who holds the kit.
func (k Kit) Covers(tool, backend, access string) bool {
	if slices.Contains(k.Tools, tool) {
		return true
	}
	for _, g := range k.Grants {
		if s, err := parseKitScope(g); err == nil && s.covers(backend, access) {
			return true
		}
	}
	return false
}

// holder returns the OpenFGA userset of the kit's holders.
func (k Kit) holder() string {
	return "kit:" + escapeID(k.Name) + "#" + relHolder
}

// tuples returns the store tuples that let the kit's holders execute what it
// covers.
func (k Kit) tuples() []tupleKey {
	user := k.holder()
	var out []tupleKey
	add := func(object string) {
		out = append(out, tupleKey{User: user, Relation: relExecutor, Object: object})
	}
	for _, g := range k.Grants {
		if s, err := parseKitScope(g); err == nil {
			add(s.object())
		}
	}
	for _, t := range k.Tools {
		add("tool:" + escapeID(t))
	}
	return out
}

// validateKits validates each kit and that no two share a name.
func validateKits(kits []Kit) error {
	seen := make(map[string]bool, len(kits))
	for _, k := range kits {
		if err := k.Validate(); err != nil {
			return fmt.Errorf("kit %q: %w", k.Name, err)
		}
		if seen[k.Name] {
			return fmt.Errorf("kit %q is defined twice", k.Name)
		}
		seen[k.Name] = true
	}
	return nil
}

// kitsFromFile returns the kits of a config file sorted by name, with Name
// set from the map key.
func kitsFromFile(m map[string]Kit) []Kit {
	out := make([]Kit, 0, len(m))
	for name, k := range m {
		k.Name = name
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b Kit) int { return strings.Compare(a.Name, b.Name) })
	return out
}
