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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Presets: named sets of grants for typical setups, so that nobody has to
// write grants to get started.
const (
	// PresetSingleUser lets the owner (TOOLMESH_AUTH_USER) and every caller
	// with the role "admin" execute every tool. Nobody else may execute any.
	PresetSingleUser = "single-user"
	// PresetTeam adds plans to single-user: plan "pro" may execute every
	// tool, plan "free" every tool classified as "read".
	PresetTeam = "team"
	// PresetOpen lets every authenticated caller execute every tool. It is
	// what an installation that ran without authorization is upgraded to, so
	// that its behavior does not change.
	PresetOpen = "open"
)

// Names the presets refer to. They match the defaults of TOOLMESH_AUTH_PLAN
// and TOOLMESH_AUTH_ROLES and the examples in users.yaml.example.
const (
	PlanPro    = "pro"
	PlanFree   = "free"
	RoleAdmin  = "admin"
	AccessRead = "read"
)

// Where the grants in effect come from (Policy.Source).
const (
	// SourceFile: the authz config file (config/authz.yaml).
	SourceFile = "file"
	// SourceEnv: TOOLMESH_AUTHZ_PRESET.
	SourceEnv = "env"
	// SourceUpgrade: the preset recorded when an installation that ran
	// without authorization was upgraded.
	SourceUpgrade = "upgrade"
	// SourceDefault: the preset chosen from the identity configuration.
	SourceDefault = "default"
)

// Grant names one subject and a set of tools. In a list of grants it allows
// the subject to execute them; in a list of denies it blocks them, whatever
// any grant says. Exactly one subject field and at least one target field
// must be set.
type Grant struct {
	// Subject: who is granted or denied.
	User     string `yaml:"user,omitempty"`
	Role     string `yaml:"role,omitempty"`
	Plan     string `yaml:"plan,omitempty"`
	Company  string `yaml:"company,omitempty"`
	Everyone bool   `yaml:"everyone,omitempty"` // every authenticated caller

	// Targets: the tools concerned.
	AllTools bool     `yaml:"all_tools,omitempty"`
	Backends []string `yaml:"backends,omitempty"`
	Tools    []string `yaml:"tools,omitempty"`
	Access   []string `yaml:"access,omitempty"` // DADL access classifications
}

// File is the authz config file, config/authz.yaml.
type File struct {
	// Preset, when set, contributes its grants in addition to Grants.
	Preset string  `yaml:"preset,omitempty"`
	Grants []Grant `yaml:"grants"`
	// Denies block tools for a subject even when a grant or the preset
	// allows them.
	Denies []Grant `yaml:"denies,omitempty"`
	// Kits are named bundles of tools a caller can be granted as a whole,
	// keyed by name.
	Kits map[string]Kit `yaml:"kits,omitempty"`
	// Approvers may approve requests for kits.
	Approvers []Approver `yaml:"approvers,omitempty"`
}

// Policy is the set of grants and denies in effect and where it comes from.
type Policy struct {
	// Preset the grants are based on; empty when a config file names none.
	Preset string
	// Source is one of the Source* constants.
	Source string
	Grants []Grant
	// Denies win over Grants. Only a config file names denies.
	Denies []Grant
	// Kits, sorted by name. Only a config file defines kits.
	Kits []Kit
	// Approvers may approve requests for kits. Only a config file names
	// approvers.
	Approvers []Approver
}

// PolicyInput holds everything ResolvePolicy chooses from.
type PolicyInput struct {
	// File is the parsed authz config file, nil when there is none.
	File *File
	// EnvPreset is TOOLMESH_AUTHZ_PRESET.
	EnvPreset string
	// UpgradePreset is the preset recorded by the embedded engine when an
	// installation that ran without authorization was upgraded.
	UpgradePreset string
	// DefaultPreset applies when nothing else names grants.
	DefaultPreset string
	// Owner is the identity of the simple authentication mode
	// (TOOLMESH_AUTH_USER), granted every tool by the single-user and team
	// presets.
	Owner string
}

// ValidPreset reports whether name is a known preset.
func ValidPreset(name string) bool {
	switch name {
	case PresetSingleUser, PresetTeam, PresetOpen:
		return true
	}
	return false
}

// PresetGrants returns the grants of a preset.
func PresetGrants(name, owner string) ([]Grant, error) {
	var grants []Grant
	switch name {
	case PresetOpen:
		return []Grant{{Everyone: true, AllTools: true}}, nil
	case PresetTeam:
		grants = append(grants,
			Grant{Plan: PlanPro, AllTools: true},
			Grant{Plan: PlanFree, Access: []string{AccessRead}},
		)
		fallthrough
	case PresetSingleUser:
		grants = append(grants, Grant{Role: RoleAdmin, AllTools: true})
		if owner != "" {
			grants = append(grants, Grant{User: owner, AllTools: true})
		}
		return grants, nil
	}
	return nil, fmt.Errorf("unknown authorization preset %q (must be %q, %q or %q)", name, PresetSingleUser, PresetTeam, PresetOpen)
}

// ResolvePolicy picks the grants in effect. The first of these that is set
// wins: the config file, TOOLMESH_AUTHZ_PRESET, the preset recorded at an
// upgrade, the default preset. Denies, kits and approvers come from the
// config file only.
func ResolvePolicy(in PolicyInput) (Policy, error) {
	if in.File != nil {
		p := Policy{Preset: in.File.Preset, Source: SourceFile}
		if in.File.Preset != "" {
			base, err := PresetGrants(in.File.Preset, in.Owner)
			if err != nil {
				return Policy{}, err
			}
			p.Grants = append(p.Grants, base...)
		}
		p.Grants = append(p.Grants, in.File.Grants...)
		p.Denies = in.File.Denies
		p.Kits = kitsFromFile(in.File.Kits)
		p.Approvers = normalizeApprovers(in.File.Approvers)
		return p, nil
	}

	name, source := in.DefaultPreset, SourceDefault
	switch {
	case in.EnvPreset != "":
		name, source = in.EnvPreset, SourceEnv
	case in.UpgradePreset != "":
		name, source = in.UpgradePreset, SourceUpgrade
	}
	grants, err := PresetGrants(name, in.Owner)
	if err != nil {
		return Policy{}, err
	}
	return Policy{Preset: name, Source: source, Grants: grants}, nil
}

// OpenToEveryone reports whether the policy lets every authenticated caller
// execute every tool, which is what running without authorization amounts to.
func (p Policy) OpenToEveryone() bool {
	return slices.ContainsFunc(p.Grants, func(g Grant) bool { return g.Everyone && g.AllTools })
}

// LoadFile reads the authz config file. A file that does not exist is not an
// error: it returns nil and the preset applies. A file that exists must be
// valid, otherwise authorization would silently differ from what it says.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read authz config: %w", err)
	}
	return ParseFile(data)
}

// ParseFile parses and validates the content of an authz config file.
func ParseFile(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse authz config: %w", err)
	}
	if f.Preset != "" && !ValidPreset(f.Preset) {
		return nil, fmt.Errorf("authz config: unknown preset %q (must be %q, %q or %q)", f.Preset, PresetSingleUser, PresetTeam, PresetOpen)
	}
	for i, g := range f.Grants {
		if err := g.Validate(); err != nil {
			return nil, fmt.Errorf("authz config: grant %d: %w", i+1, err)
		}
	}
	for i, g := range f.Denies {
		if err := g.Validate(); err != nil {
			return nil, fmt.Errorf("authz config: deny %d: %w", i+1, err)
		}
	}
	kits := kitsFromFile(f.Kits)
	if err := validateKits(kits); err != nil {
		return nil, fmt.Errorf("authz config: %w", err)
	}
	if err := validateApprovers(f.Approvers, kits); err != nil {
		return nil, fmt.Errorf("authz config: %w", err)
	}
	return &f, nil
}

// Validate checks that the grant names exactly one subject and at least one
// target, and no empty names.
func (g Grant) Validate() error {
	subjects := 0
	for _, set := range []bool{g.User != "", g.Role != "", g.Plan != "", g.Company != "", g.Everyone} {
		if set {
			subjects++
		}
	}
	if subjects != 1 {
		return errors.New("name exactly one of user, role, plan, company or everyone")
	}
	if !g.AllTools && len(g.Backends) == 0 && len(g.Tools) == 0 && len(g.Access) == 0 {
		return errors.New("name at least one of all_tools, backends, tools or access")
	}
	for _, list := range [][]string{g.Backends, g.Tools, g.Access} {
		for _, name := range list {
			if strings.TrimSpace(name) == "" {
				return errors.New("backends, tools and access must not contain empty names")
			}
		}
	}
	return nil
}

// subject returns the OpenFGA user the grant applies to.
func (g Grant) subject() string {
	switch {
	case g.User != "":
		return "user:" + escapeID(g.User)
	case g.Role != "":
		return "role:" + escapeID(g.Role) + "#assignee"
	case g.Plan != "":
		return "plan:" + escapeID(g.Plan) + "#subscriber"
	case g.Company != "":
		return "company:" + escapeID(g.Company) + "#member"
	default:
		return "user:*"
	}
}

// tuples returns the store tuples that express the grant: with relExecutor
// for a grant, with relBlocked for a deny.
func (g Grant) tuples(relation string) []tupleKey {
	user := g.subject()
	var out []tupleKey
	add := func(object string) {
		out = append(out, tupleKey{User: user, Relation: relation, Object: object})
	}
	if g.AllTools {
		add(objInstance)
	}
	for _, b := range g.Backends {
		add("backend:" + escapeID(b))
	}
	for _, t := range g.Tools {
		add("tool:" + escapeID(t))
	}
	for _, a := range g.Access {
		add("access_class:" + escapeID(a))
	}
	return out
}
