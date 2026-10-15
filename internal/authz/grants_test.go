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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFile_Errors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"unknown field", "grants:\n  - role: admin\n    all_tool: true\n", "field all_tool not found"},
		{"unknown top-level field", "presets: team\n", "field presets not found"},
		{"two subjects", "grants:\n  - role: admin\n    plan: pro\n    all_tools: true\n", "grant 1: name exactly one of"},
		{"no subject", "grants:\n  - all_tools: true\n", "grant 1: name exactly one of"},
		{"no target", "grants:\n  - role: admin\n", "grant 1: name at least one of"},
		{"empty name", "grants:\n  - role: admin\n    backends: [\"\"]\n", "must not contain empty names"},
		{"unknown preset", "preset: everyone\n", "unknown preset"},
		{"not yaml", "grants: [", "parse authz config"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseFile_EmptyFileGrantsNothing(t *testing.T) {
	f, err := ParseFile(nil)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	p, err := ResolvePolicy(PolicyInput{File: f, EnvPreset: PresetOpen, DefaultPreset: PresetTeam})
	if err != nil {
		t.Fatalf("ResolvePolicy: %v", err)
	}
	if len(p.Grants) != 0 || p.Source != SourceFile {
		t.Errorf("policy = %+v, want no grants from the file", p)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	f, err := LoadFile(filepath.Join(dir, "missing.yaml"))
	if err != nil || f != nil {
		t.Fatalf("missing file: %v, %v; want nil, nil", f, err)
	}
	path := filepath.Join(dir, "authz.yaml")
	if err := os.WriteFile(path, []byte("preset: single-user\ngrants:\n  - plan: pro\n    backends: [github]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err = LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if f.Preset != PresetSingleUser || len(f.Grants) != 1 || f.Grants[0].Backends[0] != testGitHub {
		t.Errorf("file = %+v", f)
	}
}

func TestResolvePolicy_Precedence(t *testing.T) {
	file := &File{Preset: PresetSingleUser, Grants: []Grant{{Plan: PlanPro, Backends: []string{testGitHub}}}}
	tests := []struct {
		name       string
		in         PolicyInput
		wantPreset string
		wantSource string
		wantGrants int
	}{
		{"file wins and adds its preset", PolicyInput{File: file, EnvPreset: PresetOpen, UpgradePreset: PresetOpen, DefaultPreset: PresetTeam, Owner: testOwner}, PresetSingleUser, SourceFile, 3},
		{"env preset over upgrade", PolicyInput{EnvPreset: PresetTeam, UpgradePreset: PresetOpen, DefaultPreset: PresetSingleUser, Owner: testOwner}, PresetTeam, SourceEnv, 4},
		{"upgrade over default", PolicyInput{UpgradePreset: PresetOpen, DefaultPreset: PresetSingleUser, Owner: testOwner}, PresetOpen, SourceUpgrade, 1},
		{"default", PolicyInput{DefaultPreset: PresetSingleUser, Owner: testOwner}, PresetSingleUser, SourceDefault, 2},
		{"default without owner", PolicyInput{DefaultPreset: PresetSingleUser}, PresetSingleUser, SourceDefault, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ResolvePolicy(tc.in)
			if err != nil {
				t.Fatalf("ResolvePolicy: %v", err)
			}
			if p.Preset != tc.wantPreset || p.Source != tc.wantSource || len(p.Grants) != tc.wantGrants {
				t.Errorf("policy = %s/%s with %d grants, want %s/%s with %d", p.Preset, p.Source, len(p.Grants), tc.wantPreset, tc.wantSource, tc.wantGrants)
			}
		})
	}
	if _, err := ResolvePolicy(PolicyInput{EnvPreset: "everyone"}); err == nil {
		t.Error("unknown env preset accepted")
	}
}

func TestPolicy_OpenToEveryone(t *testing.T) {
	for _, preset := range []string{PresetSingleUser, PresetTeam, PresetOpen} {
		grants, err := PresetGrants(preset, testOwner)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := (Policy{Grants: grants}).OpenToEveryone(), preset == PresetOpen; got != want {
			t.Errorf("preset %s: OpenToEveryone = %v, want %v", preset, got, want)
		}
	}
	if (Policy{Grants: []Grant{{Everyone: true, Backends: []string{testEcho}}}}).OpenToEveryone() {
		t.Error("a grant of one backend to everyone counts as open")
	}
}

func TestPresetGrantsAreValid(t *testing.T) {
	for _, preset := range []string{PresetSingleUser, PresetTeam, PresetOpen} {
		grants, err := PresetGrants(preset, testOwner)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range grants {
			if err := g.Validate(); err != nil {
				t.Errorf("preset %s: invalid grant %+v: %v", preset, g, err)
			}
		}
	}
}

// The shipped example must stay a valid authz config file.
func TestExampleFileParses(t *testing.T) {
	f, err := LoadFile(filepath.Join("..", "..", "config", "authz.yaml.example"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if f == nil || f.Preset == "" || len(f.Grants) == 0 {
		t.Errorf("example parsed to %+v, want a preset and grants", f)
	}
}
