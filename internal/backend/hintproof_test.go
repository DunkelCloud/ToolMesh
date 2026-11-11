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

package backend

import (
	"strings"
	"testing"
	"time"
)

const (
	hintTestBackend = "wiki"
	hintTestText    = "Page names follow the naming rules; read them before creating a page."
	hintTestWrite   = "write"
)

func TestBackendInfo_HintRequired(t *testing.T) {
	cases := []struct {
		name   string
		info   BackendInfo
		access string
		want   bool
	}{
		{"listed class", BackendInfo{Hint: hintTestText, HintRequiredFor: []string{hintTestWrite}}, hintTestWrite, true},
		{"class not listed", BackendInfo{Hint: hintTestText, HintRequiredFor: []string{hintTestWrite}}, accessStubClassR, false},
		{"class matches without regard to case", BackendInfo{Hint: hintTestText, HintRequiredFor: []string{"Write"}}, hintTestWrite, true},
		{"all matches a classified tool", BackendInfo{Hint: hintTestText, HintRequiredFor: []string{HintAccessAll}}, accessStubClassR, true},
		{"all matches an unclassified tool", BackendInfo{Hint: hintTestText, HintRequiredFor: []string{HintAccessAll}}, "", true},
		{"a class does not match an unclassified tool", BackendInfo{Hint: hintTestText, HintRequiredFor: []string{hintTestWrite}}, "", false},
		{"no hint, nothing to require", BackendInfo{HintRequiredFor: []string{hintTestWrite}}, hintTestWrite, false},
		{"hint as advice only", BackendInfo{Hint: hintTestText}, hintTestWrite, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.HintRequired(tc.access); got != tc.want {
				t.Errorf("HintRequired(%q) = %v, want %v", tc.access, got, tc.want)
			}
		})
	}
}

// A proof holds for one UTC day, one backend and one wording of the hint.
func TestHintProof(t *testing.T) {
	lateEvening := time.Date(2026, 3, 14, 23, 59, 0, 0, time.UTC)
	proof := HintProof(hintTestBackend, hintTestText, lateEvening)

	name, ok := HintProofBackend(proof)
	if !ok || name != hintTestBackend {
		t.Fatalf("HintProofBackend(%q) = %q, %v", proof, name, ok)
	}
	if digest := strings.TrimPrefix(proof, hintTestBackend+":"); len(digest) != hintProofDigestLen {
		t.Errorf("digest %q has %d characters, want %d", digest, len(digest), hintProofDigestLen)
	}

	same := []struct {
		name string
		got  string
	}{
		{"earlier the same day", HintProof(hintTestBackend, hintTestText, time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC))},
		{"same UTC day in another zone", HintProof(hintTestBackend, hintTestText, time.Date(2026, 3, 15, 1, 0, 0, 0, time.FixedZone("east", 2*3600)))},
		{"hint with surrounding whitespace", HintProof(hintTestBackend, "  "+hintTestText+"\n", lateEvening)},
	}
	for _, tc := range same {
		if tc.got != proof {
			t.Errorf("%s: proof = %q, want %q", tc.name, tc.got, proof)
		}
	}

	different := []struct {
		name string
		got  string
	}{
		{"a minute later, the next day", HintProof(hintTestBackend, hintTestText, lateEvening.Add(time.Minute))},
		{"changed hint", HintProof(hintTestBackend, hintTestText+" Ask before renaming.", lateEvening)},
		{"other backend", HintProof("tickets", hintTestText, lateEvening)},
	}
	for _, tc := range different {
		if tc.got == proof {
			t.Errorf("%s: proof did not change", tc.name)
		}
	}
}

func TestHintProofBackend(t *testing.T) {
	cases := []struct {
		proof    string
		wantName string
		wantOK   bool
	}{
		{"wiki:0123456789abcdef", "wiki", true},
		{"scope:wiki:0123456789abcdef", "scope:wiki", true},
		{"0123456789abcdef", "", false},
		{":0123456789abcdef", "", false},
		{"wiki:", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		name, ok := HintProofBackend(tc.proof)
		if name != tc.wantName || ok != tc.wantOK {
			t.Errorf("HintProofBackend(%q) = %q, %v, want %q, %v", tc.proof, name, ok, tc.wantName, tc.wantOK)
		}
	}
}

// An entry that requires a hint it does not have would look protected and
// deliver nothing; the parse refuses it.
func TestUnmarshalBackendConfig_HintRequiredFor(t *testing.T) {
	const valid = `
backends:
  - name: wiki
    transport: rest
    dadl: wiki.dadl
    hint: "Read the naming rules before creating a page."
    hint_required_for: [write, dangerous]
`
	var cfg BackendConfig
	if err := UnmarshalBackendConfig([]byte(valid), &cfg); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if got := cfg.Backends[0].HintRequiredFor; len(got) != 2 || got[0] != hintTestWrite || got[1] != "dangerous" {
		t.Errorf("HintRequiredFor = %v, want [write dangerous]", got)
	}

	invalid := map[string]string{
		"no hint": `
backends:
  - name: wiki
    transport: rest
    dadl: wiki.dadl
    hint_required_for: [write]
`,
		"empty class": `
backends:
  - name: wiki
    transport: rest
    dadl: wiki.dadl
    hint: "Read the naming rules before creating a page."
    hint_required_for: [write, ""]
`,
	}
	for name, doc := range invalid {
		var c BackendConfig
		err := UnmarshalBackendConfig([]byte(doc), &c)
		if err == nil || !strings.Contains(err.Error(), "hint_required_for") {
			t.Errorf("%s: err = %v, want an error naming hint_required_for", name, err)
		}
	}
}
