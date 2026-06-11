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

package toolindex

import (
	"reflect"
	"sort"
	"testing"
)

// Shared fixture literals, hoisted to satisfy goconst.
const (
	testToolNetboxDevices = "netbox_list_devices"
	testToolCloudflareDNS = "cloudflare_create_dns_record"
	testTokenDNS          = "dns"
	testTokenDevices      = "devices"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "snake case tool name",
			in:   testToolNetboxDevices,
			want: []string{"netbox", "list", testTokenDevices},
		},
		{
			name: "camel case",
			in:   "createDnsRecord",
			want: []string{"create", testTokenDNS, "record"},
		},
		{
			name: "prose with stopwords",
			in:   "List all devices in the rack",
			want: []string{"list", testTokenDevices, "rack"},
		},
		{
			name: "kebab and digits kept",
			in:   "mikrotik-sw-10g",
			want: []string{"mikrotik", "sw", "10g"},
		},
		{
			name: "single runes dropped",
			in:   "a b c dns",
			want: []string{testTokenDNS},
		},
		{
			name: "empty",
			in:   "",
			want: nil,
		},
		{
			name: "punctuation only",
			in:   "( ) , .",
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Tokenize(tt.in)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Tokenize(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func buildTestIndex() *Index {
	return Build([]Doc{
		{
			Name:        testToolCloudflareDNS,
			Description: "Create a DNS record in a Cloudflare zone",
			Extra:       []string{"zone_id", "type", "name", "content"},
		},
		{
			Name:        "cloudflare_list_zones",
			Description: "List all zones in the Cloudflare account",
			Extra:       []string{"page", "per_page"},
		},
		{
			Name:        "hetzner_list_dns_zones",
			Description: "List DNS zones managed by Hetzner",
			Extra:       []string{"page"},
		},
		{
			Name:        testToolNetboxDevices,
			Description: "List all devices (servers, switches, routers, firewalls, etc.)",
			Extra:       []string{"site", "rack_id", "status"},
		},
		{
			Name:        "github_create_issue",
			Description: "Create an issue in a repository",
			Extra:       []string{"owner", "repo", "title", "body"},
		},
	})
}

func TestSearchRanking(t *testing.T) {
	ix := buildTestIndex()

	tests := []struct {
		name      string
		query     string
		topK      int
		wantFirst string   // expected top result, empty to skip
		wantSet   []string // expected result names in any order, nil to skip
	}{
		{
			name:  "dns finds dns tools across backends",
			query: testTokenDNS,
			topK:  0,
			// Both DNS tools must surface; their relative order is a
			// length-normalization detail we do not pin down.
			wantSet: []string{testToolCloudflareDNS, "hetzner_list_dns_zones"},
		},
		{
			name:      "name match beats description match",
			query:     testTokenDevices,
			topK:      0,
			wantFirst: testToolNetboxDevices,
		},
		{
			name:      "multi term query",
			query:     "create dns record cloudflare",
			topK:      1,
			wantFirst: testToolCloudflareDNS,
		},
		{
			name:      "param names are searchable",
			query:     "rack_id",
			topK:      0,
			wantFirst: testToolNetboxDevices,
		},
		{
			name:      "free text question style",
			query:     "how to create an issue on github",
			topK:      1,
			wantFirst: "github_create_issue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ix.Search(tt.query, tt.topK)
			if len(got) == 0 {
				t.Fatalf("Search(%q) returned no results", tt.query)
			}
			if tt.wantFirst != "" && got[0].Doc.Name != tt.wantFirst {
				t.Errorf("Search(%q) first = %s, want %s", tt.query, got[0].Doc.Name, tt.wantFirst)
			}
			if tt.wantSet != nil {
				names := make([]string, len(got))
				for i, r := range got {
					names[i] = r.Doc.Name
				}
				sort.Strings(names)
				want := append([]string(nil), tt.wantSet...)
				sort.Strings(want)
				if !reflect.DeepEqual(names, want) {
					t.Errorf("Search(%q) = %v, want %v", tt.query, names, want)
				}
			}
		})
	}
}

func TestSearchEdgeCases(t *testing.T) {
	ix := buildTestIndex()

	t.Run("empty query returns nil", func(t *testing.T) {
		if got := ix.Search("", 10); got != nil {
			t.Errorf("Search(\"\") = %v, want nil", got)
		}
	})

	t.Run("stopword only query returns nil", func(t *testing.T) {
		if got := ix.Search("the all of", 10); got != nil {
			t.Errorf("Search(stopwords) = %v, want nil", got)
		}
	})

	t.Run("no match returns empty", func(t *testing.T) {
		if got := ix.Search("kubernetes", 10); len(got) != 0 {
			t.Errorf("Search(no match) = %v, want empty", got)
		}
	})

	t.Run("topK limits results", func(t *testing.T) {
		got := ix.Search("list", 2)
		if len(got) != 2 {
			t.Errorf("Search topK=2 returned %d results", len(got))
		}
	})

	t.Run("empty index", func(t *testing.T) {
		empty := Build(nil)
		if empty.Len() != 0 {
			t.Errorf("empty index Len() = %d", empty.Len())
		}
		if got := empty.Search(testTokenDNS, 5); got != nil {
			t.Errorf("empty index Search = %v, want nil", got)
		}
	})

	t.Run("deterministic tie break by name", func(t *testing.T) {
		ix2 := Build([]Doc{
			{Name: "b_tool", Description: "frobnicate widgets"},
			{Name: "a_tool", Description: "frobnicate widgets"},
		})
		got := ix2.Search("frobnicate", 0)
		if len(got) != 2 || got[0].Doc.Name != "a_tool" {
			t.Errorf("tie break order = %v", got)
		}
	})
}
