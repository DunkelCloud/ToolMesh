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
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/dop251/goja"
)

// placeholderPattern finds the {name} placeholders of a text.
var placeholderPattern = regexp.MustCompile(`\{\w+\}`)

func placeholders(s string) []string {
	p := placeholderPattern.FindAllString(s, -1)
	slices.Sort(p)
	return slices.Compact(p)
}

// catalog returns the catalog of a language, decoded.
func catalog(t *testing.T, code string) map[string]any {
	t.Helper()
	cats, err := readCatalogs(webFiles)
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]any
	if err := json.Unmarshal(cats[code], &cat); err != nil {
		t.Fatalf("%s.json: %v", code, err)
	}
	return cat
}

// compareCatalog reports the keys of want that got lacks or holds as another
// kind of value, texts whose placeholders differ, and keys want lacks.
func compareCatalog(t *testing.T, code, path string, want, got map[string]any) {
	t.Helper()
	for k, wv := range want {
		p := path + k
		gv, ok := got[k]
		if !ok {
			t.Errorf("%s.json lacks %s", code, p)
			continue
		}
		switch w := wv.(type) {
		case string:
			g, ok := gv.(string)
			switch {
			case !ok:
				t.Errorf("%s.json: %s is not a text", code, p)
			case !slices.Equal(placeholders(w), placeholders(g)):
				t.Errorf("%s.json: %s has the placeholders %v, en.json %v", code, p, placeholders(g), placeholders(w))
			case w != "" && g == "":
				t.Errorf("%s.json: %s is empty", code, p)
			}
		case map[string]any:
			g, ok := gv.(map[string]any)
			if !ok {
				t.Errorf("%s.json: %s is not an object", code, p)
				continue
			}
			compareCatalog(t, code, p+".", w, g)
		default:
			t.Errorf("en.json: %s is neither a text nor an object", p)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s.json has %s%s, which en.json lacks", code, path, k)
		}
	}
}

// Every language carries the texts of en.json with the same placeholders,
// so that no text is missing in a language or drops a value.
func TestI18n_CatalogsMatchEnglish(t *testing.T) {
	cats, err := readCatalogs(webFiles)
	if err != nil {
		t.Fatal(err)
	}
	codes := make([]string, 0, len(cats))
	for code := range cats {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	if !slices.Equal(codes, []string{"de", "en", "es", "fr", "ja"}) {
		t.Errorf("languages = %v", codes)
	}
	en := catalog(t, "en")
	for _, code := range codes {
		if code != "en" {
			compareCatalog(t, code, "", en, catalog(t, code))
		}
	}
}

// Every text the page names exists in en.json, and every group ToolMesh
// sorts an entry into has a name and a description.
func TestI18n_PageTextsExist(t *testing.T) {
	en := catalog(t, "en")
	js, err := webFiles.ReadFile("web/approve.js")
	if err != nil {
		t.Fatal(err)
	}
	page, err := webFiles.ReadFile("web/approve.html")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, m := range regexp.MustCompile(`\b(?:t|pick|plural)\('(\w+)'`).FindAllStringSubmatch(string(js), -1) {
		keys[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`data-t="(\w+)"`).FindAllStringSubmatch(string(page), -1) {
		keys[m[1]] = true
	}
	// showInfo names these by the kind of page.
	for _, k := range []string{"setupTitle", "goneTitle", "goneText", "failedTitle", "failedText"} {
		keys[k] = true
	}
	if len(keys) < 60 {
		t.Fatalf("found only %d keys; do the patterns still match the page?", len(keys))
	}
	for k := range keys {
		if _, ok := en[k]; !ok {
			t.Errorf("the page uses %q, which en.json lacks", k)
		}
	}

	groups, _ := en["groups"].(map[string]any)
	descs, _ := en["groupDesc"].(map[string]any)
	// Every classification effectOf names, none, and one of an operator's own.
	for _, access := range strings.Split("|dangerous|admin|write|read|custom", "|") {
		for _, scope := range []bool{true, false} {
			effect, _ := effectOf(access, scope)
			if groups[effect] == nil || descs[effect] == nil {
				t.Errorf("en.json has no group text for the effect %q", effect)
			}
		}
	}
	levels, _ := en["lvl"].(map[string]any)
	for _, level := range []string{"high", "elevated", "medium", "low"} {
		if levels[level] == nil {
			t.Errorf("en.json has no name for the level %q", level)
		}
	}
}

// i18n.js runs as a script and hands the page every catalog.
func TestI18n_Script(t *testing.T) {
	if !strings.HasPrefix(string(approveI18nScript), "window.ToolMeshI18n = ") {
		t.Fatalf("i18n.js starts with %.40q", approveI18nScript)
	}
	vm := goja.New()
	if _, err := vm.RunString("var window = {};"); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunScript(approveI18nAsset, string(approveI18nScript)); err != nil {
		t.Fatalf("run i18n.js: %v", err)
	}
	v, err := vm.RunString("Object.keys(window.ToolMeshI18n).sort().join(',') + '|' + window.ToolMeshI18n.de.brand + '|' + window.ToolMeshI18n.ja.lvl.high")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.String(); got != "de,en,es,fr,ja|Freigabe|高" {
		t.Errorf("window.ToolMeshI18n = %s", got)
	}
}

func TestI18n_ScriptRefusesBrokenCatalogs(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"without en":   {"web/i18n/de.json": {Data: []byte(`{}`)}},
		"invalid JSON": {"web/i18n/en.json": {Data: []byte(`{"brand": `)}},
	} {
		if _, err := i18nScript(fsys); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	js, err := i18nScript(fstest.MapFS{
		"web/i18n/en.json":  {Data: []byte(`{"brand": "Approval"}`)},
		"web/i18n/notes.md": {Data: []byte(`not a catalog`)},
	})
	if err != nil || string(js) != "window.ToolMeshI18n = {\"en\":{\"brand\":\"Approval\"}};\n" {
		t.Errorf("i18nScript = %q, %v", js, err)
	}
}
