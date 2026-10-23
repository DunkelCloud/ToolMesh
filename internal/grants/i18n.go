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
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// approveI18nDir holds the approval page's texts, one catalog per language
// as <code>.json. en.json is the reference: every other catalog carries its
// keys and placeholders, and the page falls back to it. A new language is a
// new file.
const approveI18nDir = "web/i18n"

// approveI18nAsset is the script that hands the catalogs to the page.
const approveI18nAsset = "i18n.js"

// approveI18nScript is i18n.js: window.ToolMeshI18n maps each language code
// to its catalog.
var approveI18nScript = mustI18nScript(webFiles)

func mustI18nScript(fsys fs.FS) []byte {
	js, err := i18nScript(fsys)
	if err != nil {
		panic(err)
	}
	return js
}

// i18nScript builds i18n.js from the catalogs in fsys.
func i18nScript(fsys fs.FS) ([]byte, error) {
	cats, err := readCatalogs(fsys)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(cats)
	if err != nil {
		return nil, fmt.Errorf("encode the approval page catalogs: %w", err)
	}
	return append(append([]byte("window.ToolMeshI18n = "), data...), ";\n"...), nil
}

// readCatalogs returns the catalogs in fsys by language code.
func readCatalogs(fsys fs.FS) (map[string]json.RawMessage, error) {
	entries, err := fs.ReadDir(fsys, approveI18nDir)
	if err != nil {
		return nil, fmt.Errorf("read the approval page catalogs: %w", err)
	}
	cats := make(map[string]json.RawMessage, len(entries))
	for _, e := range entries {
		code, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(approveI18nDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read the approval page catalog %s: %w", e.Name(), err)
		}
		if !json.Valid(data) {
			return nil, fmt.Errorf("the approval page catalog %s is not valid JSON", e.Name())
		}
		cats[code] = data
	}
	if _, ok := cats["en"]; !ok {
		return nil, errors.New("the approval page catalog en.json is missing")
	}
	return cats, nil
}
