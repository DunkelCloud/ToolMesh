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

// Package toolindex provides an in-memory BM25 ranking index over tool
// descriptors. It powers free-text discovery (discover_tools `query`
// parameter and the toolmesh.discover() sandbox helper) without any
// external dependency: the corpus is a few thousand short documents that
// rebuild in milliseconds, so no persistence layer is needed.
package toolindex

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// BM25 free parameters. Standard values from the literature; the corpus
// (short tool descriptions) is not sensitive enough to warrant tuning knobs.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// nameBoost weights name tokens over description and parameter tokens.
// A query term matching the tool name is a much stronger signal than the
// same term appearing somewhere in prose.
const nameBoost = 3

// stopwords are high-frequency English tokens that carry no ranking signal
// in tool descriptions. Kept deliberately small: verbs like "list" or
// "create" are meaningful in this corpus and must stay searchable.
var stopwords = map[string]struct{}{
	"the": {}, "a": {}, "an": {}, "and": {}, "or": {}, "of": {}, "to": {},
	"in": {}, "for": {}, "on": {}, "with": {}, "by": {}, "all": {},
	"is": {}, "are": {}, "be": {}, "this": {}, "that": {}, "it": {},
	"as": {}, "at": {}, "from": {}, "use": {}, "using": {}, "via": {},
}

// Doc is one searchable entry in the index.
type Doc struct {
	// Name is the tool identifier (e.g. "netbox_list_devices"). Its tokens
	// are boosted in scoring.
	Name string
	// Description is the human-readable tool description.
	Description string
	// Extra holds additional searchable terms such as parameter names.
	Extra []string
}

// Result is a single ranked search hit.
type Result struct {
	Doc   Doc
	Score float64
}

// Index is an immutable BM25 index over a set of docs. Build once, query
// many times; rebuild from scratch when the tool set changes.
type Index struct {
	docs   []Doc
	docTF  []map[string]int
	docLen []int
	df     map[string]int
	avgLen float64
}

// Build constructs an index over the given docs. An empty slice yields a
// valid index that returns no results.
func Build(docs []Doc) *Index {
	ix := &Index{
		docs:   docs,
		docTF:  make([]map[string]int, len(docs)),
		docLen: make([]int, len(docs)),
		df:     make(map[string]int),
	}

	totalLen := 0
	for i, d := range docs {
		tf := make(map[string]int)
		addTokens(tf, Tokenize(d.Name), nameBoost)
		addTokens(tf, Tokenize(d.Description), 1)
		for _, e := range d.Extra {
			addTokens(tf, Tokenize(e), 1)
		}

		length := 0
		for term, n := range tf {
			length += n
			ix.df[term]++
		}
		ix.docTF[i] = tf
		ix.docLen[i] = length
		totalLen += length
	}

	if len(docs) > 0 {
		ix.avgLen = float64(totalLen) / float64(len(docs))
	}
	return ix
}

// Len returns the number of indexed docs.
func (ix *Index) Len() int {
	return len(ix.docs)
}

// Search returns the topK docs ranked by BM25 relevance to the free-text
// query. Docs matching no query term are omitted. topK <= 0 returns all
// matching docs. Ties are broken by name for deterministic output.
func (ix *Index) Search(query string, topK int) []Result {
	terms := Tokenize(query)
	if len(terms) == 0 || len(ix.docs) == 0 {
		return nil
	}

	n := float64(len(ix.docs))
	scores := make([]float64, len(ix.docs))
	matched := make([]bool, len(ix.docs))

	for _, term := range terms {
		df, ok := ix.df[term]
		if !ok {
			continue
		}
		idf := math.Log(1 + (n-float64(df)+0.5)/(float64(df)+0.5))
		for i, tf := range ix.docTF {
			f, ok := tf[term]
			if !ok {
				continue
			}
			norm := 1 - bm25B + bm25B*float64(ix.docLen[i])/ix.avgLen
			scores[i] += idf * float64(f) * (bm25K1 + 1) / (float64(f) + bm25K1*norm)
			matched[i] = true
		}
	}

	results := make([]Result, 0)
	for i, m := range matched {
		if m {
			results = append(results, Result{Doc: ix.docs[i], Score: scores[i]})
		}
	}

	sort.Slice(results, func(a, b int) bool {
		if results[a].Score != results[b].Score {
			return results[a].Score > results[b].Score
		}
		return results[a].Doc.Name < results[b].Doc.Name
	})

	if topK > 0 && len(results) > topK {
		results = results[:topK]
	}
	return results
}

// addTokens accumulates tokens into a term-frequency map with the given
// per-occurrence weight.
func addTokens(tf map[string]int, tokens []string, weight int) {
	for _, t := range tokens {
		tf[t] += weight
	}
}

// Tokenize splits text into lowercase search tokens. It splits on any
// non-alphanumeric rune (which covers snake_case and kebab-case) and on
// lower-to-upper camelCase boundaries, drops single-rune tokens and
// stopwords. Exported so callers can preview how a query is interpreted.
func Tokenize(text string) []string {
	if text == "" {
		return nil
	}

	tokens := make([]string, 0, 8)
	var sb strings.Builder
	var prev rune

	flush := func() {
		if sb.Len() == 0 {
			return
		}
		tok := strings.ToLower(sb.String())
		sb.Reset()
		if len(tok) < 2 {
			return
		}
		if _, stop := stopwords[tok]; stop {
			return
		}
		tokens = append(tokens, tok)
	}

	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			// Split camelCase: a lower→upper transition starts a new token.
			if unicode.IsUpper(r) && unicode.IsLower(prev) {
				flush()
			}
			sb.WriteRune(r)
		default:
			flush()
		}
		prev = r
	}
	flush()

	return tokens
}
