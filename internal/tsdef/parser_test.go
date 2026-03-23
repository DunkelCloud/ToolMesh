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

package tsdef

import (
	"testing"
)

func TestParseSimpleFunction(t *testing.T) {
	src := `/** Search for items */
export function search(params: {
  /** The search query */
  query: string;
  /** Maximum results */
  limit: number;
}): Promise<any>;`

	defs, err := ParseSource(src, "test.ts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(defs) != 1 {
		t.Fatalf("expected 1 def, got %d", len(defs))
	}

	d := defs[0]
	if d.Name != "search" {
		t.Errorf("name = %q, want %q", d.Name, "search")
	}
	if d.Description != "Search for items" {
		t.Errorf("description = %q, want %q", d.Description, "Search for items")
	}
	if len(d.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(d.Params))
	}

	q := d.Params[0]
	if q.Name != "query" {
		t.Errorf("param[0].name = %q, want %q", q.Name, "query")
	}
	if q.Type.Kind != kindString {
		t.Errorf("param[0].type = %q, want %q", q.Type.Kind, kindString)
	}
	if !q.Required {
		t.Error("param[0] should be required")
	}
	if q.Description != "The search query" {
		t.Errorf("param[0].description = %q, want %q", q.Description, "The search query")
	}
}

func TestParseOptionalParams(t *testing.T) {
	src := `/** Fetch data */
export function fetch(params: {
  url: string;
  timeout?: number;
}): Promise<any>;`

	defs, _ := ParseSource(src, "test.ts")
	if len(defs) != 1 {
		t.Fatalf("expected 1 def, got %d", len(defs))
	}

	if len(defs[0].Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(defs[0].Params))
	}

	url := defs[0].Params[0]
	if !url.Required {
		t.Error("url should be required")
	}

	timeout := defs[0].Params[1]
	if timeout.Required {
		t.Error("timeout should be optional")
	}
}

func TestParseEnumType(t *testing.T) {
	src := `/** Move */
export function move(params: {
  direction: "up" | "down" | "left" | "right";
}): Promise<any>;`

	defs, _ := ParseSource(src, "test.ts")
	if len(defs) != 1 || len(defs[0].Params) != 1 {
		t.Fatalf("expected 1 def with 1 param")
	}

	p := defs[0].Params[0]
	if len(p.Enum) != 4 {
		t.Errorf("expected 4 enum values, got %d: %v", len(p.Enum), p.Enum)
	}
	if p.Enum[0] != "up" {
		t.Errorf("enum[0] = %q, want %q", p.Enum[0], "up")
	}
}

func TestParseNoParams(t *testing.T) {
	src := `/** Get time */
export function time(): Promise<any>;`

	defs, _ := ParseSource(src, "test.ts")
	if len(defs) != 1 {
		t.Fatalf("expected 1 def, got %d", len(defs))
	}
	if len(defs[0].Params) != 0 {
		t.Errorf("expected 0 params, got %d", len(defs[0].Params))
	}
}

func TestParseMultipleFunctions(t *testing.T) {
	src := `/** Tool A */
export function toolA(): Promise<any>;

/** Tool B */
export function toolB(params: {
  x: number;
}): Promise<any>;

/** Tool C */
export function toolC(params: {
  y: string;
}): Promise<any>;`

	defs, _ := ParseSource(src, "test.ts")
	if len(defs) != 3 {
		t.Fatalf("expected 3 defs, got %d", len(defs))
	}
	if defs[0].Name != "toolA" || defs[1].Name != "toolB" || defs[2].Name != "toolC" {
		t.Errorf("names = %q %q %q", defs[0].Name, defs[1].Name, defs[2].Name)
	}
}

func TestParseArrayTypes(t *testing.T) {
	src := `/** Tags */
export function setTags(params: {
  tags: string[];
  scores: number[];
}): Promise<any>;`

	defs, _ := ParseSource(src, "test.ts")
	if len(defs) != 1 || len(defs[0].Params) != 2 {
		t.Fatalf("expected 1 def with 2 params")
	}

	tags := defs[0].Params[0]
	if tags.Type.Kind != kindArray || tags.Type.ItemKind != kindString {
		t.Errorf("tags type = %v, want array of string", tags.Type)
	}
}

func TestParseEchoTS(t *testing.T) {
	src := `/** Echoes back the input message */
export function echo(params: {
  /** Message to echo back */
  message: string;
}): Promise<any>;

/** Adds two numbers */
export function add(params: {
  /** First number */
  a: number;
  /** Second number */
  b: number;
}): Promise<any>;

/** Returns the current UTC time */
export function time(): Promise<any>;`

	defs, err := ParseSource(src, "echo.ts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(defs) != 3 {
		t.Fatalf("expected 3 defs, got %d", len(defs))
	}

	if defs[0].Name != "echo" {
		t.Errorf("defs[0].name = %q", defs[0].Name)
	}
	if defs[1].Name != "add" {
		t.Errorf("defs[1].name = %q", defs[1].Name)
	}
	if defs[2].Name != "time" {
		t.Errorf("defs[2].name = %q", defs[2].Name)
	}
	if len(defs[0].Params) != 1 {
		t.Errorf("echo params = %d", len(defs[0].Params))
	}
	if len(defs[1].Params) != 2 {
		t.Errorf("add params = %d", len(defs[1].Params))
	}
	if len(defs[2].Params) != 0 {
		t.Errorf("time params = %d", len(defs[2].Params))
	}
}

func TestParseEmptySource(t *testing.T) {
	defs, err := ParseSource("", "empty.ts")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(defs) != 0 {
		t.Errorf("expected 0 defs, got %d", len(defs))
	}
}
