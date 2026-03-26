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
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/file"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/unistring"
)

// Violation represents a single static analysis finding.
type Violation struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// scanBlocklist is the set of identifiers that are forbidden in composite code.
var scanBlocklist = map[unistring.String]bool{
	"fetch":          true,
	"XMLHttpRequest": true,
	"require":        true,
	"import":         true,
	"process":        true,
	"fs":             true,
	"os":             true,
	"child_process":  true,
	"globalThis":     true,
	"setTimeout":     true,
	"setInterval":    true,
	"setImmediate":   true,
	"clearTimeout":   true,
	"clearInterval":  true,
	"clearImmediate": true,
	"window":         true,
	"self":           true,
	"global":         true,
}

// ScanCode performs static analysis on composite JavaScript code.
// It parses the code and walks the AST looking for:
//   - Identifier nodes matching the blocklist
//   - CallExpression nodes calling eval/Function
//   - DotExpression nodes accessing globalThis/window/self
//
// Returns a list of violations with line numbers.
func ScanCode(code string, compositeName string) ([]Violation, error) {
	// Wrap in async IIFE to allow await at top level (mirrors runtime behavior)
	wrappedCode := "(async function() {\n" + code + "\n})()"
	fileSet := &file.FileSet{}
	program, err := parser.ParseFile(fileSet, compositeName, wrappedCode, 0)
	if err != nil {
		return nil, fmt.Errorf("parse composite %s: %w", compositeName, err)
	}

	var violations []Violation
	walkNode(program, fileSet, &violations)

	// Adjust line numbers to account for the wrapper (line 1 = async function wrapper)
	for i := range violations {
		if violations[i].Line > 0 {
			violations[i].Line--
		}
	}

	return violations, nil
}

// walkNode recursively walks an AST node and collects violations.
func walkNode(node ast.Node, fileSet *file.FileSet, violations *[]Violation) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.Program:
		for _, stmt := range n.Body {
			walkStatement(stmt, fileSet, violations)
		}

	case *ast.Identifier:
		checkIdentifier(n, fileSet, violations)

	case *ast.CallExpression:
		// Check if calling eval or Function
		if ident, ok := n.Callee.(*ast.Identifier); ok {
			if ident.Name == "eval" || ident.Name == "Function" {
				pos := resolvePosition(fileSet, ident.Idx)
				*violations = append(*violations, Violation{
					Line:    pos.Line,
					Column:  pos.Column,
					Message: fmt.Sprintf("forbidden call to %s()", string(ident.Name)),
				})
			}
		}
		walkExpression(n.Callee, fileSet, violations)
		for _, arg := range n.ArgumentList {
			walkExpression(arg, fileSet, violations)
		}

	case *ast.DotExpression:
		// Check if accessing globalThis.*, window.*, self.*
		if ident, ok := n.Left.(*ast.Identifier); ok {
			if ident.Name == "globalThis" || ident.Name == "window" || ident.Name == "self" {
				pos := resolvePosition(fileSet, ident.Idx)
				*violations = append(*violations, Violation{
					Line:    pos.Line,
					Column:  pos.Column,
					Message: fmt.Sprintf("forbidden access to %s.%s", string(ident.Name), string(n.Identifier.Name)),
				})
				// Don't walk left side again — already reported
				break
			}
		}
		walkExpression(n.Left, fileSet, violations)

	default:
		walkChildren(node, fileSet, violations)
	}
}

func checkIdentifier(ident *ast.Identifier, fileSet *file.FileSet, violations *[]Violation) {
	if scanBlocklist[ident.Name] {
		pos := resolvePosition(fileSet, ident.Idx)
		*violations = append(*violations, Violation{
			Line:    pos.Line,
			Column:  pos.Column,
			Message: fmt.Sprintf("forbidden identifier: %s", string(ident.Name)),
		})
	}
}

func resolvePosition(fileSet *file.FileSet, idx file.Idx) file.Position {
	return fileSet.Position(idx)
}

// walkExpression walks an expression node.
func walkExpression(expr ast.Expression, fileSet *file.FileSet, violations *[]Violation) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		checkIdentifier(e, fileSet, violations)
	case *ast.CallExpression:
		walkNode(e, fileSet, violations)
	case *ast.DotExpression:
		walkNode(e, fileSet, violations)
	case *ast.BinaryExpression:
		walkExpression(e.Left, fileSet, violations)
		walkExpression(e.Right, fileSet, violations)
	case *ast.AssignExpression:
		walkExpression(e.Left, fileSet, violations)
		walkExpression(e.Right, fileSet, violations)
	case *ast.ConditionalExpression:
		walkExpression(e.Test, fileSet, violations)
		walkExpression(e.Consequent, fileSet, violations)
		walkExpression(e.Alternate, fileSet, violations)
	case *ast.UnaryExpression:
		walkExpression(e.Operand, fileSet, violations)
	case *ast.ArrayLiteral:
		for _, v := range e.Value {
			walkExpression(v, fileSet, violations)
		}
	case *ast.ObjectLiteral:
		for _, prop := range e.Value {
			// Property is an interface — handle concrete types
			switch p := prop.(type) {
			case *ast.PropertyKeyed:
				walkExpression(p.Key, fileSet, violations)
				walkExpression(p.Value, fileSet, violations)
			case *ast.PropertyShort:
				checkIdentifier(&p.Name, fileSet, violations)
				walkExpression(p.Initializer, fileSet, violations)
			case *ast.SpreadElement:
				walkExpression(p.Expression, fileSet, violations)
			}
		}
	case *ast.FunctionLiteral:
		walkStatement(e.Body, fileSet, violations)
	case *ast.ArrowFunctionLiteral:
		// ConciseBody can be ExpressionBody or BlockStatement
		switch body := e.Body.(type) {
		case *ast.BlockStatement:
			walkStatement(body, fileSet, violations)
		case *ast.ExpressionBody:
			walkExpression(body.Expression, fileSet, violations)
		}
	case *ast.SequenceExpression:
		for _, seq := range e.Sequence {
			walkExpression(seq, fileSet, violations)
		}
	case *ast.NewExpression:
		walkExpression(e.Callee, fileSet, violations)
		for _, arg := range e.ArgumentList {
			walkExpression(arg, fileSet, violations)
		}
	case *ast.BracketExpression:
		walkExpression(e.Left, fileSet, violations)
		walkExpression(e.Member, fileSet, violations)
	case *ast.TemplateLiteral:
		for _, expr := range e.Expressions {
			walkExpression(expr, fileSet, violations)
		}
	case *ast.SpreadElement:
		walkExpression(e.Expression, fileSet, violations)
	case *ast.AwaitExpression:
		walkExpression(e.Argument, fileSet, violations)
	case *ast.YieldExpression:
		walkExpression(e.Argument, fileSet, violations)
	}
}

// walkStatement walks a statement node.
func walkStatement(stmt ast.Statement, fileSet *file.FileSet, violations *[]Violation) {
	if stmt == nil {
		return
	}

	switch s := stmt.(type) {
	case *ast.BlockStatement:
		for _, stmt := range s.List {
			walkStatement(stmt, fileSet, violations)
		}
	case *ast.ExpressionStatement:
		walkExpression(s.Expression, fileSet, violations)
	case *ast.ReturnStatement:
		walkExpression(s.Argument, fileSet, violations)
	case *ast.VariableStatement:
		for _, binding := range s.List {
			walkExpression(binding.Initializer, fileSet, violations)
		}
	case *ast.LexicalDeclaration:
		for _, binding := range s.List {
			walkExpression(binding.Initializer, fileSet, violations)
		}
	case *ast.IfStatement:
		walkExpression(s.Test, fileSet, violations)
		walkStatement(s.Consequent, fileSet, violations)
		walkStatement(s.Alternate, fileSet, violations)
	case *ast.ForStatement:
		walkExpression(s.Test, fileSet, violations)
		walkExpression(s.Update, fileSet, violations)
		walkStatement(s.Body, fileSet, violations)
	case *ast.ForInStatement:
		walkExpression(s.Source, fileSet, violations)
		walkStatement(s.Body, fileSet, violations)
	case *ast.ForOfStatement:
		walkExpression(s.Source, fileSet, violations)
		walkStatement(s.Body, fileSet, violations)
	case *ast.WhileStatement:
		walkExpression(s.Test, fileSet, violations)
		walkStatement(s.Body, fileSet, violations)
	case *ast.DoWhileStatement:
		walkExpression(s.Test, fileSet, violations)
		walkStatement(s.Body, fileSet, violations)
	case *ast.SwitchStatement:
		walkExpression(s.Discriminant, fileSet, violations)
		for _, cs := range s.Body {
			walkExpression(cs.Test, fileSet, violations)
			for _, stmt := range cs.Consequent {
				walkStatement(stmt, fileSet, violations)
			}
		}
	case *ast.TryStatement:
		walkStatement(s.Body, fileSet, violations)
		if s.Catch != nil {
			walkStatement(s.Catch.Body, fileSet, violations)
		}
		if s.Finally != nil {
			walkStatement(s.Finally, fileSet, violations)
		}
	case *ast.ThrowStatement:
		walkExpression(s.Argument, fileSet, violations)
	case *ast.FunctionDeclaration:
		if s.Function != nil {
			walkStatement(s.Function.Body, fileSet, violations)
		}
	}
}

// walkChildren is a fallback for nodes not specifically handled.
func walkChildren(_ ast.Node, _ *file.FileSet, _ *[]Violation) {
	// Fallback — specific node types are handled by walkExpression/walkStatement
}
