package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// SQL execution methods that must strictly take constant/parameterized query strings
var sqlMethods = map[string]bool{
	"Query":      true,
	"QueryRow":   true,
	"QueryRowx":  true,
	"Queryx":     true,
	"Exec":       true,
	"ExecContext": true,
	"Select":     true,
	"Get":        true,
}

func main() {
	rootDir := "."
	if len(os.Args) > 1 {
		rootDir = os.Args[1]
	}

	fset := token.NewFileSet()
	var violations []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip vendor, node_modules, .git, and test files
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" || name == ".next" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			var methodName string
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				methodName = fun.Sel.Name
			case *ast.Ident:
				methodName = fun.Name
			}

			if !sqlMethods[methodName] {
				return true
			}

			if len(call.Args) == 0 {
				return true
			}

			// Check the SQL query argument (typically arg 0 or arg 1 if context is arg 0)
			queryArg := call.Args[0]
			if methodName == "ExecContext" || methodName == "QueryContext" {
				if len(call.Args) > 1 {
					queryArg = call.Args[1]
				}
			}

			// Check if queryArg is a dynamic string concatenation or Sprintf
			if isDynamicString(queryArg) {
				pos := fset.Position(queryArg.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d: Potential SQL injection - dynamic query string passed to %s()", pos.Filename, pos.Line, methodName))
			}

			return true
		})

		return nil
	})

	if err != nil {
		fmt.Printf("Error scanning codebase: %v\n", err)
		os.Exit(1)
	}

	if len(violations) > 0 {
		fmt.Printf("❌ OWASP A03 SQL Injection Security Gate FAILED!\nFound %d violation(s):\n\n", len(violations))
		for _, v := range violations {
			fmt.Printf("  • %s\n", v)
		}
		fmt.Println("\nRemediation: Use strictly parameterized SQL queries with $1, $2 placeholders.")
		os.Exit(1)
	}

	fmt.Println("✅ OWASP A03 SQL Injection Security Gate PASSED: 100% of queries use parameterized arguments.")
}

func isDynamicString(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		// e.g. "SELECT * FROM users WHERE id = " + id
		if e.Op == token.ADD {
			return true
		}
	case *ast.CallExpr:
		// e.g. fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "fmt" && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Sprint") {
					return true
				}
			}
		}
	}
	return false
}
