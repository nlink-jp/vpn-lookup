package mcp

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nlink-jp/vpn-lookup/internal/verdict"
)

// The manual is what an agent reads before its first call; these tests pin it
// to the code so that it cannot drift from the real tool set.

func listed(t *testing.T) []struct {
	Name        string `json:"name"`
	InputSchema struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	} `json:"inputSchema"`
} {
	t.Helper()
	b, err := json.Marshal(map[string]any{"tools": toolsList()})
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Type                 string                     `json:"type"`
				Properties           map[string]json.RawMessage `json:"properties"`
				AdditionalProperties *bool                      `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Tools) == 0 {
		t.Fatal("toolsList advertises nothing")
	}
	return l.Tools
}

func TestUsageMentionsEveryToolAndArgument(t *testing.T) {
	for _, tl := range listed(t) {
		if !strings.Contains(usageMarkdown, "`"+tl.Name+"`") {
			t.Errorf("usage.md never mentions the tool `%s`", tl.Name)
		}
		for arg := range tl.InputSchema.Properties {
			if !strings.Contains(usageMarkdown, "`"+arg+"`") {
				t.Errorf("usage.md never documents %s's %q argument", tl.Name, arg)
			}
		}
	}
}

// Every Tool* and Code* constant declared in this package must appear in the
// manual. Read from the source, so a new constant cannot slip past.
func TestUsageDocumentsEveryToolAndCodeConstant(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Tool") && !strings.HasPrefix(name.Name, "Code") {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				found++
				if !strings.Contains(usageMarkdown, "`"+v+"`") {
					t.Errorf("usage.md never mentions %s (`%s`)", name.Name, v)
				}
			}
			return true
		})
	}
	if found < 4 {
		t.Fatalf("only %d Tool*/Code* constants found; the scan is not seeing them", found)
	}
}

func TestInstructionsPointAtTheManual(t *testing.T) {
	if !strings.Contains(Instructions, "get_usage") {
		t.Error("Instructions should mention get_usage")
	}
}

// org ADR-021 §10: every registered schema sets additionalProperties:false,
// and this assertion exists because a rule stated only in prose is re-decided
// by whoever adds the next tool.
func TestEveryToolSchemaIsValidAndClosed(t *testing.T) {
	for _, tl := range listed(t) {
		if tl.InputSchema.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", tl.Name, tl.InputSchema.Type)
		}
		if tl.InputSchema.AdditionalProperties == nil || *tl.InputSchema.AdditionalProperties {
			t.Errorf("%s: schema should set additionalProperties:false", tl.Name)
		}
	}
}

// The manual must document every verdict value, or an agent cannot read the
// main tool's answer.
func TestUsageDocumentsEveryVerdict(t *testing.T) {
	for _, v := range verdict.All {
		if !strings.Contains(usageMarkdown, "`"+string(v)+"`") {
			t.Errorf("usage.md never documents the verdict %q", v)
		}
	}
	for _, s := range []string{verdict.SeenByBoth, verdict.SeenByIPAPI, verdict.SeenByProxycheck,
		verdict.ProxyOpen, verdict.ProxyResidential, verdict.ProxyUnspecified} {
		if !strings.Contains(usageMarkdown, "`"+s+"`") {
			t.Errorf("usage.md never documents %q", s)
		}
	}
}

// The instructions are the only text some clients surface.
func TestInstructionsCoverTheEssentials(t *testing.T) {
	for _, want := range []string{"get_usage", "check_ip", "none", "unknown", "third-party"} {
		if !strings.Contains(Instructions, want) {
			t.Errorf("Instructions should mention %q", want)
		}
	}
}
