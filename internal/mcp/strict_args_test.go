package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUnknownArgumentIsRefusedByName is the enforcing half of org ADR-021 §4:
// additionalProperties:false only tells a client what is allowed, and a client
// that does not check the schema sends the typo anyway. Every tool must refuse
// it, and the message must name the offending field.
func TestUnknownArgumentIsRefusedByName(t *testing.T) {
	for _, tc := range []struct{ tool, args, field string }{
		{ToolCheckIP, `{"ips":["8.8.8.8"],"refesh":true}`, "refesh"},
		{ToolCheckIP, `{"ip":"8.8.8.8"}`, "ip"},
		{ToolCheckIP, `{"IPS":["8.8.8.8"]}`, "IPS"},
		{ToolCheckIP, `{"ips":["8.8.8.8"],"Refresh":true}`, "Refresh"},
		{ToolCacheStatus, `{"verbose":true}`, "verbose"},
		{ToolGetUsage, `{"topic":"verdicts"}`, "topic"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			text, isErr := toolText(t, serve(t, testConfig("", ""), callTool(tc.tool, tc.args))[0])
			if !isErr {
				t.Fatalf("%s accepted unknown argument %q: %s", tc.tool, tc.field, text)
			}
			var e struct{ Code, Message string }
			if err := json.Unmarshal([]byte(text), &e); err != nil {
				t.Fatalf("tool error is not structured JSON: %v (%s)", err, text)
			}
			if e.Code != CodeInvalidInput || !strings.Contains(e.Message, `unknown field "`+tc.field+`"`) {
				t.Fatalf("got %+v; want invalid_input naming %q", e, tc.field)
			}
		})
	}
}

// A wrong-typed argument is refused, not read as "no arguments".
func TestMalformedArgumentsAreRefused(t *testing.T) {
	text, isErr := toolText(t, serve(t, testConfig("", ""), callTool(ToolCheckIP, `{"ips":"8.8.8.8"}`))[0])
	if !isErr || !strings.Contains(text, CodeInvalidInput) {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
}

// The module answers arguments that are not an object with -32602; they no
// longer reach the tool.
func TestNonObjectArgumentsAreAProtocolError(t *testing.T) {
	resps := serve(t, testConfig("", ""), callTool(ToolCacheStatus, `[1,2]`))
	e, _ := resps[0]["error"].(map[string]any)
	if e == nil || int(e["code"].(float64)) != -32602 {
		t.Errorf("array arguments: %v, want -32602", resps[0])
	}
}
