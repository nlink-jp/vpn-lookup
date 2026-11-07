package mcp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
// check_ip arrives with the lookup engine (RFP Phase 1–2); until then the
// server advertises only what can answer.
const (
	ToolCacheStatus = "cache_status"
	ToolGetUsage    = "get_usage"
)

// Error codes this layer emits. Every Code* constant must be documented in
// usage.md; a meta-test pins that.
const (
	CodeInvalidInput = "invalid_input"
	CodeUnknownTool  = "unknown_tool"
	CodeInternal     = "internal_error"
)

// usageMarkdown is the operating manual returned by get_usage. Its coherence
// with the real tools and error codes is pinned by usage_test.go.
//
//go:embed usage.md
var usageMarkdown string

// Instructions is the initialize-time hint (surfaced via the MCP
// `instructions` field) that makes get_usage discoverable.
const Instructions = "vpn-lookup tells whether an IP address is an intermediary — Tor, a commercial VPN, a managed " +
	"relay (iCloud Private Relay), a corporate secure web gateway, an email gateway, a public DNS resolver, a " +
	"satellite ISP, a proxy, or a hosting provider — and whose, by layering ipapi.is and proxycheck.io. This build " +
	"is a scaffold: the lookup tool (check_ip) is not implemented yet. Call get_usage for the reference; " +
	"cache_status shows which sources have a key. Tool errors are structured JSON ({code, message})."

// obj builds a tool's input schema. Every schema goes through here so that
// org ADR-021 §10's `additionalProperties: false` is set once instead of being
// remembered per tool.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// decodeArgs decodes a tool's arguments strictly: an argument the tool does not
// declare is refused by name, and a malformed argument object is refused rather
// than read as an empty one. Every tool decodes through here — obj() is only
// the declared half of org ADR-021 §4; this is the half that refuses.
func decodeArgs(raw json.RawMessage, into any) error {
	raw = bytes.TrimSpace(raw)
	// Omitted or null arguments mean the empty object, not an error.
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errors.New("arguments: " + err.Error())
	}
	return nil
}

// toolsList returns the advertised tool set with JSON Schema for each input.
func toolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        ToolGetUsage,
				"description": "Return this server's operating manual (markdown): the tools, the verdict semantics, and the error-recovery table. Call it once before first use.",
				"inputSchema": obj(map[string]any{}),
			},
			{
				"name":        ToolCacheStatus,
				"description": "Report which sources have a key, the cache directory and freshness windows. Answers even when no key is configured.",
				"inputSchema": obj(map[string]any{}),
			},
		},
	}
}

func (s *server) toolsCall(params json.RawMessage) (toolResult, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolResult{}, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	switch p.Name {
	case ToolGetUsage:
		// No arguments — which still means "none", not "any".
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult(CodeInvalidInput, err.Error()), nil
		}
		return textResult(false, usageMarkdown), nil
	case ToolCacheStatus:
		if err := decodeArgs(p.Arguments, &struct{}{}); err != nil {
			return errorResult(CodeInvalidInput, err.Error()), nil
		}
		return s.toolCacheStatus(), nil
	default:
		return errorResult(CodeUnknownTool, "unknown tool: "+p.Name+" (call tools/list)"), nil
	}
}

func (s *server) toolCacheStatus() toolResult {
	var sources []string
	if s.cfg.HasIPAPI() {
		sources = append(sources, "ipapi.is")
	}
	if s.cfg.HasProxycheck() {
		sources = append(sources, "proxycheck.io")
	}
	if sources == nil {
		sources = []string{} // "none configured" reads as an empty list, not null
	}
	return jsonResult(map[string]any{
		"sources":         sources,
		"cache_dir":       s.cfg.CacheDir,
		"ipapi_ttl_hours": s.cfg.IPAPITTL.Hours(),
		"proxycheck_ttl":  "clean results 1 hour; anonymous results until delist_datetime, at most 15 minutes",
	})
}

// errorResult renders a structured tool error: {code, message}.
func errorResult(code, message string) toolResult {
	b, _ := json.Marshal(map[string]string{"code": code, "message": message})
	return textResult(true, string(b))
}

// jsonResult marshals v into a non-error text result.
func jsonResult(v any) toolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(CodeInternal, "encode result: "+err.Error())
	}
	return textResult(false, string(b))
}
