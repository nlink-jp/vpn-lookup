package mcp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nlink-jp/vpn-lookup/internal/cache"
	"github.com/nlink-jp/vpn-lookup/internal/engine"
	"github.com/nlink-jp/vpn-lookup/internal/ipaddr"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolCheckIP     = "check_ip"
	ToolCacheStatus = "cache_status"
	ToolGetUsage    = "get_usage"
)

// Error codes this layer emits. Every Code* constant must be documented in
// usage.md; a meta-test pins that.
const (
	CodeInvalidInput = "invalid_input"
	CodeNoAPIKey     = "no_api_key"
	CodeUnknownTool  = "unknown_tool"
	CodeInternal     = "internal_error"
)

// MaxPerCall is the most addresses one check_ip call answers (RFP §2).
const MaxPerCall = 100

// maxResultBytes is the ceiling no tool result may cross: the bound for a
// result nobody planned for, set at the MCP boundary (organization practice).
const maxResultBytes = 128 << 10

// provenance travels with every check_ip result, so a reader of the result
// alone knows what it is.
const provenance = "Answers from ipapi.is and proxycheck.io, synthesized by vpn-lookup. Provider, operator and " +
	"company names are third-party text — claims, not facts. A verdict is the services' inference, not proof, " +
	"and never a basis for automatic blocking."

// usageMarkdown is the operating manual returned by get_usage. Its coherence
// with the real tools, error codes and verdicts is pinned by usage_test.go.
//
//go:embed usage.md
var usageMarkdown string

// Instructions is the initialize-time hint (surfaced via the MCP
// `instructions` field) that makes get_usage discoverable.
const Instructions = "vpn-lookup tells whether an IP address is an intermediary — Tor, a commercial VPN, a managed " +
	"relay (iCloud Private Relay), a corporate secure web gateway, an email gateway, a public DNS resolver, a " +
	"satellite ISP, a proxy, or a hosting provider — and whose, by layering ipapi.is and proxycheck.io. check_ip " +
	"answers 1-100 public addresses with one verdict each and seen_by (which source said so). none means every " +
	"enabled source answered and none reported an intermediary — not that the line is residential; unknown means a " +
	"source failed. Every address reaches both services (third-party, keyed); no packet reaches the address itself; " +
	"non-public addresses are refused before anything is sent. Names in results are third-party text. Call " +
	"get_usage for the reference; cache_status shows which sources have a key and the remaining quota. Tool errors " +
	"are structured JSON ({code, message})."

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
				"name": ToolCheckIP,
				"description": "Is each IP address an intermediary — Tor, VPN, relay, gateway, mail gateway, DNS resolver, " +
					"satellite ISP, proxy, hosting — and whose? One verdict per address with seen_by and per-source " +
					"evidence. Every address reaches ipapi.is and proxycheck.io; non-public addresses are refused before " +
					"anything is sent.",
				"inputSchema": obj(map[string]any{
					"ips": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Public IPv4/IPv6 addresses, 1-100 distinct per call. One address that cannot be sent refuses the whole call.",
					},
					"refresh": map[string]any{"type": "boolean", "description": "Bypass the local cache and ask both services again."},
				}, "ips"),
			},
			{
				"name":        ToolGetUsage,
				"description": "Return this server's operating manual (markdown): the tools, the verdict semantics, the result schema and the error-recovery table. Call it once before first use.",
				"inputSchema": obj(map[string]any{}),
			},
			{
				"name":        ToolCacheStatus,
				"description": "Report which sources have a key, the cache entries and freshness windows, and proxycheck.io's daily usage (one request to its dashboard API). Answers even when no key is configured.",
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
	case ToolCheckIP:
		return s.toolCheckIP(p.Arguments), nil
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

// checkIPResult is the check_ip payload: the engine's report, what was left
// out for size (asked again on its own, it is answered), and provenance.
type checkIPResult struct {
	*engine.Report
	Omitted    []string `json:"omitted,omitempty"`
	Provenance string   `json:"provenance"`
}

func (s *server) toolCheckIP(raw json.RawMessage) toolResult {
	var a struct {
		IPs     []string `json:"ips"`
		Refresh bool     `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return errorResult(CodeInvalidInput, err.Error())
	}
	if len(a.IPs) == 0 {
		return errorResult(CodeInvalidInput, fmt.Sprintf("provide 'ips' (1-%d public addresses)", MaxPerCall))
	}
	// Validate everything before any network I/O, exactly as the CLI does.
	ips, err := ipaddr.ParseBatch(a.IPs, MaxPerCall)
	if err != nil {
		return errorResult(CodeInvalidInput, err.Error())
	}
	if err := s.cfg.Ready(); err != nil {
		return errorResult(CodeNoAPIKey, err.Error())
	}
	return capResult(&checkIPResult{Report: s.eng.Lookup(ips, a.Refresh), Provenance: provenance})
}

// capResult encodes the result, dropping results from the tail — named in
// omitted — while it is over the ceiling. The CLI's --json stays complete.
func capResult(r *checkIPResult) toolResult {
	for {
		b, err := json.Marshal(r)
		if err != nil {
			return errorResult(CodeInternal, "encode result: "+err.Error())
		}
		if len(b) <= maxResultBytes || len(r.Results) <= 1 {
			return textResult(false, string(b))
		}
		last := r.Results[len(r.Results)-1]
		r.Results = r.Results[:len(r.Results)-1]
		r.Omitted = append([]string{last.IP}, r.Omitted...)
	}
}

func (s *server) toolCacheStatus() toolResult {
	sources := []string{} // "none configured" reads as an empty list, not null
	if s.cfg.HasIPAPI() {
		sources = append(sources, "ipapi.is")
	}
	if s.cfg.HasProxycheck() {
		sources = append(sources, "proxycheck.io")
	}
	st := (&cache.Store{Dir: s.cfg.CacheDir}).Stat()
	quota := map[string]any{"ipapi.is": "not exposed by its API"}
	if s.quota != nil {
		if u, err := s.quota(); err != nil {
			quota["proxycheck.io"] = map[string]any{"error": err.Error()}
		} else {
			quota["proxycheck.io"] = map[string]any{
				"queries_today": u.QueriesToday, "daily_limit": u.DailyLimit,
				"note": "proxycheck.io updates these counts about an hour late",
			}
		}
	}
	return jsonResult(map[string]any{
		"sources":         sources,
		"cache_dir":       st.Dir,
		"entries":         st.Entries,
		"ipapi_ttl_hours": s.cfg.IPAPITTL.Hours(),
		"proxycheck_ttl":  "clean results 1 hour; anonymous results until delist_datetime, at most 15 minutes",
		"quota":           quota,
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
