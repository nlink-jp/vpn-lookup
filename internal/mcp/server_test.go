package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/vpn-lookup/internal/config"
)

func testConfig(ipapiKey, proxycheckKey string) *config.Config {
	return &config.Config{
		IPAPIKey: ipapiKey, ProxycheckKey: proxycheckKey,
		IPAPITTL: 24 * time.Hour, CacheDir: "/tmp/vpn-lookup-test-cache", Timeout: time.Second,
	}
}

// serve feeds newline-delimited JSON-RPC requests through the server and
// returns the decoded responses.
func serve(t *testing.T, cfg *config.Config, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(cfg, "test", strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		resps = append(resps, m)
	}
	return resps
}

func callTool(name, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args)
}

// toolText extracts the text payload and isError flag of a tools/call response.
func toolText(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	return text, isErr
}

func TestInitializeEchoesProtocolAndNamesTheServer(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	res := resps[0]["result"].(map[string]any)
	if res["protocolVersion"] != "2024-11-05" {
		t.Fatalf("protocolVersion = %v", res["protocolVersion"])
	}
	if res["serverInfo"].(map[string]any)["name"] != "vpn-lookup" {
		t.Fatalf("serverInfo = %v", res["serverInfo"])
	}
	if !strings.Contains(res["instructions"].(string), "get_usage") {
		t.Fatal("instructions must point at get_usage")
	}
}

func TestToolsListAdvertisesOnlyWhatAnswers(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := resps[0]["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, x := range tools {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "get_usage,cache_status" {
		t.Fatalf("tools = %v; the scaffold must not advertise check_ip before it answers", names)
	}
}

func TestCacheStatusAnswersWithoutKeys(t *testing.T) {
	resps := serve(t, testConfig("", ""), callTool(ToolCacheStatus, `{}`))
	text, isErr := toolText(t, resps[0])
	if isErr || !strings.Contains(text, `"sources": []`) {
		t.Fatalf("cache_status with no key: isErr=%v %s", isErr, text)
	}
}

func TestCacheStatusNamesEnabledSourcesAndNeverAKey(t *testing.T) {
	resps := serve(t, testConfig("ipapi-secret", "pc-secret"), callTool(ToolCacheStatus, `null`))
	text, isErr := toolText(t, resps[0])
	if isErr || !strings.Contains(text, "ipapi.is") || !strings.Contains(text, "proxycheck.io") {
		t.Fatalf("cache_status: isErr=%v %s", isErr, text)
	}
	if strings.Contains(text, "secret") {
		t.Fatalf("a key leaked into cache_status: %s", text)
	}
}

func TestGetUsageReturnsTheManual(t *testing.T) {
	resps := serve(t, testConfig("", ""), callTool(ToolGetUsage, `{}`))
	text, isErr := toolText(t, resps[0])
	if isErr || !strings.Contains(text, "vpn-lookup MCP server") {
		t.Fatalf("get_usage: isErr=%v", isErr)
	}
}

func TestUnknownToolIsAStructuredError(t *testing.T) {
	resps := serve(t, testConfig("", ""), callTool("check_ip", `{"ips":["192.0.2.1"]}`))
	text, isErr := toolText(t, resps[0])
	if !isErr || !strings.Contains(text, CodeUnknownTool) {
		t.Fatalf("unknown tool: isErr=%v %s", isErr, text)
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	resps := serve(t, testConfig("", ""),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if len(resps) != 1 {
		t.Fatalf("responses = %d, want only the ping reply", len(resps))
	}
}

func TestUnknownMethodIsRPCError(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	if resps[0]["error"] == nil {
		t.Fatalf("want a JSON-RPC error, got %v", resps[0])
	}
}

func TestMalformedJSONReportsParseErrorAndStops(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{not json`)
	if len(resps) != 1 || resps[0]["error"] == nil {
		t.Fatalf("want a single parse-error response, got %v", resps)
	}
}
