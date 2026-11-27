package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/mcp"
	"github.com/nlink-jp/mcp/client"
	"github.com/nlink-jp/vpn-lookup/internal/config"
	"github.com/nlink-jp/vpn-lookup/internal/engine"
	"github.com/nlink-jp/vpn-lookup/internal/ipapi"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
	"github.com/nlink-jp/vpn-lookup/internal/verdict"
)

func testConfig(ipapiKey, proxycheckKey string) *config.Config {
	return &config.Config{
		IPAPIKey: ipapiKey, ProxycheckKey: proxycheckKey,
		IPAPITTL: 24 * time.Hour, CacheDir: "/nonexistent/vpn-lookup-test-cache", Timeout: time.Second,
	}
}

// fakeEngine records calls and answers every address as a VPN.
type fakeEngine struct {
	calls   [][]string
	refresh []bool
	name    string
}

func (f *fakeEngine) Lookup(ips []string, noCache bool) *engine.Report {
	f.calls = append(f.calls, ips)
	f.refresh = append(f.refresh, noCache)
	rep := &engine.Report{}
	for _, ip := range ips {
		rep.Results = append(rep.Results, engine.Result{IP: ip, Verdict: verdict.VPN, SeenBy: verdict.SeenByBoth,
			Providers: engine.Providers{IPAPI: "Example" + f.name}})
	}
	return rep
}

// serve feeds newline-delimited JSON-RPC requests through the server and
// returns the decoded responses.
func serve(t *testing.T, cfg *config.Config, lines ...string) []map[string]any {
	t.Helper()
	return serveWith(t, Options{Config: cfg, Engine: &fakeEngine{}, Version: "test"}, lines...)
}

func serveWith(t *testing.T, o Options, lines ...string) []map[string]any {
	t.Helper()
	out := serveOverClient(t, func(ctx context.Context, in io.Reader, w io.Writer) error {
		return Serve(ctx, o, in, w)
	}, strings.Join(lines, "\n"))
	var resps []map[string]any
	dec := json.NewDecoder(out)
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

func TestInitializeNamesTheServer(t *testing.T) {
	resps := serve(t, testConfig("", ""), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	res := resps[0]["result"].(map[string]any)
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
	if strings.Join(names, ",") != "check_ip,get_usage,cache_status" {
		t.Fatalf("tools = %v", names)
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

// An unknown tool is the protocol module's to refuse (-32602); it no longer
// reaches toolsCall as an isError result.
func TestUnknownToolIsAProtocolError(t *testing.T) {
	resps := serve(t, testConfig("", ""), callTool("check_hash", `{"hashes":["x"]}`))
	e, _ := resps[0]["error"].(map[string]any)
	if e == nil || int(e["code"].(float64)) != -32602 {
		t.Fatalf("unknown tool: %v, want -32602", resps[0])
	}
}

func TestCheckIPAnswersThroughTheEngine(t *testing.T) {
	eng := &fakeEngine{}
	resps := serveWith(t, Options{Config: testConfig("ik", ""), Engine: eng},
		callTool(ToolCheckIP, `{"ips":["8.8.8.8","::ffff:1.1.1.1"],"refresh":true}`))
	text, isErr := toolText(t, resps[0])
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if len(eng.calls) != 1 || strings.Join(eng.calls[0], ",") != "8.8.8.8,1.1.1.1" || !eng.refresh[0] {
		t.Fatalf("engine calls = %v refresh = %v; canonical addresses and refresh must reach it", eng.calls, eng.refresh)
	}
	var got struct {
		Results    []engine.Result `json:"results"`
		Provenance string          `json:"provenance"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 || got.Results[0].Verdict != verdict.VPN || !strings.Contains(got.Provenance, "third-party text") {
		t.Fatalf("payload = %s", text)
	}
}

func TestCheckIPRefusesBeforeAnythingIsSent(t *testing.T) {
	for args, want := range map[string]string{
		`{"ips":[]}`:                     "provide 'ips'",
		`{}`:                             "provide 'ips'",
		`{"ips":["8.8.8.8","10.0.0.1"]}`: "private",
		`{"ips":["example.com"]}`:        "not an IP address",
		`{"ips":"8.8.8.8"}`:              "cannot unmarshal",
	} {
		eng := &fakeEngine{}
		text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("ik", ""), Engine: eng}, callTool(ToolCheckIP, args))[0])
		if !isErr || !strings.Contains(text, CodeInvalidInput) || !strings.Contains(text, want) || len(eng.calls) != 0 {
			t.Errorf("%s: isErr=%v text=%s calls=%v", args, isErr, text, eng.calls)
		}
	}
}

func TestCheckIPWithoutKeysIsNoAPIKey(t *testing.T) {
	eng := &fakeEngine{}
	text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("", ""), Engine: eng}, callTool(ToolCheckIP, `{"ips":["8.8.8.8"]}`))[0])
	if !isErr || !strings.Contains(text, CodeNoAPIKey) || len(eng.calls) != 0 {
		t.Fatalf("isErr=%v text=%s calls=%v", isErr, text, eng.calls)
	}
}

func TestCheckIPOverTheCeilingIsRefused(t *testing.T) {
	var ips []string
	for i := 1; i <= MaxPerCall+1; i++ {
		ips = append(ips, fmt.Sprintf("%q", fmt.Sprintf("8.8.%d.%d", i/250, i%250+1)))
	}
	text, isErr := toolText(t, serve(t, testConfig("ik", ""), callTool(ToolCheckIP, `{"ips":[`+strings.Join(ips, ",")+`]}`))[0])
	if !isErr || !strings.Contains(text, "ceiling") {
		t.Fatalf("isErr=%v %s", isErr, text)
	}
}

// A result over the 128 KB ceiling loses results from its tail, named in
// omitted, instead of being cut mid-way or sent whole.
func TestCheckIPResultIsCappedAndSaysWhatWasLeftOut(t *testing.T) {
	eng := &fakeEngine{name: strings.Repeat("x", 3000)}
	var ips []string
	for i := 1; i <= MaxPerCall; i++ {
		ips = append(ips, fmt.Sprintf("%q", fmt.Sprintf("8.8.%d.%d", i/250, i%250+1)))
	}
	text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("ik", ""), Engine: eng}, callTool(ToolCheckIP, `{"ips":[`+strings.Join(ips, ",")+`]}`))[0])
	if isErr {
		t.Fatalf("unexpected error: %.200s", text)
	}
	if len(text) > maxResultBytes {
		t.Fatalf("result is %d bytes, over the %d ceiling", len(text), maxResultBytes)
	}
	var got struct {
		Results []engine.Result `json:"results"`
		Omitted []string        `json:"omitted"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results)+len(got.Omitted) != MaxPerCall || len(got.Omitted) == 0 {
		t.Fatalf("results %d + omitted %d; every address must be either answered or named", len(got.Results), len(got.Omitted))
	}
	if got.Omitted[len(got.Omitted)-1] != "8.8.0.101" {
		t.Fatalf("omitted = %v; the tail goes first, in order", got.Omitted)
	}
}

// A realistic answer (shaped like the live Mullvad result, 2026-11-07) is
// about 880 bytes, so 100 of them fit the ceiling with nothing omitted;
// omission is the backstop for pathological upstream text, not the norm.
func TestRealisticResultsFitWithoutOmission(t *testing.T) {
	f, r50, c100 := false, 50, 100
	res := engine.Result{IP: "2001:4860:4860:1234:5678:9abc:def0:1234", Verdict: verdict.VPN, SeenBy: verdict.SeenByBoth, Mobile: &f,
		Providers: engine.Providers{IPAPI: "ExampleVPN", Proxycheck: "Example"}}
	res.IPAPI = engine.SourceView[ipapi.Result]{Enabled: true, Result: &ipapi.Result{IsVPN: true, IsDatacenter: true,
		VPN: &ipapi.VPN{Service: "ExampleVPN", Type: "vpn_server", LastSeen: "2026-11-06T12:43:23.958Z"}, Datacenter: "Example Hosting SHPK",
		CompanyType: "business", CompanyName: "Example Hosting SHPK", AbuserScore: "0.0010 (Low)"}}
	res.Proxycheck = engine.SourceView[proxycheck.Result]{Enabled: true, Result: &proxycheck.Result{VPN: true, Hosting: true, Anonymous: true,
		Risk: &r50, Confidence: &c100, Operator: "Example", Services: []string{"datacenter_vpns"}, NetworkType: "Hosting",
		Provider: "Example Hosting SHPK", DelistDateTime: "2026-11-07T03:35:58Z"}}
	r := &checkIPResult{Report: &engine.Report{}, Provenance: provenance}
	for i := 0; i < MaxPerCall; i++ {
		r.Results = append(r.Results, res)
	}
	out := capResult(r)
	if len(r.Omitted) != 0 || len(out.Content[0].Text) > maxResultBytes {
		t.Fatalf("realistic results were cut: omitted %d, %d bytes", len(r.Omitted), len(out.Content[0].Text))
	}
}

func TestCacheStatusReportsQuotaAndItsFailure(t *testing.T) {
	ok := func() (*proxycheck.Usage, error) { return &proxycheck.Usage{QueriesToday: 12, DailyLimit: 1000}, nil }
	text, _ := toolText(t, serveWith(t, Options{Config: testConfig("", "pk"), Engine: &fakeEngine{}, Quota: ok}, callTool(ToolCacheStatus, `{}`))[0])
	if !strings.Contains(text, `"queries_today": 12`) || !strings.Contains(text, `"daily_limit": 1000`) || !strings.Contains(text, "not exposed") {
		t.Fatalf("cache_status = %s", text)
	}
	bad := func() (*proxycheck.Usage, error) { return nil, errors.New("proxycheck.io: usage: HTTP 500") }
	text, isErr := toolText(t, serveWith(t, Options{Config: testConfig("", "pk"), Engine: &fakeEngine{}, Quota: bad}, callTool(ToolCacheStatus, `{}`))[0])
	if isErr || !strings.Contains(text, "HTTP 500") {
		t.Fatalf("a quota failure is reported inside the status, not as a tool error: isErr=%v %s", isErr, text)
	}
}

// Quotes and angle brackets are escaped a second time inside the JSON-RPC
// response; the ceiling holds for what goes over the wire.
func TestCeilingMeasuresTheEscapedText(t *testing.T) {
	eng := &fakeEngine{name: strings.Repeat(`"<>&`, 400)}
	var ips []string
	for i := 1; i <= MaxPerCall; i++ {
		ips = append(ips, fmt.Sprintf("8.8.%d.%d", i/250, i%250+1))
	}
	// Each line the server writes is measured as it passes to the client. The
	// client opens a dual-era server in the modern era, whose result carries
	// resultType and _meta as well: the larger envelope of the two.
	longest := wireLongest(t, Options{Config: testConfig("ik", ""), Engine: eng},
		ToolCheckIP, map[string]any{"ips": ips})
	if longest > maxResultBytes+1024 {
		t.Errorf("the longest line on the wire is %d bytes; the ceiling is %d", longest, maxResultBytes)
	}
	// The answer is cut near the ceiling, so its line is long: a short one
	// would mean the meter saw something else.
	if longest < maxResultBytes/2 {
		t.Errorf("the longest line is only %d bytes; the meter did not see the result", longest)
	}
}

// wireLongest opens the server with nlink-jp/mcp's client, calls one tool,
// and returns the length of the longest line the server wrote.
func wireLongest(t *testing.T, o Options, tool string, args any) int {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = Serve(ctx, o, inR, outW); _ = outW.Close(); close(done) }()
	lines := &lineMeter{}
	kill := func() { _ = inW.Close(); _ = outR.Close() }
	conn, err := client.NewLineConn(io.TeeReader(outR, lines), inW, kill, client.LineOptions{})
	if err != nil {
		t.Fatal(err)
	}
	opts := client.Options{Client: mcp.Implementation{Name: "test", Version: "0"}}
	octx, ocancel := context.WithTimeout(ctx, 10*time.Second)
	defer ocancel()
	cl, err := client.Open(octx, conn, opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := cl.CallTool(octx, tool, args, nil); err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	_ = cl.Close()
	<-done
	return lines.longest
}

// lineMeter records the longest newline-terminated line written through it.
type lineMeter struct{ cur, longest int }

func (m *lineMeter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			m.longest = max(m.longest, m.cur)
			m.cur = 0
			continue
		}
		m.cur++
	}
	return len(p), nil
}

// ADR-030 §7: the server against the three probe clients (legacy only,
// dual-era, modern only).
func TestAgainstTheProbeClients(t *testing.T) {
	o := Options{Config: testConfig("", ""), Engine: &fakeEngine{}, Version: "test"}
	probeMatrix(t, func(ctx context.Context, in io.Reader, w io.Writer) error {
		return Serve(ctx, o, in, w)
	})
}

// The client that opens the server receives the instructions — the hint that
// points it at get_usage — whichever era it opens in.
func TestOpeningCarriesTheInstructions(t *testing.T) {
	o := Options{Config: testConfig("", ""), Engine: &fakeEngine{}, Version: "test"}
	cl := openWith(t, func(ctx context.Context, in io.Reader, w io.Writer) error {
		return Serve(ctx, o, in, w)
	}, client.Options{})
	if got := cl.Instructions(); got != Instructions {
		t.Errorf("instructions = %q, want the package's Instructions", got)
	}
}

type brokenStdin struct{}

func (brokenStdin) Read([]byte) (int, error) { return 0, errors.New("broken stdin") }

// The protocol layer's diagnostics go to Options.Log — the mcp subcommand
// passes its stderr — not to os.Stderr behind the caller's back.
func TestDiagnosticsGoToTheGivenLog(t *testing.T) {
	var log bytes.Buffer
	o := Options{Config: testConfig("", ""), Engine: &fakeEngine{}, Version: "test", Log: &log}
	_ = Serve(context.Background(), o, brokenStdin{}, io.Discard)
	if !strings.Contains(log.String(), "reading stdin failed") {
		t.Fatalf("log = %q, want the protocol layer's warning", log.String())
	}
}
