//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/vpn-lookup/internal/app"
	"github.com/nlink-jp/vpn-lookup/internal/config"
	"github.com/nlink-jp/vpn-lookup/internal/engine"
	"github.com/nlink-jp/vpn-lookup/internal/verdict"
)

// Live fixtures: the example addresses ipapi.is uses in its own documentation
// for each managed-service type (developers.html, read 2026-11-07), plus a
// large cloud provider's address. Chosen because the provider publishes them
// as examples, not because anyone investigated them. If one of these tests
// starts failing, the upstream data or wire format changed — investigate
// before touching the assertion.
//
// Budget per run: one ipapi.is request and one proxycheck.io request for the
// engine test (one lookup per address on each free tier), and nothing more —
// the binary tests are answered from the same cache.
var fixtures = []struct {
	ip   string
	want verdict.Verdict
}{
	{"172.224.226.5", verdict.Relay},        // ipapi.is docs: private_relay
	{"136.226.50.55", verdict.Gateway},      // ipapi.is docs: secure_web_gateway
	{"67.231.144.10", verdict.MailGateway},  // ipapi.is docs: email_gateway
	{"208.67.222.222", verdict.DNSResolver}, // ipapi.is docs: dns_resolver
	{"129.222.200.1", verdict.Satellite},    // inside ipapi.is's satellite example range
	{"3.5.140.2", verdict.Hosting},          // ipapi.is docs: Amazon AWS
}

func keys(t *testing.T) (string, string) {
	t.Helper()
	ik, pk := os.Getenv("VPN_LOOKUP_IPAPI_API_KEY"), os.Getenv("VPN_LOOKUP_PROXYCHECK_API_KEY")
	if ik == "" || pk == "" {
		t.Skip("VPN_LOOKUP_IPAPI_API_KEY and VPN_LOOKUP_PROXYCHECK_API_KEY must both be set for the live suite")
	}
	return ik, pk
}

func liveConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	ik, pk := keys(t)
	return &config.Config{IPAPIKey: ik, ProxycheckKey: pk, IPAPITTL: time.Hour, CacheDir: dir, Timeout: 30 * time.Second}
}

func TestLiveVerdicts(t *testing.T) {
	cfg := liveConfig(t, t.TempDir())
	var ips []string
	for _, f := range fixtures {
		ips = append(ips, f.ip)
	}
	rep := app.NewEngine(cfg, "e2e").Lookup(ips, false)
	if rep.Degraded != 0 {
		for _, r := range rep.Results {
			t.Logf("%s: %v", r.IP, r.SourceErrors())
		}
		t.Fatalf("%d degraded results — an upstream failed", rep.Degraded)
	}
	for i, f := range fixtures {
		r := rep.Results[i]
		if r.IP != f.ip || r.Verdict != f.want {
			t.Errorf("%s: verdict %s (seen by %s), want %s; ipapi=%+v proxycheck=%+v", f.ip, r.Verdict, r.SeenBy, f.want, r.IPAPI.Result, r.Proxycheck.Result)
		}
		if !r.IPAPI.Enabled || r.IPAPI.Result == nil || !r.Proxycheck.Enabled || r.Proxycheck.Result == nil {
			t.Errorf("%s: both sources should have answered: %+v", f.ip, r)
		}
	}
}

// The key-in-URL path must keep the key out of an error: a bad key is
// answered as an unregistered caller (measured), so it is the base URL that
// is broken here, through a closed port.
func TestLiveErrorsNeverCarryAKey(t *testing.T) {
	cfg := liveConfig(t, t.TempDir())
	cfg.ProxycheckBaseURL = "http://127.0.0.1:1/v3"
	rep := app.NewEngine(cfg, "e2e").Lookup([]string{"3.5.140.2"}, true)
	r := rep.Results[0]
	if r.Proxycheck.Error == "" || r.Verdict != verdict.Hosting {
		t.Fatalf("got %+v; the failed source must show and the other still speak", r)
	}
	if strings.Contains(r.Proxycheck.Error, cfg.ProxycheckKey) || strings.Contains(r.Proxycheck.Error, "key=") {
		t.Fatalf("the proxycheck.io key leaked into the error: %s", r.Proxycheck.Error)
	}
}

// The built binary, end to end: --version, a JSON lookup, and the MCP server's
// check_ip — all answered from one shared cache after the first call.
func TestLiveBinary(t *testing.T) {
	bin := os.Getenv("VPN_LOOKUP_E2E_BINARY")
	if bin == "" {
		t.Skip("VPN_LOOKUP_E2E_BINARY not set (make e2e sets it)")
	}
	keys(t)
	dir := t.TempDir()
	env := append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_CACHE_HOME="+filepath.Join(dir, "cache"),
		"HOME="+filepath.Join(dir, "home"),
	)
	run := func(stdin string, args ...string) (string, string, int) {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return out.String(), errOut.String(), code
	}

	if out, _, code := run("", "--version"); code != 0 || !strings.HasPrefix(out, "vpn-lookup ") {
		t.Fatalf("--version: code=%d out=%q", code, out)
	}
	out, errOut, code := run("", "--json", "136.226.50.55")
	if code != 0 {
		t.Fatalf("lookup: code=%d err=%q", code, errOut)
	}
	var rep engine.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Results) != 1 || rep.Results[0].Verdict != verdict.Gateway {
		t.Fatalf("lookup: %v %s", err, out)
	}
	if _, errOut, code := run("", "10.0.0.1"); code != 2 || !strings.Contains(errOut, "private") {
		t.Fatalf("a private address must be refused: code=%d err=%q", code, errOut)
	}
	mcpIn := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_ip","arguments":{"ips":["136.226.50.55"]}}}` + "\n"
	out, errOut, code = run(mcpIn, "mcp")
	if code != 0 || !strings.Contains(out, `\"verdict\":\"gateway\"`) || !strings.Contains(out, `\"from_cache\":true`) {
		t.Fatalf("mcp check_ip: code=%d out=%.400s err=%q", code, out, errOut)
	}
}
