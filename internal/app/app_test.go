package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/vpn-lookup/internal/engine"
)

// The CLI refuses documentation ranges, so these tests use well-known public
// resolver addresses; every answer about them below is fictional fixture data.
const (
	ipVPN   = "8.8.8.8"
	ipClean = "1.1.1.1"
)

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	for _, k := range []string{"VPN_LOOKUP_IPAPI_API_KEY", "VPN_LOOKUP_PROXYCHECK_API_KEY",
		"VPN_LOOKUP_IPAPI_BASE_URL", "VPN_LOOKUP_PROXYCHECK_BASE_URL", "VPN_LOOKUP_CACHE_DIR"} {
		t.Setenv(k, "")
	}
	return dir
}

type calls struct{ ipapi, proxycheck int }

// fakeUpstreams starts both services. Each refuses a request without its key,
// in the place that service reads it.
func fakeUpstreams(t *testing.T, c *calls) {
	t.Helper()
	ia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.ipapi++
		var body struct {
			IPs []string `json:"ips"`
			Key string   `json:"key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Key != "ik" {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"Invalid API key","error_code":"ERR_FORBIDDEN_INVALID_API_KEY"}`)
			return
		}
		out := map[string]any{}
		for _, ip := range body.IPs {
			switch ip {
			case ipVPN:
				out[ip] = map[string]any{"is_vpn": true, "is_datacenter": true, "vpn": map[string]any{"service": "FictionalVPN"}, "company": map[string]any{"type": "business"}}
			case ipClean:
				out[ip] = map[string]any{"is_vpn": false, "company": map[string]any{"type": "isp"}}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(ia.Close)
	pc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.proxycheck++
		if r.URL.Query().Get("key") != "pk" || r.URL.Query().Get("tag") != "0" {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"status":"denied","message":"key or tag missing"}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		out := map[string]any{"status": "ok"}
		for _, ip := range strings.Split(form.Get("ips"), ",") {
			switch ip {
			case ipVPN:
				out[ip] = map[string]any{"detections": map[string]any{"vpn": true, "hosting": true, "anonymous": true, "risk": 50}, "operator": map[string]any{"name": "Fictional"}}
			case ipClean:
				out[ip] = map[string]any{"detections": map[string]any{"vpn": false}, "network": map[string]any{"type": "Residential"}}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(pc.Close)
	t.Setenv("VPN_LOOKUP_IPAPI_BASE_URL", ia.URL)
	t.Setenv("VPN_LOOKUP_PROXYCHECK_BASE_URL", pc.URL)
	t.Setenv("VPN_LOOKUP_IPAPI_API_KEY", "ik")
	t.Setenv("VPN_LOOKUP_PROXYCHECK_API_KEY", "pk")
}

func runIt(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, "v9.9.9-test", strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionFlag(t *testing.T) {
	isolate(t)
	code, out, errOut := runIt(t, "", "--version")
	if code != 0 || out != "vpn-lookup v9.9.9-test\n" || errOut != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

// --version must not depend on a readable config: brew test runs it on a
// machine with nothing configured.
func TestVersionIgnoresConfig(t *testing.T) {
	dir := isolate(t)
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("[nope]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runIt(t, "", "--config", bad, "--version"); code != 0 || !strings.Contains(out, "v9.9.9-test") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	isolate(t)
	code, _, errOut := runIt(t, "", "--help")
	if code != 0 || !strings.Contains(errOut, "Exit codes") || !strings.Contains(errOut, "unknown") {
		t.Fatalf("code=%d help=%q", code, errOut)
	}
}

func TestNoKeyIsAUsageErrorThatSaysWhatToSet(t *testing.T) {
	isolate(t)
	code, out, errOut := runIt(t, "", ipVPN)
	if code != 2 || out != "" || !strings.Contains(errOut, "VPN_LOOKUP_IPAPI_API_KEY") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestNonPublicAddressIsRefusedBeforeAnythingIsSent(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	for _, in := range []string{"10.0.0.1", "192.0.2.1", "::1", "example.com", "100.64.1.1"} {
		code, out, errOut := runIt(t, "", ipVPN, in)
		if code != 2 || out != "" || errOut == "" {
			t.Errorf("%s: code=%d out=%q err=%q", in, code, out, errOut)
		}
	}
	if c.ipapi+c.proxycheck != 0 {
		t.Fatalf("a refused batch sent requests: %+v", c)
	}
}

func TestTooManyAddressesIsRefused(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	var lines []string
	for i := 1; i <= MaxPerCall+1; i++ {
		lines = append(lines, fmt.Sprintf("8.8.%d.%d", i/250, i%250+1))
	}
	if code, _, errOut := runIt(t, strings.Join(lines, "\n")); code != 2 || !strings.Contains(errOut, "ceiling") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	if c.ipapi+c.proxycheck != 0 {
		t.Fatalf("requests were sent: %+v", c)
	}
}

func TestTextLookup(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	code, out, errOut := runIt(t, "", ipVPN, "--no-cache", ipClean)
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	for _, want := range []string{
		"verdict    : vpn (seen by both)",
		"provider   : ipapi.is: FictionalVPN / proxycheck.io: Fictional",
		"verdict    : none",
		"proxycheck : no detections",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if c.ipapi != 1 || c.proxycheck != 1 {
		t.Fatalf("calls = %+v; one request per source", c)
	}
}

func TestJSONLookupFromStdinAndCache(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	stdin := "# a comment\n" + ipVPN + "\n\n::ffff:8.8.8.8\n"
	code, out, errOut := runIt(t, stdin, "--json")
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	var rep engine.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if len(rep.Results) != 2 || rep.Results[1].IP != ipVPN || rep.Results[0].Verdict != "vpn" {
		t.Fatalf("results = %+v; an IPv4-mapped address is the IPv4 host", rep.Results)
	}
	runIt(t, ipVPN)
	if c.ipapi != 1 || c.proxycheck != 1 {
		t.Fatalf("calls = %+v; the second run must come from cache", c)
	}
}

func TestSourceFailureExitsOneAndSaysUnknown(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	t.Setenv("VPN_LOOKUP_PROXYCHECK_API_KEY", "wrong")
	code, out, errOut := runIt(t, "", "--no-cache", ipClean)
	if code != 1 || !strings.Contains(out, "verdict    : unknown") || !strings.Contains(errOut, "key or tag missing") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	if strings.Contains(out+errOut, "wrong") {
		t.Fatalf("the key leaked into the output: %q %q", out, errOut)
	}
}

func TestOneKeyOnly(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	t.Setenv("VPN_LOOKUP_IPAPI_API_KEY", "")
	code, out, _ := runIt(t, "", ipVPN)
	if code != 0 || !strings.Contains(out, "ipapi      : disabled") || !strings.Contains(out, "cannot be told apart") || c.ipapi != 0 {
		t.Fatalf("code=%d out=%q calls=%+v", code, out, c)
	}
}

func TestClearCache(t *testing.T) {
	isolate(t)
	var c calls
	fakeUpstreams(t, &c)
	runIt(t, "", ipVPN)
	code, out, _ := runIt(t, "", "--clear-cache")
	if code != 0 || !strings.Contains(out, "removed 2 cache entries") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	runIt(t, "", ipVPN)
	if c.ipapi != 2 {
		t.Fatalf("after clearing, the lookup must ask again: %+v", c)
	}
	if code, _, _ := runIt(t, "", "--clear-cache", ipVPN); code != 2 {
		t.Fatal("--clear-cache with addresses must be refused")
	}
}

func TestBadConfigIsAUsageError(t *testing.T) {
	dir := isolate(t)
	if code, _, errOut := runIt(t, "", "--config", filepath.Join(dir, "missing.toml"), ipVPN); code != 2 || !strings.Contains(errOut, "does not exist") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestMCPRejectsPositionalArgs(t *testing.T) {
	isolate(t)
	if code, _, errOut := runIt(t, "", "mcp", "extra"); code != 2 || !strings.Contains(errOut, "no positional arguments") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestMCPStartsWithoutKeys(t *testing.T) {
	isolate(t)
	code, out, errOut := runIt(t, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n", "mcp")
	if code != 0 || !strings.Contains(out, `"name":"vpn-lookup"`) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}
