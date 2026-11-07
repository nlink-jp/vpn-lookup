package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("VPN_LOOKUP_IPAPI_API_KEY", "")
	t.Setenv("VPN_LOOKUP_PROXYCHECK_API_KEY", "")
	return dir
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
// machine with nothing configured, and a broken config must still let the
// operator see which build they have.
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
	code, out, errOut := runIt(t, "", "192.0.2.1")
	if code != 2 || out != "" || !strings.Contains(errOut, "VPN_LOOKUP_IPAPI_API_KEY") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestLookupIsHonestlyNotImplemented(t *testing.T) {
	isolate(t)
	t.Setenv("VPN_LOOKUP_IPAPI_API_KEY", "k")
	code, out, errOut := runIt(t, "", "192.0.2.1")
	if code != 2 || out != "" || !strings.Contains(errOut, "not implemented yet") {
		t.Fatalf("a scaffold must not pretend to answer: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestClearCacheIsHonestlyNotImplemented(t *testing.T) {
	isolate(t)
	code, _, errOut := runIt(t, "", "--clear-cache")
	if code != 2 || !strings.Contains(errOut, "not implemented yet") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestBadConfigIsAUsageError(t *testing.T) {
	dir := isolate(t)
	if code, _, errOut := runIt(t, "", "--config", filepath.Join(dir, "missing.toml"), "192.0.2.1"); code != 2 || !strings.Contains(errOut, "does not exist") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestMCPRejectsPositionalArgs(t *testing.T) {
	isolate(t)
	if code, _, errOut := runIt(t, "", "mcp", "extra"); code != 2 || !strings.Contains(errOut, "no positional arguments") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

// The MCP server starts with no key, so the client can read get_usage and
// cache_status before anything is configured.
func TestMCPStartsWithoutKeys(t *testing.T) {
	isolate(t)
	code, out, errOut := runIt(t, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n", "mcp")
	if code != 0 || !strings.Contains(out, `"name":"vpn-lookup"`) {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}
