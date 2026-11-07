package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points every search root and variable at a temp dir, so no test
// reads the developer's real config or keys.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	for _, k := range []string{
		"VPN_LOOKUP_IPAPI_API_KEY", "VPN_LOOKUP_IPAPI_BASE_URL",
		"VPN_LOOKUP_PROXYCHECK_API_KEY", "VPN_LOOKUP_PROXYCHECK_BASE_URL",
		"VPN_LOOKUP_CACHE_DIR", "VPN_LOOKUP_IPAPI_TTL_HOURS", "VPN_LOOKUP_TIMEOUT_SECONDS",
	} {
		t.Setenv(k, "")
	}
	return dir
}

func write(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsLoadWithoutAnyKey(t *testing.T) {
	dir := isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("loading with nothing configured must succeed (MCP handshake, get_usage): %v", err)
	}
	if cfg.Timeout != DefaultTimeout || cfg.IPAPITTL != DefaultIPAPITTL {
		t.Fatalf("defaults = %v / %v", cfg.Timeout, cfg.IPAPITTL)
	}
	if cfg.CacheDir != filepath.Join(dir, "cache", AppName) {
		t.Fatalf("CacheDir = %q, want under XDG_CACHE_HOME", cfg.CacheDir)
	}
	if cfg.HasIPAPI() || cfg.HasProxycheck() {
		t.Fatal("no source should be enabled without keys")
	}
	var nc *NotConfiguredError
	if err := cfg.Ready(); err == nil || !asNotConfigured(err, &nc) {
		t.Fatalf("Ready() = %v, want NotConfiguredError", err)
	}
}

func asNotConfigured(err error, target **NotConfiguredError) bool {
	e, ok := err.(*NotConfiguredError)
	if ok {
		*target = e
	}
	return ok
}

func TestFileIsRead(t *testing.T) {
	dir := isolate(t)
	p := write(t, dir, `
[ipapi]
api_key = "ik"
base_url = "http://127.0.0.1:9/"

[proxycheck]
api_key = "pk"

[cache]
ipapi_ttl_hours = 48
dir = "~/vl-cache"

[network]
timeout_seconds = 5
`)
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPAPIKey != "ik" || cfg.ProxycheckKey != "pk" || !cfg.HasIPAPI() || !cfg.HasProxycheck() {
		t.Fatalf("keys = %q / %q", cfg.IPAPIKey, cfg.ProxycheckKey)
	}
	if cfg.IPAPIBaseURL != "http://127.0.0.1:9" {
		t.Fatalf("IPAPIBaseURL = %q (trailing slash dropped)", cfg.IPAPIBaseURL)
	}
	if cfg.IPAPITTL != 48*time.Hour || cfg.Timeout != 5*time.Second {
		t.Fatalf("ttl %v timeout %v", cfg.IPAPITTL, cfg.Timeout)
	}
	if !strings.HasSuffix(cfg.CacheDir, "vl-cache") || strings.HasPrefix(cfg.CacheDir, "~") {
		t.Fatalf("CacheDir = %q, want ~ expanded", cfg.CacheDir)
	}
	if err := cfg.Ready(); err != nil {
		t.Fatalf("Ready() = %v", err)
	}
}

func TestOneKeyIsEnough(t *testing.T) {
	isolate(t)
	t.Setenv("VPN_LOOKUP_PROXYCHECK_API_KEY", "pk")
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HasIPAPI() || !cfg.HasProxycheck() || cfg.Ready() != nil {
		t.Fatalf("ipapi=%v proxycheck=%v ready=%v", cfg.HasIPAPI(), cfg.HasProxycheck(), cfg.Ready())
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := isolate(t)
	p := write(t, dir, "[ipapi]\napi_key = \"file\"\n[cache]\nipapi_ttl_hours = 2\n")
	t.Setenv("VPN_LOOKUP_IPAPI_API_KEY", "env")
	t.Setenv("VPN_LOOKUP_IPAPI_TTL_HOURS", "3")
	t.Setenv("VPN_LOOKUP_TIMEOUT_SECONDS", "7")
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPAPIKey != "env" || cfg.IPAPITTL != 3*time.Hour || cfg.Timeout != 7*time.Second {
		t.Fatalf("env must win: %q %v %v", cfg.IPAPIKey, cfg.IPAPITTL, cfg.Timeout)
	}
}

func TestTimeoutFlagWins(t *testing.T) {
	isolate(t)
	t.Setenv("VPN_LOOKUP_TIMEOUT_SECONDS", "60")
	cfg, err := Load("", 3*time.Second)
	if err != nil || cfg.Timeout != 3*time.Second {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
	if _, err := Load("", 601*time.Second); err == nil {
		t.Fatal("a --timeout over the ceiling must be refused")
	}
}

func TestRefusesWhatItDoesNotUnderstand(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "[ipapi]\napi_kee = \"x\"\n",
		"unknown section":  "[bazaar]\nauth_key = \"x\"\n",
		"empty key":        "[ipapi]\napi_key = \"  \"\n",
		"ttl over 30 days": "[cache]\nipapi_ttl_hours = 721\n",
		"ttl zero":         "[cache]\nipapi_ttl_hours = 0\n",
		"timeout zero":     "[network]\ntimeout_seconds = 0\n",
		"wrong type":       "[network]\ntimeout_seconds = \"5\"\n",
		"malformed":        "[ipapi\napi_key = \"x\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := isolate(t)
			if _, err := Load(write(t, dir, body), 0); err == nil {
				t.Fatalf("%q was accepted", body)
			}
		})
	}
}

func TestUnknownKeyIsNamed(t *testing.T) {
	dir := isolate(t)
	_, err := Load(write(t, dir, "[proxycheck]\ntag = \"x\"\n"), 0)
	if err == nil || !strings.Contains(err.Error(), "proxycheck.tag") || !strings.Contains(err.Error(), "known:") {
		t.Fatalf("err = %v; want the unknown key named and the known keys listed", err)
	}
}

func TestEnvNumbersAreChecked(t *testing.T) {
	for _, kv := range [][2]string{
		{"VPN_LOOKUP_IPAPI_TTL_HOURS", "721"},
		{"VPN_LOOKUP_IPAPI_TTL_HOURS", "NaN"},
		{"VPN_LOOKUP_TIMEOUT_SECONDS", "0"},
		{"VPN_LOOKUP_TIMEOUT_SECONDS", "1e9"},
	} {
		isolate(t)
		t.Setenv(kv[0], kv[1])
		if _, err := Load("", 0); err == nil {
			t.Errorf("%s=%s was accepted", kv[0], kv[1])
		}
	}
}

func TestExplicitConfigMustExist(t *testing.T) {
	dir := isolate(t)
	_, err := Load(filepath.Join(dir, "nope.toml"), 0)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
}

func TestBaseURLRules(t *testing.T) {
	ok := map[string]string{
		"https://api.example.test/":   "https://api.example.test",
		"https://api.example.test/v3": "https://api.example.test/v3",
		"http://127.0.0.1:8080":       "http://127.0.0.1:8080",
		"http://localhost:1/":         "http://localhost:1",
	}
	for in, want := range ok {
		got, err := validateBaseURL("x", in)
		if err != nil || got != want {
			t.Errorf("validateBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"http://api.example.test", // plain http to another machine: the key would travel in clear
		"ftp://api.example.test",
		"https://",
		"https://user:secret@api.example.test",
		"https://api.example.test/?key=secret",
		"https://api.example.test/#frag",
	} {
		if _, err := validateBaseURL("x", in); err == nil {
			t.Errorf("validateBaseURL(%q) was accepted", in)
		}
	}
}

// A malformed URL with credentials must not echo them: Go's url.Error quotes
// the whole input.
func TestBaseURLErrorNeverQuotesTheInput(t *testing.T) {
	for _, in := range []string{"https://user:s3cret@host/%zz", "https://user:s3cret@host/?k=v"} {
		_, err := validateBaseURL("ipapi base_url", in)
		if err == nil {
			t.Fatalf("%q was accepted", in)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("error leaks the credential: %v", err)
		}
	}
}

func TestPermissionWarning(t *testing.T) {
	dir := isolate(t)
	p := write(t, dir, "[ipapi]\napi_key = \"k\"\n")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "0644") {
		t.Fatalf("Warnings = %v", cfg.Warnings)
	}
}

func TestDotConfigIsFoundEvenWithXDGSet(t *testing.T) {
	dir := isolate(t)
	dot := filepath.Join(dir, "home", ".config", AppName)
	if err := os.MkdirAll(dot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dot, "config.toml"), []byte("[ipapi]\napi_key = \"k\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasIPAPI() || cfg.Path != filepath.Join(dot, "config.toml") {
		t.Fatalf("Path = %q; ~/.config must be searched even when XDG_CONFIG_HOME is set", cfg.Path)
	}
}

func TestRedactedHidesKeys(t *testing.T) {
	cfg := &Config{IPAPIKey: "ik-secret", ProxycheckKey: "pk-secret"}
	r := cfg.Redacted()
	if strings.Contains(r.IPAPIKey+r.ProxycheckKey, "secret") {
		t.Fatalf("Redacted leaked a key: %+v", r)
	}
	if cfg.IPAPIKey != "ik-secret" {
		t.Fatal("Redacted must not modify the original")
	}
}

// The decoder quotes the token it cannot parse; an API key written without
// quotes must not reach stderr (and from there an MCP client's log).
func TestParseErrorNeverQuotesTheValue(t *testing.T) {
	for _, body := range []string{
		"[ipapi]\napi_key = 7f3a9c1b2d4e5f60718293a4b5c6d7e8\n",
		"[proxycheck]\napi_key = 2026-11-07secretkeyvalue\n",
		"[ipapi]\napi_key = secretkeyvalue\n",
		"[network]\ntimeout_seconds = \"7f3a9c1b2d4e\"\n",
	} {
		dir := isolate(t)
		_, err := Load(write(t, dir, body), 0)
		if err == nil {
			t.Fatalf("%q was accepted", body)
		}
		for _, secret := range []string{"7f3a9c1b2d4e", "secretkeyvalue"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the error quotes the value: %v", err)
			}
		}
		if !strings.Contains(err.Error(), "line") {
			t.Fatalf("the error must still say where: %v", err)
		}
	}
}
