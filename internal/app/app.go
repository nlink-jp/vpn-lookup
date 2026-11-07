// Package app is the CLI shell: flag parsing, input validation, dispatch and
// rendering. Everything below it is I/O-free or dependency-injected, so this is
// the only layer that touches the real process environment.
package app

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nlink-jp/vpn-lookup/internal/cache"
	"github.com/nlink-jp/vpn-lookup/internal/config"
	"github.com/nlink-jp/vpn-lookup/internal/engine"
	"github.com/nlink-jp/vpn-lookup/internal/guard"
	"github.com/nlink-jp/vpn-lookup/internal/ipaddr"
	"github.com/nlink-jp/vpn-lookup/internal/ipapi"
	"github.com/nlink-jp/vpn-lookup/internal/mcp"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
)

// Exit codes. Verdicts are never encoded here: scripts read --json.
const (
	exitOK    = 0 // every lookup completed with every enabled source answering
	exitError = 1 // at least one source failed (results still printed)
	exitUsage = 2 // bad flags, bad input, configuration problems
)

// MaxPerCall is the most addresses one invocation answers (RFP §2).
const MaxPerCall = 100

// Run executes the CLI with the given arguments and returns the process exit
// code.
func Run(args []string, version string) int {
	return run(args, version, os.Stdin, os.Stdout, os.Stderr)
}

func run(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "mcp" {
		return runMCP(args[1:], version, stdin, stdout, stderr)
	}

	fs := flag.NewFlagSet("vpn-lookup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	var (
		jsonOut     = fs.Bool("json", false, "structured output")
		noCache     = fs.Bool("no-cache", false, "bypass the cache and re-query")
		clearCache  = fs.Bool("clear-cache", false, "delete every cache entry")
		timeout     = fs.Duration("timeout", 0, "upstream timeout (e.g. 10s)")
		configPath  = fs.String("config", "", "config file path")
		showVersion = fs.Bool("version", false, "print version")
	)
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}

	if *showVersion {
		printVersion(stdout, version)
		return exitOK
	}

	cfg, err := config.Load(*configPath, *timeout)
	if *clearCache {
		// Deleting cached answers is a duty (ipapi.is §2.5), so a broken config
		// does not stop it: the directory falls back to VPN_LOOKUP_CACHE_DIR or
		// the default.
		if len(positional) > 0 {
			fmt.Fprintln(stderr, "error: --clear-cache takes no addresses")
			return exitUsage
		}
		dir := config.DefaultCacheDir()
		if err != nil {
			if v := strings.TrimSpace(os.Getenv("VPN_LOOKUP_CACHE_DIR")); v != "" {
				dir = v
			}
			fmt.Fprintf(stderr, "warning: config not read (%v); clearing %s\n", err, dir)
		} else {
			dir = cfg.CacheDir
		}
		n, err := (&cache.Store{Dir: dir}).Clear()
		if err != nil {
			fmt.Fprintf(stderr, "error: clear cache: %v\n", err)
			return exitError
		}
		fmt.Fprintf(stdout, "removed %d cache entries from %s\n", n, dir)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	warn(stderr, cfg)

	if len(positional) == 0 && isTerminal(stdin) {
		usage(stderr)
		return exitUsage
	}
	ips, err := gatherIPs(positional, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	if len(ips) == 0 {
		usage(stderr)
		fmt.Fprintln(stderr, "\nerror: no addresses given (pass them as arguments or on stdin)")
		return exitUsage
	}
	if err := cfg.Ready(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}

	rep := NewEngine(cfg, version).Lookup(ips, *noCache)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "error: encode results: %v\n", err)
			return exitError
		}
	} else {
		renderText(stdout, rep)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	for i := range rep.Results {
		for _, e := range rep.Results[i].SourceErrors() {
			fmt.Fprintf(stderr, "error: %s: %s\n", rep.Results[i].IP, e)
		}
	}
	if rep.Degraded > 0 {
		return exitError
	}
	return exitOK
}

// gatherIPs validates every input before any network I/O; one bad address
// fails the whole invocation, so a typo never half-runs a triage. It returns
// the canonical addresses to send, duplicates kept (the engine asks once).
func gatherIPs(args []string, stdin io.Reader) ([]string, error) {
	raw := args
	if len(raw) == 0 {
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw = append(raw, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
	}
	return ipaddr.ParseBatch(raw, MaxPerCall)
}

// NewEngine builds the engine for a configuration: one HTTP client per source,
// each refusing redirects because each carries a key.
func NewEngine(cfg *config.Config, version string) *engine.Engine {
	ua := "vpn-lookup/" + version
	e := &engine.Engine{
		Cache:    &cache.Store{Dir: cfg.CacheDir},
		IPAPITTL: cfg.IPAPITTL,
		Now:      time.Now,
	}
	if cfg.HasIPAPI() {
		e.IPAPI = &ipapi.Client{HTTP: keyClient(cfg), BaseURL: cfg.IPAPIBaseURL, APIKey: cfg.IPAPIKey, UserAgent: ua}
		e.IPAPIScope = scope(cfg.IPAPIBaseURL, ipapi.DefaultBaseURL, cfg.IPAPIKey)
	}
	if cfg.HasProxycheck() {
		e.Proxycheck = &proxycheck.Client{HTTP: keyClient(cfg), BaseURL: cfg.ProxycheckBaseURL, APIKey: cfg.ProxycheckKey, UserAgent: ua}
		e.ProxycheckScope = scope(cfg.ProxycheckBaseURL, proxycheck.DefaultBaseURL, cfg.ProxycheckKey)
	}
	return e
}

// scope is a source's cache scope: its endpoint and a short fingerprint of its
// key. Only the fingerprint is used, and cache.Key hashes it again with the
// address into the file name, so the key is never on disk.
func scope(baseURL, def, key string) string {
	if baseURL == "" {
		baseURL = def
	}
	sum := sha256.Sum256([]byte(key))
	return baseURL + "|" + hex.EncodeToString(sum[:8])
}

func keyClient(cfg *config.Config) *http.Client {
	return &http.Client{Timeout: cfg.Timeout, CheckRedirect: guard.RefuseRedirects}
}

// parseInterleaved parses flags that appear anywhere among the positional
// arguments, and returns the positionals (from opencti-lookup). Go's flag
// package stops at the first non-flag argument, so `vpn-lookup 1.2.3.4 --json`
// would otherwise read --json as an address.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}

// runMCP starts the stdio MCP server. Diagnostics go to stderr only: stdout
// belongs to the JSON-RPC stream. It starts without any key, so that get_usage
// and cache_status answer before the operator has configured anything.
func runMCP(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vpn-lookup mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		timeout    = fs.Duration("timeout", 0, "upstream timeout (e.g. 10s)")
		configPath = fs.String("config", "", "config file path")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: mcp takes no positional arguments (got %q)\n", fs.Arg(0))
		return exitUsage
	}
	cfg, err := config.Load(*configPath, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	warn(stderr, cfg)
	opts := mcp.Options{Config: cfg, Engine: NewEngine(cfg, version), Version: version}
	if cfg.HasProxycheck() {
		pc := &proxycheck.Client{HTTP: keyClient(cfg), BaseURL: cfg.ProxycheckBaseURL, APIKey: cfg.ProxycheckKey, UserAgent: "vpn-lookup/" + version}
		opts.Quota = pc.Usage
	}
	if err := mcp.Serve(opts, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "error: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}

func warn(w io.Writer, cfg *config.Config) {
	for _, m := range cfg.Warnings {
		fmt.Fprintf(w, "warning: %s\n", m)
	}
}

// isTerminal reports whether r is an interactive terminal, so that a bare
// `vpn-lookup` prints usage instead of waiting on stdin.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// printVersion is the single source of the version banner (a Homebrew
// formula's brew test calls --version).
func printVersion(w io.Writer, version string) {
	fmt.Fprintln(w, "vpn-lookup "+version)
}

func usage(w io.Writer) {
	fmt.Fprint(w, strings.TrimLeft(`
vpn-lookup — is this IP address an intermediary (VPN, proxy, Tor, relay, gateway, hosting), and whose?

Layers ipapi.is and proxycheck.io (one organization key each, both free tiers)
into one lookup. Every address looked up reaches both services; no packet
reaches the address itself. Results are inference — never a basis for
automatic blocking. For your organization's own work only.

Usage:
  vpn-lookup [flags] <ip> [ip...]   # IPv4/IPv6, up to 100; flags may come anywhere
  vpn-lookup [flags]                # addresses from stdin, one per line
  vpn-lookup --clear-cache          # delete every cache entry
  vpn-lookup mcp [--config <path>]  # run as a local MCP server (stdio)

Flags:
  --json            structured output (default: human-readable text)
  --no-cache        bypass the cache and re-query
  --clear-cache     delete every cache entry
  --timeout <dur>   upstream timeout (e.g. 10s)
  --config <path>   config file (default ~/.config/vpn-lookup/config.toml)
  --version         print version

Verdicts: tor / vpn / relay / gateway / mail_gateway / dns_resolver /
satellite / proxy / hosting / none / unknown. "none" means every enabled
source answered and none reported an intermediary — not that the line is
residential; "unknown" means a source failed.

Private, loopback, documentation and other non-public addresses are refused
before anything is sent.

Exit codes: 0 all lookups completed / 1 a source failed / 2 usage error.
Verdicts are never encoded in exit codes — scripts should read --json.
`, "\n"))
}
