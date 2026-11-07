// Package app is the CLI shell: flag parsing, dispatch, and rendering.
// Everything below it is I/O-free or dependency-injected, so this is the only
// layer that touches the real process environment.
//
// Scaffold: --version, help and the mcp subcommand work; a lookup and
// --clear-cache load and check the configuration, then report that they are
// not implemented yet (exit 2) instead of pretending to answer.
package app

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nlink-jp/vpn-lookup/internal/config"
	"github.com/nlink-jp/vpn-lookup/internal/mcp"
)

// Exit codes. Verdicts are never encoded here: scripts read --json.
const (
	exitOK    = 0 // every lookup completed with every enabled source answering
	exitError = 1 // at least one source failed (results still printed)
	exitUsage = 2 // bad flags, bad input, configuration problems
)

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
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}
	_, _ = jsonOut, noCache // used by the lookup path (RFP Phase 1)

	if *showVersion {
		printVersion(stdout, version)
		return exitOK
	}

	cfg, err := config.Load(*configPath, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	warn(stderr, cfg)

	if *clearCache {
		fmt.Fprintln(stderr, "error: --clear-cache is not implemented yet (RFP Phase 1)")
		return exitUsage
	}

	if fs.NArg() == 0 && isTerminal(stdin) {
		usage(stderr)
		return exitUsage
	}
	if err := cfg.Ready(); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsage
	}
	fmt.Fprintln(stderr, "error: lookups are not implemented yet (RFP Phase 1)")
	return exitUsage
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
	if err := mcp.Serve(cfg, version, stdin, stdout); err != nil {
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
  vpn-lookup [flags] <ip> [ip...]   # IPv4/IPv6, up to 100
  vpn-lookup [flags]                # addresses from stdin, one per line
  vpn-lookup mcp [--config <path>]  # run as a local MCP server (stdio)

Flags:
  --json            structured output (default: human-readable text)
  --no-cache        bypass the cache and re-query
  --clear-cache     delete every cache entry
  --timeout <dur>   upstream timeout (e.g. 10s)
  --config <path>   config file (default ~/.config/vpn-lookup/config.toml)
  --version         print version

Verdicts: tor / vpn / relay / gateway / mail_gateway / dns_resolver /
satellite / proxy / hosting / none / unknown.

Exit codes: 0 all lookups completed / 1 a source failed / 2 usage error.
Verdicts are never encoded in exit codes — scripts should read --json.

This build is a scaffold: lookups are not implemented yet.
`, "\n"))
}
