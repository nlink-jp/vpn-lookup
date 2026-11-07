# CLAUDE.md — vpn-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that tells whether an IP address is an intermediary (Tor, VPN,
relay, gateway, proxy, hosting, …) and whose, by layering ipapi.is and proxycheck.io.

Design authority: [docs/ja/vpn-lookup-rfp.ja.md](docs/ja/vpn-lookup-rfp.ja.md).
Contributor summary and gotchas: [AGENTS.md](AGENTS.md).

## Build & test

```bash
make build   # never `go build` directly
make test    # offline
make lint
make e2e     # live; keys from VPN_LOOKUP_IPAPI_API_KEY / VPN_LOOKUP_PROXYCHECK_API_KEY
```

## Key conventions

- **Measure before you code a response shape.** Both APIs have undocumented edges (an
  invalid proxycheck.io key is silently treated as no key; ipapi.is bulk drops entries
  silently). Pin what was measured in tests.
- **Input that is not understood is refused**: unknown config keys, empty values, a missing
  `--config` file, undeclared MCP arguments, non-public addresses.
- **A negative answer is never manufactured.** A source failure is `unknown`, never `none`;
  an entry missing from a bulk response is a failure for that address.
- **Keys never appear on any output surface.** The key-carrying HTTP client refuses
  redirects; no error text contains a URL. `Config.Redacted` for anything that prints
  settings.
- **proxycheck.io always gets `tag=0`**, with no setting to remove it.
- **Third-party text is cleaned** of control and format characters before it reaches a
  terminal or an MCP client.
- **No raw control or bidi character in any source file** (`source_test.go`).
- **The documents are pinned to the code**: `internal/mcp/usage_test.go`. README.md and
  README.ja.md change together.

## Communication Language

All communication between contributors and Claude Code is conducted in **Japanese**.
