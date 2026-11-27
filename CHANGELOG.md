# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The MCP server speaks both eras of the protocol** (ADR-0001): the
  2026-07-28 revision, whose clients probe with `server/discover`, as well as
  the earlier `initialize` handshake (2025-11-25, 2025-06-18, 2024-11-05). The
  protocol layer is now the organization's shared module nlink-jp/mcp
  (organization ADR-030); the tools, their arguments and their results are
  unchanged.

### Changed

- Protocol details now follow the module:
  - an unknown tool is -32602 (it was an isError `unknown_tool` result, now
    gone from usage.md);
  - `tools/list`, `tools/call` and unknown methods before `initialize` are
    refused with -32602 (an unknown method was -32601);
  - `arguments` that is not an object is refused with -32602 before reaching
    the tool;
  - a request with `"id":null`, or without `"jsonrpc":"2.0"`, gets -32600;
  - messages are read one per line (up to 16 MiB) instead of as a JSON stream;
  - a parse error or a batch no longer ends the server (a batch gets -32600);
  - a panic in a tool is answered -32603 and the server goes on (it crashed);
  - up to 256 calls wait behind a running one; more are refused with -32603
    "server busy";
  - `notifications/cancelled` now cancels the call.
    A cancelled `check_ip` still runs to its end — the engine takes no context
    — and its answer is dropped; the cache is written whole to a temporary
    file and renamed, so no entry is ever partial; a temp file left by a
    process ended part-way (a SIGTERM past the shutdown grace) is removed by
    `vpn-lookup --clear-cache`.

  Requests piped in are still all answered before the server exits at end of
  input.
- `mcp.Serve` takes a context first, cancelled by SIGINT and SIGTERM in the
  `mcp` subcommand.

### Fixed

- SIGINT or SIGTERM ended the MCP server by killing the process; a signal now ends it through its context, so its cleanup runs.

## [0.1.1] - 2026-11-27

### Changed

- `make package` runs `govulncheck ./...` first (`make vuln`) and stops on a
  finding, so a release cannot be built past one.
- `make vuln` — and so `make package` — scans every platform in `PLATFORMS`,
  with the environment `build-all` builds each with. It scanned the host's
  build alone, so an advisory in a Linux- or Windows-only package could not
  stop a release.

### Fixed

- **`initialize` no longer echoes back whichever protocol version the client
  asks for.** The server answers with the requested revision only when it
  satisfies it (2025-11-25, 2025-06-18 or 2024-11-05), and with 2025-11-25
  otherwise, as the MCP lifecycle requires. A client asking for 2026-07-28 was
  told the server spoke it, while the server went on speaking the
  handshake-based protocol. 2025-03-26 is not offered: it requires accepting
  JSON-RPC batches, which this server does not.

## [0.1.0] - 2026-11-07

### Added

- Project scaffold: the RFP (en/ja) with the phase 0 measurement, the strict
  config loader (`[ipapi]` / `[proxycheck]` keys, `[cache] ipapi_ttl_hours`
  capped at ipapi.is's 30 days, `[network] timeout_seconds`, `VPN_LOOKUP_*`
  overrides), the CLI's `--version` / help contract, and the stdio MCP server
  answering `get_usage` and `cache_status`.
- Lookups from the CLI (RFP Phase 1): the public-address gate (ported from
  shodan-lookup; IPv4-mapped / -compatible / NAT64 send the IPv4 host, 6to4 /
  Teredo the IPv6 address), the ipapi.is client (bulk POST, key in the body),
  the proxycheck.io client (key and `tag=0` in the URL — measured: a body key
  is not read), the verdict synthesis, a per-source cache (ipapi.is 24 hours,
  proxycheck.io 1 hour clean / at most 15 minutes anonymous), text and
  `--json` output, and `--clear-cache`.
- The MCP tool `check_ip` (RFP Phase 2): validation identical to the CLI's,
  `no_api_key` when neither service has a key, compact JSON with provenance,
  and a 128 KB ceiling that drops results from the tail into `omitted`.
  `cache_status` now reports cache entries and proxycheck.io's daily usage
  (from its dashboard API). The manual documents every verdict value, and a
  meta-test pins that.
- Third-party names are capped at 200 characters and an operator's service
  list at 10, so results fit an MCP client's budget.
- From the pre-release review: a config syntax error never quotes the value
  (it may be an unquoted key); a verdict given while a source failed, or one
  that overrode a tor / vpn / proxy report, says so in its notes; a boolean
  is_crawler is kept; proxycheck.io's message is capped; the 128 KB ceiling
  measures the escaped wire text; inputs are capped at 1,000 with duplicates;
  cached answers are scoped by endpoint and key fingerprint; --clear-cache
  removes temp files and runs with a broken config; MCP argument names must
  match exactly.
- Shared safeguards: third-party text loses control and format characters,
  the key-carrying HTTP clients refuse redirects, and no error quotes a URL.
