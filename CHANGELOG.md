# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `make package` runs `govulncheck ./...` first (`make vuln`) and stops on a
  finding, so a release cannot be built past one.

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
