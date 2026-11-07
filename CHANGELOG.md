# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Shared safeguards: third-party text loses control and format characters,
  the key-carrying HTTP clients refuse redirects, and no error quotes a URL.
