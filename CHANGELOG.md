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
  answering `get_usage` and `cache_status`. Lookups and `--clear-cache` report
  that they are not implemented yet.
