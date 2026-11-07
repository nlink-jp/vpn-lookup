# AGENTS.md — vpn-lookup

## Summary

A CLI and local MCP server that answers the question IP triage keeps asking: is this
address an intermediary — Tor, a commercial VPN, a managed relay, a corporate secure web
gateway, an email gateway, a public DNS resolver, a satellite ISP, a proxy, a hosting
provider — and whose? It layers two IP-intelligence services, ipapi.is and proxycheck.io,
into one verdict with per-source evidence and `seen_by` corroboration.

Module path: `github.com/nlink-jp/vpn-lookup`. Design authority:
[docs/ja/vpn-lookup-rfp.ja.md](docs/ja/vpn-lookup-rfp.ja.md) (English beside it).

**Status: scaffold (RFP Phase 2 of the org process).** Config, the CLI's `--version` /
help contract, and the MCP server's `get_usage` / `cache_status` work. The lookup engine,
the two clients, the cache, the public-address check and `check_ip` are RFP Phase 1 work.

## Build / test

```bash
make build   # → dist/vpn-lookup (NEVER `go build` directly)
make test    # go test -race -cover ./... then go vet -tags e2e ./...  (offline)
make lint    # golangci-lint
make check   # lint + test + build-all
make e2e     # live tests; keys from the environment, each test skips without its key
```

Go 1.25+. One dependency, the organization's TOML decoder `github.com/nlink-jp/toml`
(ADR-026). Everything else is the standard library.

## Layout

```
main.go              Entry point; delegates to internal/app
source_test.go       No raw control or bidi character in any source file
internal/config/     Strict TOML + VPN_LOOKUP_* loader (ported from opencti-lookup)
internal/app/        CLI shell: flags, dispatch (lookups: Phase 1)
internal/mcp/        Zero-dep stdio JSON-RPC 2.0 server; usage.md pinned by meta-tests
e2e/                 Live suite (build tag "e2e"), Phase 3
docs/{en,ja}/        RFP
```

Planned in Phase 1: `internal/ipaddr` (ported from shodan-lookup), `internal/ipapi`,
`internal/proxycheck`, `internal/verdict` (pure synthesis), `internal/cache` (per source),
`internal/engine`.

## Copy sources (chosen per package by last change, 2026-11-07)

- config, the Makefile and `source_test.go`: opencti-lookup (strict loader on nlink-jp/toml)
- MCP server loop and strict argument decoding: malware-lookup
- cache and the public-address check (Phase 1): shodan-lookup
- `scripts/`: copied from `nlink-jp/.github/templates/`, byte-identical (check-org check 10)

## Decisions (from the RFP — do not silently reverse)

- **One verdict, `seen_by` for corroboration, no `conflicting`.** ipapi.is's
  `egress_service` decides first, one verdict value per type (`relay`, `gateway`,
  `mail_gateway`, `dns_resolver`, `satellite`); otherwise the strongest class either source
  reports (`tor` > `vpn` > `proxy` > `hosting`); nothing reported is `none` only when every
  enabled source answered, else `unknown`.
- **A source without a key is not used.** ipapi.is without a key returns no detection flags
  (measured), so keyless use is pointless. One key per organization (both free tiers).
- **proxycheck.io always gets `tag=0`.** Otherwise anonymous results stay in the account's
  detection log for 180 days and clean ones get unpublished "post-query testing".
- **Cache per source.** ipapi.is 24 h default, 30-day ceiling (its terms §2.2).
  proxycheck.io: clean 1 h, anonymous until `delist_datetime`, at most 15 min.
- **Non-public addresses are refused before anything is sent**; IPv4-mapped / 6to4 /
  Teredo etc. are unwrapped and the inner IPv4 is what gets sent.
- **For the organization's own work only** (ipapi.is §2.3 forbids client IR engagements).

## Gotchas

- **The MCP server starts with no key** (get_usage and cache_status answer); the CLI's
  lookup path refuses with a usage error naming the variables to set.
- **`--version` is handled before config is read**, so a broken config never hides which
  build is installed (brew test runs it).
- **proxycheck.io accepts an invalid key silently** (answers 200 as if unregistered), so a
  response cannot tell whether the key took effect. Whether it reads the key from the POST
  body is an open item (RFP §7), to be settled with a dashboard custom-rule marker.
- **A URL parse error must not quote the URL** (Go's `url.Error` does): config reports the
  inner error only.
