# AGENTS.md — vpn-lookup

## Summary

A CLI and local MCP server that answers the question IP triage keeps asking: is this
address an intermediary — Tor, a commercial VPN, a managed relay, a corporate secure web
gateway, an email gateway, a public DNS resolver, a satellite ISP, a proxy, a hosting
provider — and whose? It layers two IP-intelligence services, ipapi.is and proxycheck.io,
into one verdict with per-source evidence and `seen_by` corroboration.

Module path: `github.com/nlink-jp/vpn-lookup`. Design authority:
[docs/ja/vpn-lookup-rfp.ja.md](docs/ja/vpn-lookup-rfp.ja.md) (English beside it).

**Status: RFP Phases 1–2 done (CLI and MCP lookups); Phase 3 (live e2e, release) next.** Not released.

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
internal/ipaddr/     Public-address gate + Target (what is sent), ported from shodan-lookup
internal/guard/      Clean (Cc/Cf), RefuseRedirects, ScrubURL — every client uses all three
internal/ipapi/      ipapi.is client (bulk POST, key in the JSON body)
internal/proxycheck/ proxycheck.io v3 client (key + tag=0 in the URL, ips in the body)
internal/verdict/    Pure synthesis: egress first, tor > vpn > proxy > hosting, none/unknown
internal/cache/      Per-source JSON-file cache (ported from shodan-lookup), dir 0700
internal/engine/     Per-source cache lookups, one request per source, fresh verdicts
internal/app/        CLI shell: flags (anywhere), validation, text/JSON, --clear-cache
internal/mcp/        Zero-dep stdio JSON-RPC 2.0 server: check_ip / cache_status / get_usage;
                     the 128 KB response ceiling (tail omission); usage.md pinned by meta-tests
e2e/                 Live suite (build tag "e2e"): ipapi.is's documented example addresses per
                     managed-service type; skips without both keys; ~6 lookups per source
docs/{en,ja}/        RFP
```


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

- **The MCP server starts with no key** (get_usage and cache_status answer; check_ip
  returns `no_api_key`); the CLI's lookup path refuses with a usage error naming the
  variables to set.
- **The response budget lives in the MCP layer.** Names are capped at 200 characters and
  operator services at 10 in the clients; check_ip's compact JSON drops results from the
  tail into `omitted` only past 128 KB. A realistic result is ~880 bytes (100 → ~90 KB);
  every name at its cap would be ~430 KB, which is what the backstop is for.
- **cache_status makes one network call** when proxycheck.io has a key: its dashboard usage
  API (key in the URL, counts an hour late). ipapi.is exposes no quota.
- **`--version` is handled before config is read**, so a broken config never hides which
  build is installed (brew test runs it).
- **proxycheck.io accepts an invalid key silently** (answers 200 as if unregistered), so a
  response cannot tell whether the key took effect, **and it does not read a key from the POST
  body** — measured 2026-11-07 on the dashboard counter (which lags about an hour): only the
  URL-key queries were counted. So the key is in the URL, and every error path runs
  `guard.ScrubURL`. `tag=0` queries are counted too.
- **Both APIs key their responses by the exact string sent** (a non-canonical IPv6 comes back
  under the same spelling): send `netip.Addr.String()` and map back by it.
- **Invalid entries:** ipapi.is drops them silently (so a missing entry is a failure);
  proxycheck.io returns `{"error": "..."}` per entry, or HTTP 400 `{"status":"error"}` when
  nothing in the request is valid. Wrong paths answer 404 HTML on both; a bad ipapi.is key is
  403 `ERR_FORBIDDEN_INVALID_API_KEY`.
- **Only ipapi.is identifies managed services.** Measured: Cisco OpenDNS → `dns_resolver`,
  Proofpoint → `email_gateway`, Starlink → `satellite`, Zscaler → `secure_web_gateway`
  (proxycheck.io called them Business / Wireless / vpn+hosting). That is why its
  `egress_service` decides first.
- **Fixtures are hand-written**, never captured responses, and never the addresses of hosts
  seen in measurement. Client tests use documentation ranges; CLI tests (which refuse those)
  use well-known resolver addresses with fictional data.
- **A URL parse error must not quote the URL** (Go's `url.Error` does): config reports the
  inner error only.
