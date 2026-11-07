# vpn-lookup

Is this IP address an intermediary — a VPN, a proxy, Tor, a relay, a gateway, a hosting
provider — and whose?

> **Status: release candidate.** The CLI and the MCP server both look addresses up, with a
> live end-to-end suite; not released yet. The design is in
> [docs/en/vpn-lookup-rfp.md](docs/en/vpn-lookup-rfp.md).

`vpn-lookup` is a CLI and local MCP server that layers two IP-intelligence services whose
free tiers may be used for an organization's own work — [ipapi.is](https://ipapi.is) and
[proxycheck.io](https://proxycheck.io) — into one lookup. For each address it returns one
verdict, the provider's name, and which source said so (`seen_by`):

| verdict | meaning |
|---|---|
| `tor` | a Tor exit |
| `vpn` | a commercial VPN exit or server |
| `relay` | a managed privacy relay (iCloud Private Relay, Cloudflare WARP) |
| `gateway` | a corporate secure web gateway (Zscaler, Netskope) — shared by many organizations |
| `mail_gateway` | an email security relay (Proofpoint, Mimecast, Barracuda) |
| `dns_resolver` | a public DNS resolver (Google Public DNS, Cisco OpenDNS) |
| `satellite` | a satellite ISP (Starlink, Viasat) — a real user's line, not an intermediary |
| `proxy` | a proxy, open or residential (a residential proxy is also a real household's line) |
| `hosting` | cloud, hosting or CDN |
| `none` | every enabled source answered and none reported an intermediary — not a claim that the line is residential |
| `unknown` | nothing was reported, but a source failed — never read it as `none` |

If an address is an intermediary, it does not lead to the person behind it; the next step
is a request to the provider.

## Before you use it

- **For your organization's own work only.** ipapi.is's terms (§2.3) forbid using its data
  to answer third parties' questions about IP addresses — client IR engagements included.
- **One key per organization.** Both free tiers are granted once per organization and forbid
  multiple accounts; analysts in the same organization share the key.
- **Every address looked up reaches both services.** ipapi.is states it does not log looked-up
  addresses and keeps personal data in the EEA. proxycheck.io is always queried with `tag=0`,
  which stops logging and its post-query testing (a clean address may still be held five
  minutes for inference); it stores data where it is generated (Canada, the UK, the EU or
  Singapore). If you check your own users' login origins, you are sending personal data to
  these services, and each lookup spends one of 1,000 free lookups a day on each.
- **In the proxycheck.io dashboard**, turn off "Address Logging" (an account-wide backstop
  for `tag=0`) and set no custom rules — they rewrite the responses this tool reads.
- **Results are inference, not proof.** Never use them as the basis for automatic blocking.

## Install

Not released yet. Build from source:

```bash
make build  # → dist/vpn-lookup
```

## Usage

```
vpn-lookup [flags] <ip> [ip...]   # IPv4/IPv6, up to 100; flags may come anywhere
vpn-lookup [flags]                # addresses from stdin, one per line
vpn-lookup --clear-cache          # delete every cache entry
vpn-lookup mcp                    # run as a local MCP server (stdio)

Flags:
  --json            structured output (default: human-readable text)
  --no-cache        bypass the cache and re-query
  --clear-cache     delete every cache entry
  --timeout <dur>   upstream timeout (e.g. 10s)
  --config <path>   config file (default ~/.config/vpn-lookup/config.toml)
  --version         print version
```

Exit codes: `0` all lookups completed / `1` a source failed (results still printed) /
`2` usage error. Verdicts are never encoded in exit codes.

Example (one block per address; names are what the services report):

```
$ vpn-lookup a.b.c.d
a.b.c.d
  verdict    : vpn (seen by both)
  provider   : ipapi.is: MullvadVPN / proxycheck.io: Mullvad
  ipapi      : vpn, datacenter; vpn MullvadVPN, last seen 2026-11-06T12:43:23.958Z; hosting Keminet SHPK; company type business
  proxycheck : vpn, hosting; risk 50, confidence 100; operator Mullvad [datacenter_vpns]; network Hosting
```

- Private, loopback, CGNAT, documentation and other non-public addresses are refused before
  anything is sent. An IPv4-mapped, IPv4-compatible or NAT64 address is looked up as the IPv4
  host it spells; a 6to4 or Teredo address as the IPv6 address itself.
- Answers are cached per source: ipapi.is for 24 hours (`[cache] ipapi_ttl_hours`, at most
  30 days), proxycheck.io as it recommends — an hour for a clean answer, until its
  `delist_datetime` and at most 15 minutes for an anonymous one. `--clear-cache` deletes
  everything (ipapi.is's terms require deleting cached answers within 30 days of the contract
  ending).
- A source without a key is shown as `disabled` and not used. Without ipapi.is, relays,
  gateways, email gateways, DNS resolvers and satellite ISPs cannot be told apart.

## Configuration

See [config.example.toml](config.example.toml). The file is read strictly: an unknown key,
an empty value or a missing `--config` file is an error. Environment variables
(listed below) override the file.

Environment variables override the file: `VPN_LOOKUP_IPAPI_API_KEY`,
`VPN_LOOKUP_PROXYCHECK_API_KEY`, `VPN_LOOKUP_IPAPI_BASE_URL`,
`VPN_LOOKUP_PROXYCHECK_BASE_URL`, `VPN_LOOKUP_CACHE_DIR`, `VPN_LOOKUP_IPAPI_TTL_HOURS`,
`VPN_LOOKUP_TIMEOUT_SECONDS`. A `base_url` must be https (plain http only to a loopback
host, for tests). A syntax error in the file is reported by line and column without
quoting the text, since it may be a key.

## MCP server

`vpn-lookup mcp` speaks MCP over stdio. Register it with a client such as Claude Code:

```json
{
  "mcpServers": {
    "vpn-lookup": { "command": "vpn-lookup", "args": ["mcp"] }
  }
}
```

| tool | role |
|------|------|
| `check_ip` | verdict, `seen_by` and per-source evidence for 1–100 public addresses |
| `cache_status` | which sources have a key, cache entries, and proxycheck.io's daily usage |
| `get_usage` | the server's operating manual — call it once before first use |

The server starts even with no key (`check_ip` then answers `no_api_key`). Arguments are
checked strictly: an undeclared argument is refused by name. A result that would cross
128 KB loses addresses from its tail, listed in `omitted` (a realistic 100-address answer
is about 90 KB).

## Build

```
make build   # → dist/vpn-lookup (never `go build` directly)
make test
make lint
```

## License

[MIT](LICENSE)
