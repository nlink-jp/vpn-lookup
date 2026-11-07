# RFP: vpn-lookup

> Generated: 2026-11-07
> Status: Draft (phase 0 measured; all seven items agreed with the requester; design review applied)

## 1. Problem Statement

When incident response or log analysis turns up an IP address, the first question is
whether it is the line of the attacker or user themselves, or an intermediary that anyone
can rent or that many users share — a commercial VPN, a proxy, a cloud or hosting data
centre, Tor, a managed relay such as iCloud Private Relay, a corporate secure web gateway
such as Zscaler, an email relay such as Proofpoint, or a public DNS resolver — and whose.
If it is an intermediary, the address does not lead to the person: the next step is a
request to the provider, and blocking the address or guessing its location means little.
The current tools recognise only Tor (tor-exit-lookup) and iCloud Private Relay
(icloud-relay-lookup).

vpn-lookup is a CLI and local MCP server that layers two sources whose free tiers may be
used for an organization's own work — **ipapi.is** and **proxycheck.io** — into one lookup,
and returns the kind of intermediary, the provider's name, and which source said so.
Reputation (abuser flag, risk score) is attached for reference only; judging reputation is
abuse-lookup's job.

Two uses are intended, **both limited to the organization's own work**: (1) triaging a
suspicious address under investigation (agents over MCP and analysts), and (2) checking
whether the organization's own users log in through an intermediary. Use (2) sends the
users' IP addresses — personal data — to external services (§7). Investigations done for
clients (IR engagements) are out of scope: ipapi.is §2.3 forbids them.

## 2. Functional Specification

### Commands / API Surface

**CLI**

```
vpn-lookup [flags] <ip> [ip...]   # one or more as arguments; none reads stdin, one per line
  --json            # structured output (default: human-readable text)
  --no-cache        # bypass the cache and re-query
  --timeout <dur>   # upstream timeout
  --config <path>   # config file
  --clear-cache     # delete every cache entry (answers ipapi.is §2.5's deletion duty)
  --version         # required (brew test calls it)
vpn-lookup mcp      # local MCP server (stdio)
```

- IPv4 and IPv6 are detected automatically. No subcommand split: the input decides the intent
- **Anything that is not a public address is refused on the spot and never sent** (exit 2).
  The check is shodan-lookup's `internal/ipaddr`, ported: it covers 100.64/10 (CGNAT), the
  documentation and benchmarking ranges, ULA, site-local and the 2000::/3 allow-list, and
  unwraps IPv4-mapped, NAT64, 6to4, Teredo and IPv4-compatible IPv6 to judge the IPv4
  inside. **The unwrapped IPv4 is what gets sent**
- Inputs are canonicalised with `netip.Addr` (`String()`) and deduplicated before sending.
  Every input is validated before any lookup starts; one invalid entry sends nothing
- At most 100 addresses per invocation. Sweeps of thousands are out of scope

**MCP tools**

| tool | role |
|---|---|
| `check_ip` | verdict and evidence for 1–100 addresses |
| `cache_status` | cache entries, TTLs, location, active sources, and each source's remaining quota where it can be read |
| `get_usage` | the operating manual (embedded usage.md, pinned to the code by meta-tests); says that use (2), login-origin checks, spends quota quickly |

With no key at all the MCP server still starts; `cache_status` and `get_usage` answer and
`check_ip` returns the structured error `no_api_key`. The CLI refuses with a usage error
(exit 2).

### Input / Output

**Verdict (`verdict`)**

| value | meaning |
|---|---|
| `tor` | a Tor exit |
| `vpn` | a commercial VPN exit or server |
| `relay` | a managed privacy relay (iCloud Private Relay, Cloudflare WARP); its users sit behind it |
| `gateway` | a corporate secure web gateway (Zscaler, Netskope, …). **Many organizations share it, so the address does not identify one** |
| `mail_gateway` | an email security relay (Proofpoint, Mimecast, Barracuda); what appears in Received headers is this provider's relay |
| `dns_resolver` | a public DNS resolver (Google Public DNS, Cisco OpenDNS); its traffic is resolver queries, not users |
| `satellite` | a satellite ISP (Starlink, Viasat). **Not an intermediary but a real user's line**, shared behind CGNAT and with an unreliable location |
| `proxy` | a proxy, open or residential. **A residential proxy is also a real household's line** — read `proxy_kind` and the operator's services |
| `hosting` | cloud, hosting or CDN — servers anyone can rent. A crawler carries its name in `crawler` |
| `none` | every enabled source answered and none reported an intermediary. **Not a claim that the line is residential** |
| `unknown` | nothing was reported, but an enabled source failed. Never read it as `none` |

**Synthesis rule (decided from the phase 0 measurement and the design review)**

1. When ipapi.is names a managed service (`egress_service`), its type decides the verdict:
   `private_relay` → `relay`, `secure_web_gateway` → `gateway`, `email_gateway` →
   `mail_gateway`, `dns_resolver` → `dns_resolver`, `satellite` → `satellite`. An unknown
   type is shown as evidence and the rule moves on to step 2
2. Otherwise the strongest class either source reports: `tor` > `vpn` > `proxy` > `hosting`
3. Nothing reported and every enabled source answered: `none`. A source failed: `unknown`
4. Separately, `seen_by` (`both` / `ipapi` / `proxycheck`) says who reported the verdict. A
   detection by one source only is a difference in coverage, not a conflict; there is no
   `conflicting` value
5. Without an ipapi.is key step 1 is unavailable, and proxycheck.io reads iCloud Relay as
   `vpn` and Zscaler as `hosting`; the result says that relay/gateway identification is
   unavailable

**Attached to the verdict**

- `mobile` (mobile carrier), `crawler` (the bot's name), `proxy_kind` (open or residential,
  as far as the operator's services tell), and ipapi.is's `vpn.last_seen` (to spot a stale
  VPN flag)
- Reputation (ipapi.is `is_abuser`, proxycheck.io `risk`) for reference only
- No geolocation

**One result (JSON; fields are fixed in phase 1)**

```json
{
  "ip": "45.142.26.2",
  "verdict": "vpn",
  "seen_by": "both",
  "mobile": false,
  "crawler": null,
  "providers": { "ipapi": "MullvadVPN", "proxycheck": "Mullvad" },
  "ipapi": {
    "enabled": true,
    "is_vpn": true, "is_proxy": false, "is_tor": false, "is_datacenter": true,
    "is_mobile": false, "is_abuser": false, "is_crawler": false,
    "vpn_service": "MullvadVPN", "vpn_last_seen": "2026-11-06T12:43:23Z",
    "datacenter": "Keminet SHPK",
    "egress_service": null, "company_type": "business"
  },
  "proxycheck": {
    "enabled": true,
    "vpn": true, "proxy": false, "tor": false, "hosting": true,
    "risk": 50, "confidence": 100,
    "operator": "Mullvad", "operator_services": ["datacenter_vpns"],
    "network_type": "Hosting", "delist_datetime": "2026-11-07T03:35:58Z"
  },
  "degraded": false,
  "from_cache": false
}
```

- A source without a key is `enabled: false` (never queried) and every boolean of it is
  `null` (`false` means only "queried and not so")
- `egress_service` stays the `{type, provider}` object
- Provider, operator and company names, WHOIS-derived names and upstream error text are
  **third-party text**: control and format characters (bidi, zero-width) are stripped, and
  the MCP result says so (as in malware-lookup v0.4.0)
- Exit codes: `0` all lookups completed / `1` a source failed (results still printed) /
  `2` usage or input error. Verdicts are never encoded in exit codes

### Configuration

`~/.config/vpn-lookup/config.toml` (XDG-aware) and `VPN_LOOKUP_*` environment variables
(the environment wins).

```toml
[ipapi]
api_key = "..."

[proxycheck]
api_key = "..."

[cache]
ipapi_ttl_hours = 24   # default 24 hours; anything over 30 days (720 hours) is refused

[network]
timeout_seconds = 15
```

- Both keys are optional, and **a source without a key is not used**
- ipapi.is returns no detection flags without a key (measured), so keyless use is pointless
- **One key per organization.** ipapi.is grants the free tier "once per person or legal
  entity" (§2.9) and proxycheck.io one free account per customer; both forbid multiple
  accounts. Analysts in the same organization share the key (proxycheck.io keys may be
  shared inside the organization)
- TOML is read with the organization's decoder `nlink-jp/toml` (ADR-026)

### External Dependencies

| dependency | use | authentication |
|---|---|---|
| ipapi.is API (`https://api.ipapi.is`) | VPN / proxy / Tor / data centre / mobile / crawler / managed-service detection and provider names | the organization's free account key, sent in the POST JSON body (never in the URL) |
| proxycheck.io v3 API (`https://proxycheck.io/v3/`) | VPN / proxy / Tor / hosting detection, operator name, risk | the organization's free account key (where it goes is the open item in §7) |

No dependencies beyond the Go standard library (TOML comes from the organization's own library).

## 3. Design Decisions

- **Go, standard library only.** The organization's supply-chain policy. The MCP skeleton is
  ported from a lookup sibling, choosing per package the most recent one
  (`git log -1 -- internal/<pkg>`). The public-address check is shodan-lookup's
  `internal/ipaddr`, ported
- **One tool layering two sources.** There is one question — is this an intermediary — and
  whether the two sources agree is itself evidence (the malware-lookup pattern)
- **One verdict, with `seen_by` as corroboration.** The first draft's `conflicting` was
  expected to fire constantly, since VPN servers live in data centres and the sources'
  coverage differs; the measurement (4 of 9 samples classified differently) confirmed it,
  and it was dropped
- **ipapi.is's `egress_service` takes precedence, one verdict value per type** (the
  requester's decision). proxycheck.io answered `vpn` for iCloud Private Relay and `hosting`
  for Zscaler. Who sits behind decides the next step — a company's employees, an email
  sender, a resolver's users, a satellite subscriber
- **A failure never reads as `none`.** Nothing reported plus a failed source is `unknown`
- **Other tools' results are not merged in.** tor-exit-lookup and icloud-relay-lookup
  (authoritative local lists), asn-lookup (ASN, organization) and abuse-lookup (reputation)
  keep their roles; mcp-tactics' IP route says how to combine them. vpn-lookup widens that
  route's "is it an anonymizing egress at all?" step
- **Tier 2 on the observability ladder, keyed.** Every address looked up reaches both sources
- **proxycheck.io always gets `tag=0`, and no setting removes it.** Without it, an address
  judged anonymous stays in the account's detection log for 180 days, and one judged clean
  goes through an unpublished "battery of post-query testing" (GDPR page). Even with
  `tag=0` a clean address may be held five minutes for inference. The README recommends
  turning off the account-wide "Address Logging" in the dashboard as a backstop
- **The HTTP client that carries a key refuses redirects** (Go forwards custom headers to
  another host), and **no error text contains a URL** (Go's `url.Error` quotes the whole URL)
- **An "absent" answer is confirmed from its body** (knowledge: "Decide `not_found` on the
  shape of the 404's body"). ipapi.is's bulk endpoint drops invalid entries silently, so
  **an entry missing from the response is a failure for that address**, never "nothing found"
- **Cache per source.** ipapi.is: 24 hours by default (ceiling 30 days, terms §2.2).
  proxycheck.io follows its recommendation: clean results 1 hour, anonymous results until
  `delist_datetime`, at most 15 minutes. Caching per source keeps one source's outage from
  spending the other's quota. The cache key includes the set of enabled sources, so adding a
  key re-queries
- **proxycheck.io's `warning` (near the limit, HTTP 200) is an answer with a note attached**
- **Out of scope:** geolocation, reputation as the main question, proxycheck.io's
  disposable-email check, paid plans and database downloads, sweeps of thousands, automatic
  blocking decisions, client IR engagements

## 4. Development Plan

### Phase 0: Measurement (done 2026-11-07)

With the requester's free keys, nine samples were looked up — a Tor exit, iCloud Relay,
Mullvad, AWS, Cloudflare IPv6, a French home line, NTT docomo, proxycheck.io's documentation
example, and Zscaler — and the synthesis rule and caching in §2 were decided from them. The
following design review's findings were applied. Results are in the Discussion Log.

### Phase 1: Core

- Input validation (port `internal/ipaddr`, canonicalise, deduplicate), two clients (ipapi.is:
  key in the POST body, bulk of 100; proxycheck.io: always `tag=0`), verdict synthesis (pure
  functions), per-source cache (`--clear-cache`), config, CLI
- **Phase 1 measurements:** both APIs' responses to a miss, a wrong path, an invalid key, an
  exhausted quota and `warning`; proxycheck.io's per-entry failures and mid-batch quota
  exhaustion in bulk; real examples of `satellite` / `dns_resolver` / `email_gateway` /
  residential proxies / crawlers. Pin the shapes in the clients and tests
- **Settle where proxycheck.io reads the key:** add a marker field with a dashboard custom
  rule and see whether it comes back with the key only in the POST body
- Remaining-quota reporting (proxycheck.io through its dashboard API; ipapi.is to be checked)
- All tests offline (fake upstream servers). Reviewable on its own

### Phase 2: MCP

- `check_ip` / `cache_status` / `get_usage`, closed schemas and strict argument decoding (ADR-021)
- Meta-tests pin usage.md to the tools, arguments, verdict values and error codes
- stdio smoke test. Reviewable on its own

### Phase 3: Release

- Live e2e against the real services (keys from the environment, skipped without them),
  README (en/ja), AGENTS.md, CHANGELOG
- The README states: the organization's own work only (no client IR engagements), one key per
  organization, the data is inference and not for automatic blocking, where looked-up
  addresses go and may be stored, no proxycheck.io custom rules (they rewrite responses),
  turn off Address Logging
- Independent verification before release
- Signing, notarization, release, Homebrew tap, integration into cybersecurity-series, org
  profile, website and About text, check-org

**Dependency on another repository (not a phase of this plan):** after release, mcp-tactics
(skills-series) will need to list the server. Whether and when is for mcp-tactics' owner to decide.

## 5. Required API Scopes / Permissions

No OAuth or IAM. Two free account API keys only.

- ipapi.is: the organization's registered account key (free tier 1,000 requests/day)
- proxycheck.io: the organization's registered account key (free tier 1,000 queries/day)

Each free tier is one per organization (ipapi.is §2.9 "once per person or legal entity", no
multiple accounts; proxycheck.io "one free account per customer"). Analysts in the same
organization share the key, and it never leaves the organization (proxycheck.io). The
allowance for software where "users supply their own key" means other organizations, not
colleagues.

## 6. Series Placement

Series: cybersecurity-series
Reason: it joins the IP investigation tools (asn, whois, abuse, tor-exit, icloud-relay and
shodan-lookup) and fills the missing "is this an intermediary" step.

## 7. External Platform Constraints

| item | ipapi.is | proxycheck.io |
|---|---|---|
| free tier | with a key 1,000/day, full response. Keyless: 30/day, no detection flags, no bulk | registered 1,000/day (confirmed as the dashboard's Daily Limit); unregistered 100 |
| bulk | POST up to 100, one count each; duplicates and invalid entries dropped silently | POST up to 1,000 (the documentation also says 10,000 elsewhere) |
| permitted use | internal use only (§2.2); the free tier explicitly includes commercial use (§2.9); a service answering third parties' questions about IP addresses is forbidden even one record at a time (§2.3) → no client IR engagements | no purpose restriction; software where users enter their own key is explicitly allowed |
| looked-up addresses | not logged (privacy §3.3); personal data stated to stay in the EEA (no server locations named) | `tag=0` stops logging and post-query testing, though a clean address may be held five minutes for inference; data stored where it is generated (Canada, UK, EU, Singapore) |
| caching | up to 30 days (§2.2); delete within 30 days of the contract ending (§2.5; records of individual events may be kept) | recommended 10 min–1 h for clean, 1–15 min for anonymous, or until `delist_datetime` |
| errors | JSON `error_code` (`ERR_QUOTA_EXCEEDED`, …); ignoring the keyless limit earns a 24-hour firewall block | v3 returns HTTP status codes; `warning` (200) near the limit. **An invalid key is silently treated as no key** (measured) |
| other | — | dashboard custom rules can rewrite responses (`type`, …) → assume none are set |

**Shared cautions**

- **The data is probabilistic inference.** ipapi.is §2.8 asks that it not be the sole basis
  of decisions with legal or similar effects on individuals (GDPR Art. 22). The README says
  not to use it for automatic blocking, the login-origin use included
- **An organization's users' addresses are personal data.** Looking them up sends them to two
  external services; the README says where they go and where they may be stored
- **The organization's own TLS-inspecting gateway may log whole URLs.** A proxycheck.io key
  sent in the URL would be stored there (resolved if the body works — the open item)

**Open items (settled in phase 1)**

- **Whether proxycheck.io reads the key from the body or the URL.** An invalid key raises no
  error and the dashboard's query count stayed at 0 for several minutes, so phase 0 could not
  decide. Settle it with a custom-rule marker (§4). Until then follow the documentation (URL)
  and keep URLs out of error text
- Whether ipapi.is's remaining quota can be read

---

## Discussion Log

- **Origin (2026-11-07):** a survey of about 70 sources whose free tiers may be used for an
  organization's own work found that ipapi.is and proxycheck.io qualify and answer a question
  no existing tool does — is this an intermediary, and whose. Their terms were re-read
  first-hand from the originals
- **Scope:** reputation stays reference-only (abuse-lookup's job). Checking the organization's
  own users' login origins is in scope. After the design review the requester decided the
  tool is for the organization's own work only, not client IR engagements
- **Name:** `egress-lookup` was proposed; the requester chose `vpn-lookup` for clarity
- **Volume and non-public addresses:** at most 100 per call, sweeps of thousands out of scope;
  private and similar addresses refused on the spot
- **Verdict rule:** the first draft was `vpn` / `proxy` / `tor` / `hosting` / `none` /
  `conflicting`. Expecting `conflicting` to fire constantly, the rule was deferred to the
  measurement; afterwards `relay` and `gateway` were added, `conflicting` dropped and
  `seen_by` added. The design review found three unmapped `egress_service` types and that a
  failure could read as `none`; the requester chose separate values `mail_gateway`,
  `dns_resolver` and `satellite`, and `unknown` was added
- **Phase 0 measurement (nine samples):**
  - Both agree: Tor exit, Mullvad (provider names MullvadVPN / Mullvad), AWS, Cloudflare IPv6
    (ipapi.is also flags anycast), a French home line
  - iCloud Relay: ipapi.is says datacenter + `egress_service: private_relay`; proxycheck.io
    says vpn (operator iCloud)
  - Zscaler: ipapi.is says `egress_service: secure_web_gateway` (deliberately not a data
    centre); proxycheck.io says hosting
  - proxycheck.io's documentation example: only proxycheck.io says vpn; ipapi.is says data centre only
  - NTT docomo: only ipapi.is says mobile; proxycheck.io gives the network type "Business"
  - For the Tor exit, ipapi.is also flags proxy and abuser; proxycheck.io's operator is "TOR"
- **Cache:** first a flat 24 hours, then a flat hour after the measurement. The design review
  pointed out that anonymous results are recommended for at most 15 minutes, that not caching
  degraded results spends the healthy source's quota, and that the key must record enabled
  sources; caching became per source
- **Number of keys:** the draft said each operator configures their own keys; the review
  pointed out both free tiers are one per organization and forbid multiple accounts. Now one
  key per organization, shared inside it
- **proxycheck.io key:** an invalid key in the URL or the body is answered 200 and the query
  count does not move, so a response cannot tell whether a key took effect. The review
  proposed a custom-rule marker to settle it
- **Lessons carried over from malware-lookup v0.4.0's independent review:** refuse redirects on
  a key-carrying client, confirm an "absent" answer from its body, clean third-party text
