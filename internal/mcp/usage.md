# vpn-lookup MCP server

**Tells whether an IP address is an intermediary, and whose**, by layering two sources: ipapi.is and proxycheck.io. An intermediary is Tor, a commercial VPN, a managed privacy relay (iCloud Private Relay), a corporate secure web gateway (Zscaler), an email security gateway (Proofpoint), a public DNS resolver, a satellite ISP, a proxy, or a hosting provider. If an address is one, it does not lead to the person behind it.

> **This build is a scaffold.** The lookup tool, `check_ip`, is not implemented yet. The design is in `docs/en/vpn-lookup-rfp.md`.

Every address looked up reaches both services, with the operator's organization keys; no packet reaches the address itself. Results are the services' inference, never a basis for automatic blocking.

## Tools

### `get_usage`

No arguments. Returns this manual.

### `cache_status`

No arguments. Reports `sources` (the services that have a key — an empty list means none is configured), `cache_dir`, `ipapi_ttl_hours`, and `proxycheck_ttl`. Answers even when no key is configured.

## Arguments are strict

Every tool refuses an argument it does not declare, naming it: `arguments: json: unknown field "verbose"`. Nothing runs before the arguments decode.

## Error recovery

Tool errors are structured JSON: `{"code": ..., "message": ...}` with `isError: true`.

| code | meaning | recovery |
|------|---------|----------|
| `invalid_input` | an argument this tool does not declare, or one of the wrong JSON type | fix the name or the type and call again |
| `unknown_tool` | a tool name this server does not have | call `tools/list` |
| `internal_error` | the result could not be encoded | report it; it is a bug |
