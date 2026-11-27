// Package mcp is vpn-lookup's stdio MCP server, speaking both eras of the
// protocol through nlink-jp/mcp's server.ToolServer (ADR-0001), answering
// check_ip, cache_status and get_usage over the same engine the CLI uses.
//
// This package is where the response budget lives: check_ip's result is
// encoded compactly and, if it would cross 128 KB, loses results from its tail,
// named in omitted (a realistic 100-address answer is about 90 KB). The CLI's
// --json is never cut.
//
// get_usage is canonical: the embedded usage.md is what an agent reads before
// its first call, and meta-tests pin it to the tools, arguments, error codes
// and verdict values. Tool errors are structured JSON ({code, message}),
// returned as results rather than protocol errors so that the model sees them.
// Arguments are decoded strictly (decodeArgs): an undeclared argument is
// refused by name, for every tool including those that take none. Addresses
// are validated exactly as the CLI validates them (ipaddr.ParseBatch) before
// anything is sent. The server ends at end of input (answering every request
// that arrived) or on SIGINT/SIGTERM.
package mcp
