// Package mcp is the zero-dependency stdio JSON-RPC 2.0 MCP server. In the
// scaffold it answers get_usage and cache_status; check_ip joins with the
// lookup engine.
//
// get_usage is canonical: the embedded usage.md is what an agent reads before
// its first call, and meta-tests pin it to the code. Tool errors are structured
// JSON ({code, message}), returned as results rather than protocol errors so
// that the model sees them. Arguments are decoded strictly (decodeArgs): an
// undeclared argument is refused by name, for every tool including those that
// take none. A closing stdin is the shutdown signal.
package mcp
