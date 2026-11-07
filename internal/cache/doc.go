// Package cache is a JSON-file cache with atomic writes, shared by the CLI and
// the MCP server (ported from shodan-lookup).
//
// Entries are per source: an ipapi.is answer and a proxycheck.io answer about
// the same address are separate entries, so one source's outage never makes
// the healthy one's answers expire or be re-fetched. ipapi.is entries age on
// a fixed TTL (24 hours by default, at most 30 days — its terms §2.2), applied
// at read time so a config change takes effect on entries already on disk.
// proxycheck.io entries age by content (Load hands the caller the fetch time).
//
// Never cached: a failed answer for an address. Entry names are hashes of what
// determined the answer (Key), so investigated addresses do not sit readable
// in a directory listing. --clear-cache removes everything (ipapi.is §2.5
// requires deleting cached answers within 30 days of the contract ending).
package cache
