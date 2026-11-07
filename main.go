// Command vpn-lookup tells whether an IP address is an intermediary — a
// commercial VPN, a proxy, Tor, a managed relay or gateway, a hosting
// provider — and whose, by layering ipapi.is and proxycheck.io into one
// lookup, as a CLI and a local MCP server.
//
// Every address looked up reaches those two services (with the operator's
// organization keys); no packet reaches the address itself. Results are the
// services' inference, not proof, and are never a basis for automatic
// blocking.
package main

import (
	"os"

	"github.com/nlink-jp/vpn-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
