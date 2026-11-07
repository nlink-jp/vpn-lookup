// Package ipaddr is the pre-network gate. Every address is judged against a
// finite table of address classes before anything is sent: only publicly
// routable addresses leave this machine.
//
// Two reasons, in order. Every lookup reaches ipapi.is and proxycheck.io with
// the organization's keys, so an internal address sent there tells two third
// parties about the operator's own network. And both services describe the
// public Internet only, so an internal address could only come back as
// "nothing known" — an answer that reads like a finding.
//
// The table is the whole rule (ported from shodan-lookup internal/ipaddr,
// itself from util-series/web-fetch internal/guard, plus the documentation
// ranges). A class is a table row plus a test row; never a pattern.
package ipaddr

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// Class names an address class that is never sent. The empty Class means
// publicly routable.
type Class string

// The refused classes.
const (
	ClassLoopback      Class = "loopback"
	ClassPrivate       Class = "private"
	ClassLinkLocal     Class = "link-local"
	ClassSiteLocal     Class = "site-local"
	ClassUniqueLocal   Class = "unique-local"
	ClassUnspecified   Class = "unspecified"
	ClassBroadcast     Class = "broadcast"
	ClassMulticast     Class = "multicast"
	ClassShared        Class = "shared-address-space"
	ClassDocumentation Class = "documentation"
	ClassReserved      Class = "reserved"
)

type row struct {
	prefix netip.Prefix
	class  Class
}

// table is the finite refused domain. No two rows nest; exact addresses
// (unspecified, broadcast, ::1) are judged before the table.
var table = []row{
	// IPv4
	{mustPrefix("0.0.0.0/8"), ClassReserved},
	{mustPrefix("10.0.0.0/8"), ClassPrivate},
	{mustPrefix("100.64.0.0/10"), ClassShared},
	{mustPrefix("127.0.0.0/8"), ClassLoopback},
	{mustPrefix("169.254.0.0/16"), ClassLinkLocal},
	{mustPrefix("172.16.0.0/12"), ClassPrivate},
	{mustPrefix("192.0.0.0/24"), ClassReserved},
	{mustPrefix("192.0.2.0/24"), ClassDocumentation}, // TEST-NET-1
	{mustPrefix("192.168.0.0/16"), ClassPrivate},
	{mustPrefix("198.18.0.0/15"), ClassReserved},        // benchmarking
	{mustPrefix("198.51.100.0/24"), ClassDocumentation}, // TEST-NET-2
	{mustPrefix("203.0.113.0/24"), ClassDocumentation},  // TEST-NET-3
	{mustPrefix("224.0.0.0/4"), ClassMulticast},
	{mustPrefix("240.0.0.0/4"), ClassReserved},
	// IPv6
	{mustPrefix("100::/64"), ClassReserved},    // discard-only
	{mustPrefix("2001:2::/48"), ClassReserved}, // benchmarking
	{mustPrefix("2001:db8::/32"), ClassDocumentation},
	{mustPrefix("3fff::/20"), ClassDocumentation},
	{mustPrefix("fc00::/7"), ClassUniqueLocal},
	{mustPrefix("fe80::/10"), ClassLinkLocal},
	{mustPrefix("fec0::/10"), ClassSiteLocal},
	{mustPrefix("ff00::/8"), ClassMulticast},
}

// embed is an IPv6 prefix that carries an IPv4 address; the embedded address
// is judged in place of the outer one.
type embed struct {
	prefix  netip.Prefix
	name    string
	extract func(netip.Addr) netip.Addr
}

var embeds = []embed{
	{mustPrefix("64:ff9b::/96"), "nat64", last4},
	{mustPrefix("64:ff9b:1::/48"), "nat64-local", last4},
	{mustPrefix("2002::/16"), "6to4", bytes2to5},
	{mustPrefix("2001::/32"), "teredo", last4Inverted}, // the client; the server is judged too (Classify)
	// ::/96 (IPv4-compatible) last: :: and ::1 live inside it and are judged
	// exactly before the embeds run.
	{mustPrefix("::/96"), "ipv4-compatible", last4},
}

var (
	globalUnicast6 = mustPrefix("2000::/3")
	unspecified4   = netip.MustParseAddr("0.0.0.0")
	broadcast4     = netip.MustParseAddr("255.255.255.255")
)

// Classify judges one address. It returns the refused class, or "" when the
// address is publicly routable, and the name of the IPv6 embedding that was
// unwrapped to reach the judgment ("" when none).
func Classify(addr netip.Addr) (Class, string) {
	if addr.Is4In6() {
		c, _ := Classify(addr.Unmap())
		return c, "ipv4-mapped"
	}
	if addr.Is6() {
		if addr.IsUnspecified() {
			return ClassUnspecified, ""
		}
		if addr.IsLoopback() {
			return ClassLoopback, ""
		}
		for _, e := range embeds {
			if e.prefix.Contains(addr) {
				c, _ := Classify(e.extract(addr))
				if c == "" && e.name == "teredo" {
					c, _ = Classify(teredoServer(addr))
				}
				return c, e.name
			}
		}
		if c := lookup(addr); c != "" {
			return c, ""
		}
		// An allow-list, not only a deny-list: global unicast IPv6 is
		// 2000::/3. Anything outside it (4000::/3, ::ffff:0:0/96 translated
		// forms, unassigned space) is not an address on the public Internet.
		if !globalUnicast6.Contains(addr) {
			return ClassReserved, ""
		}
		return "", ""
	}
	if addr == broadcast4 {
		return ClassBroadcast, ""
	}
	if addr == unspecified4 {
		return ClassUnspecified, ""
	}
	return lookup(addr), ""
}

func lookup(addr netip.Addr) Class {
	for _, r := range table {
		if r.prefix.Contains(addr) {
			return r.class
		}
	}
	return ""
}

// Error is a refused input. It never carries anything but the input itself,
// which the caller typed.
type Error struct {
	Input  string
	Reason string
}

// Error reads as one sentence: the input, quoted, then what is wrong with it
// ("is a private address; …"). A refusal that is about the query as a whole
// carries no Input.
func (e *Error) Error() string {
	if e.Input == "" {
		return e.Reason
	}
	return fmt.Sprintf("%q %s", e.Input, e.Reason)
}

// Parse validates one IP argument and returns the address to send, in
// canonical form (Target). A zone, a zero-padded IPv4 octet and anything that
// is not publicly routable are refused.
func Parse(s string) (netip.Addr, error) {
	in := strings.TrimSpace(s)
	if strings.Contains(in, "%") {
		return netip.Addr{}, &Error{Input: s, Reason: "is a zoned address, which names an interface on this machine, not a host on the Internet"}
	}
	addr, err := netip.ParseAddr(in)
	if err != nil {
		return netip.Addr{}, &Error{Input: s, Reason: "is not an IP address (hostnames are not accepted — resolve them with doh-lookup first)"}
	}
	if c, via := Classify(addr); c != "" {
		return netip.Addr{}, refused(s, c, via)
	}
	return Target(addr), nil
}

// Target is the address that is actually looked up. Where an IPv6 form only
// spells an IPv4 host — IPv4-mapped, IPv4-compatible, NAT64 — the IPv4 host is
// what the services know, so that is sent. 6to4 and Teredo are different: the
// embedded IPv4 is the tunnel's endpoint, not the host that was seen, so the
// IPv6 address is sent as given. Classify has already judged the embedded
// address in every case.
func Target(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if !addr.Is6() || addr.IsUnspecified() || addr.IsLoopback() {
		return addr
	}
	for _, e := range embeds {
		if !e.prefix.Contains(addr) {
			continue
		}
		switch e.name {
		case "nat64", "nat64-local", "ipv4-compatible":
			return e.extract(addr)
		}
		return addr
	}
	return addr
}

func refused(input string, c Class, via string) error {
	what := string(c)
	if via != "" {
		what += " (inside " + via + ")"
	}
	return &Error{Input: input, Reason: "is a " + what + " address; ipapi.is and proxycheck.io describe only the public Internet, and an internal address is never sent to a third party"}
}

// last4 returns the IPv4 address in the low 32 bits.
func last4(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

// bytes2to5 returns the IPv4 address in bits 16–47 (6to4: 2002:AABB:CCDD::).
func bytes2to5(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
}

// teredoServer returns the Teredo server's IPv4 address, bits 32–63
// (RFC 4380 §4).
func teredoServer(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
}

// last4Inverted returns the IPv4 address Teredo stores in the low 32 bits with
// every bit flipped (RFC 4380 §4).
func last4Inverted(a netip.Addr) netip.Addr {
	b := a.As16()
	v := ^binary.BigEndian.Uint32(b[12:16])
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// ParseBatch turns raw inputs into the canonical addresses to send (Target),
// refusing the whole batch on the first input that cannot be sent — so a typo
// never half-runs a triage — and refusing more than max distinct addresses.
// Duplicates are kept in input order; the caller asks once per address.
//
// Duplicates count toward a second ceiling, ten times max inputs in all, so a
// flood of one address cannot make a call arbitrarily long.
func ParseBatch(raw []string, max int) ([]string, error) {
	if len(raw) > 10*max {
		return nil, &Error{Reason: fmt.Sprintf("%d inputs; the ceiling is %d per call, duplicates included", len(raw), 10*max)}
	}
	out := make([]string, 0, len(raw))
	distinct := map[string]bool{}
	for _, r := range raw {
		addr, err := Parse(r)
		if err != nil {
			return nil, err
		}
		s := addr.String()
		distinct[s] = true
		out = append(out, s)
	}
	if len(distinct) > max {
		return nil, &Error{Reason: fmt.Sprintf("%d distinct addresses; the ceiling is %d per call (both free tiers allow 1,000 lookups a day)", len(distinct), max)}
	}
	return out, nil
}
