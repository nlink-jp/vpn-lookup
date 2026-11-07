package ipaddr

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// One row per table row and per embedding: a class is a table row plus a test
// row. TestEveryRowIsExercised holds the two lists to each other.
var refusedCases = []struct {
	addr  string
	class Class
	via   string
}{
	{"0.1.2.3", ClassReserved, ""},
	{"10.20.30.40", ClassPrivate, ""},
	{"100.64.0.1", ClassShared, ""},
	{"127.0.0.1", ClassLoopback, ""},
	{"169.254.169.254", ClassLinkLocal, ""},
	{"172.16.5.4", ClassPrivate, ""},
	{"192.0.0.8", ClassReserved, ""},
	{"192.0.2.1", ClassDocumentation, ""},
	{"192.168.1.1", ClassPrivate, ""},
	{"198.18.0.1", ClassReserved, ""},
	{"198.51.100.7", ClassDocumentation, ""},
	{"203.0.113.9", ClassDocumentation, ""},
	{"224.0.0.251", ClassMulticast, ""},
	{"240.0.0.1", ClassReserved, ""},
	{"100::1", ClassReserved, ""},
	{"2001:2::1", ClassReserved, ""},
	{"2001:db8::1", ClassDocumentation, ""},
	{"3fff::1", ClassDocumentation, ""},
	{"fd00::1", ClassUniqueLocal, ""},
	{"fe80::1", ClassLinkLocal, ""},
	{"fec0::1", ClassSiteLocal, ""},
	{"ff02::1", ClassMulticast, ""},
	{"0.0.0.0", ClassUnspecified, ""},
	{"255.255.255.255", ClassBroadcast, ""},
	{"::", ClassUnspecified, ""},
	{"::1", ClassLoopback, ""},
	{"64:ff9b::a00:1", ClassPrivate, "nat64"},
	{"64:ff9b:1::c0a8:101", ClassPrivate, "nat64-local"},
	{"2002:c0a8:0101::1", ClassPrivate, "6to4"},
	{"2001:0:4136:e378:8000:63bf:f5ff:fffe", ClassPrivate, "teredo"}, // client 10.0.0.1, bits inverted
	{"::a00:1", ClassPrivate, "ipv4-compatible"},
}

func TestRefusedClasses(t *testing.T) {
	for _, tc := range refusedCases {
		c, via := Classify(netip.MustParseAddr(tc.addr))
		if c != tc.class || via != tc.via {
			t.Errorf("%s: Classify = (%q, %q), want (%q, %q)", tc.addr, c, via, tc.class, tc.via)
		}
	}
}

func TestEveryRowIsExercised(t *testing.T) {
	for _, r := range table {
		hit := false
		for _, tc := range refusedCases {
			if tc.via == "" && r.prefix.Contains(netip.MustParseAddr(tc.addr)) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("table row %s has no test case", r.prefix)
		}
	}
	for _, e := range embeds {
		hit := false
		for _, tc := range refusedCases {
			hit = hit || tc.via == e.name
		}
		if !hit {
			t.Errorf("embedding %s has no test case", e.name)
		}
	}
}

func TestPublicAddressesPass(t *testing.T) {
	for in, want := range map[string]string{
		"8.8.8.8":                     "8.8.8.8",
		" 1.1.1.1 ":                   "1.1.1.1",
		"::ffff:9.9.9.9":              "9.9.9.9", // unmapped
		"2001:4860:4860::8888":        "2001:4860:4860::8888",
		"2001:4860:4860:0:0:0:0:8888": "2001:4860:4860::8888", // canonical form is sent
		"2002:0808:0808::1":           "2002:808:808::1",      // 6to4: the IPv6 host is sent, not the tunnel endpoint
		"64:ff9b::808:808":            "8.8.8.8",              // NAT64 spells the IPv4 host, which is sent
		"::808:808":                   "8.8.8.8",              // IPv4-compatible likewise
		"2a00:1450:4001:80b::200e":    "2a00:1450:4001:80b::200e",
		"9.9.9.9":                     "9.9.9.9",
		"191.255.255.255":             "191.255.255.255",
		"192.0.3.0":                   "192.0.3.0",
		"198.20.0.1":                  "198.20.0.1",
		"223.255.255.255":             "223.255.255.255",
	} {
		got, err := Parse(in)
		if err != nil {
			t.Errorf("%q: refused: %v", in, err)
			continue
		}
		if got.String() != want {
			t.Errorf("%q: canonical form %s, want %s", in, got, want)
		}
	}
}

func TestParseRefusesWhatCannotBeSent(t *testing.T) {
	for in, want := range map[string]string{
		"008.008.008.008":   "not an IP address",
		"8.8.8":             "not an IP address",
		"example.com":       "doh-lookup",
		"fe80::1%en0":       "zoned",
		"":                  "not an IP address",
		"10.0.0.1":          "private",
		"::ffff:10.0.0.1":   "private",
		"2002:0a00:0001::1": "inside 6to4",
	} {
		_, err := Parse(in)
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("%q: error %v is not an *Error", in, err)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %q does not mention %q", in, err, want)
		}
	}
}

func TestIPv6OutsideGlobalUnicastAndTeredoServers(t *testing.T) {
	for _, a := range []string{
		"::ffff:0:10.0.0.1", // IPv4-translated
		"4000::1", "5f00::1", "::1:0:0:1", "100:0:0:1::1",
		"2001:0:a00:1::f7f7:f7f7", // Teredo server 10.0.0.1, client 8.8.8.8
	} {
		if _, err := Parse(a); err == nil {
			t.Errorf("%s: accepted", a)
		}
	}
	if _, err := Parse("2001:0:808:808::f7f7:f7f7"); err != nil {
		t.Errorf("a Teredo address with public server and client was refused: %v", err)
	}
}

// Teredo carries a public client, but the IPv6 address is what was seen; the
// embedded IPv4 is not the host to look up.
func TestTargetKeepsTunnelledIPv6(t *testing.T) {
	got, err := Parse("2001:0:808:808::f7f7:f7f7")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Is6() {
		t.Fatalf("Teredo address was replaced by %s; the IPv6 host must be sent", got)
	}
}

func TestParseBatch(t *testing.T) {
	got, err := ParseBatch([]string{"8.8.8.8", "::ffff:8.8.8.8", "2001:4860:4860:0:0:0:0:8888"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "8.8.8.8,8.8.8.8,2001:4860:4860::8888" {
		t.Fatalf("got %v; canonical, duplicates kept, counted once", got)
	}
	if _, err := ParseBatch([]string{"8.8.8.8", "10.0.0.1"}, 10); err == nil || !strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("one bad input must refuse the batch, naming it: %v", err)
	}
	if _, err := ParseBatch([]string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}, 2); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("over the ceiling must be refused: %v", err)
	}
}
