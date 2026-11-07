// Package verdict turns the two sources' answers about one address into one
// verdict (RFP §2, decided from the phase 0 measurement and the design
// review). Pure functions: no I/O, no clock.
package verdict

import (
	"github.com/nlink-jp/vpn-lookup/internal/ipapi"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
)

// Verdict is the one answer about an address.
type Verdict string

const (
	Tor         Verdict = "tor"
	VPN         Verdict = "vpn"
	Relay       Verdict = "relay"
	Gateway     Verdict = "gateway"
	MailGateway Verdict = "mail_gateway"
	DNSResolver Verdict = "dns_resolver"
	Satellite   Verdict = "satellite"
	Proxy       Verdict = "proxy"
	Hosting     Verdict = "hosting"
	None        Verdict = "none"
	Unknown     Verdict = "unknown"
)

// All lists every verdict, in the order the manual documents them.
var All = []Verdict{Tor, VPN, Relay, Gateway, MailGateway, DNSResolver, Satellite, Proxy, Hosting, None, Unknown}

// SeenBy values.
const (
	SeenByBoth       = "both"
	SeenByIPAPI      = "ipapi"
	SeenByProxycheck = "proxycheck"
)

// ProxyKind values, set only when the verdict is proxy.
const (
	ProxyOpen        = "open"
	ProxyResidential = "residential"
	ProxyUnspecified = "unspecified"
)

// egressVerdicts maps ipapi.is egress_service types to verdicts (rule 1). The
// managed service is the most specific identification either source makes.
var egressVerdicts = map[string]Verdict{
	"private_relay":      Relay,
	"secure_web_gateway": Gateway,
	"email_gateway":      MailGateway,
	"dns_resolver":       DNSResolver,
	"satellite":          Satellite,
}

// rank orders the classes of rule 2, strongest first.
var rank = []Verdict{Tor, VPN, Proxy, Hosting}

// Source is one source's state for one address.
type Source[R any] struct {
	Enabled bool // a key is configured
	Result  *R   // nil when not enabled or failed
	Failed  bool // enabled, but no answer for this address
}

// Inputs are both sources' states.
type Inputs struct {
	IPAPI      Source[ipapi.Result]
	Proxycheck Source[proxycheck.Result]
}

// Outcome is the synthesized answer.
type Outcome struct {
	Verdict   Verdict
	SeenBy    string // "" for none / unknown
	ProxyKind string // set only for proxy
	// Mobile is ipapi.is's mobile-carrier flag; nil when ipapi.is did not answer.
	Mobile *bool
	// Crawler is the bot's name from ipapi.is; "" when none or unknown.
	Crawler string
	// Notes says what the reader must know to read the verdict right.
	Notes []string
}

// UnknownEgress is the note for an egress_service type this build does not map.
const UnknownEgress = "ipapi.is names a managed egress service of a type this build does not know; it is shown as evidence and did not decide the verdict"

// NoIdentification is the note when ipapi.is did not answer.
const NoIdentification = "ipapi.is did not answer, so relays, gateways, email gateways, DNS resolvers and satellite ISPs cannot be told apart (proxycheck.io reads iCloud Private Relay as vpn and Zscaler as hosting)"

// FailedNote is the note when a source failed for the address but a verdict
// was still given: the failed source might have reported a stronger class
// (measured: proxycheck.io alone named a VPN that ipapi.is called a data
// centre).
func FailedNote(source string) string {
	return source + " failed for this address, so this verdict rests on the other source alone; " + source + " might have reported a stronger class"
}

// AlsoReportedNote is the note when rule 1 decided but a source also reported
// tor, vpn or proxy: the managed-service identification takes precedence, and
// the stronger-sounding report is named rather than dropped.
func AlsoReportedNote(source string, v Verdict) string {
	return source + " also reports " + string(v) + "; the managed service ipapi.is names decided the verdict"
}

// Synthesize applies the rule:
//
//  1. an ipapi.is egress_service of a known type decides the verdict
//     (an is_satellite flag without one counts as satellite);
//  2. otherwise the strongest class either source reports:
//     tor > vpn > proxy > hosting;
//  3. nothing reported: none when every enabled source answered, unknown when
//     one failed — a failure never reads as "no intermediary".
func Synthesize(in Inputs) Outcome {
	o := synthesize(in)
	if o.Verdict != Unknown {
		if in.IPAPI.Failed {
			o.Notes = append(o.Notes, FailedNote("ipapi.is"))
		}
		if in.Proxycheck.Failed {
			o.Notes = append(o.Notes, FailedNote("proxycheck.io"))
		}
	}
	return o
}

func synthesize(in Inputs) Outcome {
	var o Outcome
	ia, pc := in.IPAPI.Result, in.Proxycheck.Result

	if ia != nil {
		m := ia.IsMobile
		o.Mobile = &m
		o.Crawler = ia.Crawler
	} else if in.IPAPI.Enabled || in.Proxycheck.Enabled {
		o.Notes = append(o.Notes, NoIdentification)
	}

	// Rule 1.
	if ia != nil {
		decided := Verdict("")
		if ia.Egress != nil {
			if v, ok := egressVerdicts[ia.Egress.Type]; ok {
				decided = v
			} else {
				o.Notes = append(o.Notes, UnknownEgress)
			}
		}
		if decided == "" && ia.IsSatellite {
			decided = Satellite
		}
		if decided != "" {
			o.Verdict, o.SeenBy = decided, SeenByIPAPI
			o.Notes = append(o.Notes, alsoReported(ia, pc)...)
			return o
		}
	}

	// Rule 2.
	iaClasses := map[Verdict]bool{}
	if ia != nil {
		iaClasses[Tor], iaClasses[VPN], iaClasses[Proxy], iaClasses[Hosting] = ia.IsTor, ia.IsVPN, ia.IsProxy, ia.IsDatacenter
	}
	pcClasses := map[Verdict]bool{}
	if pc != nil {
		pcClasses[Tor], pcClasses[VPN], pcClasses[Proxy], pcClasses[Hosting] = pc.Tor, pc.VPN, pc.Proxy, pc.Hosting
	}
	for _, v := range rank {
		a, p := iaClasses[v], pcClasses[v]
		if !a && !p {
			continue
		}
		o.Verdict = v
		switch {
		case a && p:
			o.SeenBy = SeenByBoth
		case a:
			o.SeenBy = SeenByIPAPI
		default:
			o.SeenBy = SeenByProxycheck
		}
		if v == Proxy {
			o.ProxyKind = proxyKind(ia, pc)
		}
		return o
	}

	// Rule 3.
	if in.IPAPI.Failed || in.Proxycheck.Failed {
		o.Verdict = Unknown
	} else {
		o.Verdict = None
	}
	return o
}

// alsoReported names the strongest of tor / vpn / proxy each source reported,
// for a verdict rule 1 decided.
func alsoReported(ia *ipapi.Result, pc *proxycheck.Result) []string {
	var notes []string
	pick := func(tor, vpn, proxy bool) Verdict {
		switch {
		case tor:
			return Tor
		case vpn:
			return VPN
		case proxy:
			return Proxy
		}
		return ""
	}
	if v := pick(ia.IsTor, ia.IsVPN, ia.IsProxy); v != "" {
		notes = append(notes, AlsoReportedNote("ipapi.is", v))
	}
	if pc != nil {
		if v := pick(pc.Tor, pc.VPN, pc.Proxy); v != "" {
			notes = append(notes, AlsoReportedNote("proxycheck.io", v))
		}
	}
	return notes
}

// proxyKind tells an open proxy from a residential one, as far as the sources
// say. proxycheck.io names the operator's services (residential_proxies,
// wireless_proxies); ipapi.is's is_proxy comes from public open-proxy lists.
func proxyKind(ia *ipapi.Result, pc *proxycheck.Result) string {
	if pc != nil {
		for _, s := range pc.Services {
			if s == "residential_proxies" || s == "wireless_proxies" {
				return ProxyResidential
			}
		}
	}
	if ia != nil && ia.IsProxy {
		return ProxyOpen
	}
	return ProxyUnspecified
}
