package verdict

import (
	"testing"

	"github.com/nlink-jp/vpn-lookup/internal/ipapi"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
)

func ia(r ipapi.Result) Source[ipapi.Result] {
	return Source[ipapi.Result]{Enabled: true, Result: &r}
}
func pc(r proxycheck.Result) Source[proxycheck.Result] {
	return Source[proxycheck.Result]{Enabled: true, Result: &r}
}

var (
	iaOff    = Source[ipapi.Result]{}
	pcOff    = Source[proxycheck.Result]{}
	iaFailed = Source[ipapi.Result]{Enabled: true, Failed: true}
	pcFailed = Source[proxycheck.Result]{Enabled: true, Failed: true}
)

func egress(t string) *ipapi.Egress { return &ipapi.Egress{Type: t, Provider: "Example"} }

// The nine phase 0 samples and the phase 1 examples, as the sources answered
// them (shapes only; no captured data).
func TestSynthesizeMeasuredCases(t *testing.T) {
	cases := []struct {
		name   string
		in     Inputs
		want   Verdict
		seenBy string
	}{
		{"tor exit", Inputs{ia(ipapi.Result{IsTor: true, IsProxy: true, IsAbuser: true}), pc(proxycheck.Result{Tor: true, Anonymous: true})}, Tor, SeenByBoth},
		{"commercial vpn", Inputs{ia(ipapi.Result{IsVPN: true, IsDatacenter: true}), pc(proxycheck.Result{VPN: true, Hosting: true})}, VPN, SeenByBoth},
		{"cloud", Inputs{ia(ipapi.Result{IsDatacenter: true}), pc(proxycheck.Result{Hosting: true})}, Hosting, SeenByBoth},
		{"home line", Inputs{ia(ipapi.Result{}), pc(proxycheck.Result{})}, None, ""},
		{"icloud relay", Inputs{ia(ipapi.Result{IsDatacenter: true, Egress: egress("private_relay")}), pc(proxycheck.Result{VPN: true, Hosting: true})}, Relay, SeenByIPAPI},
		{"zscaler", Inputs{ia(ipapi.Result{Egress: egress("secure_web_gateway")}), pc(proxycheck.Result{VPN: true, Hosting: true})}, Gateway, SeenByIPAPI},
		{"proofpoint", Inputs{ia(ipapi.Result{Egress: egress("email_gateway")}), pc(proxycheck.Result{})}, MailGateway, SeenByIPAPI},
		{"opendns", Inputs{ia(ipapi.Result{IsAnycast: true, Egress: egress("dns_resolver")}), pc(proxycheck.Result{})}, DNSResolver, SeenByIPAPI},
		{"starlink", Inputs{ia(ipapi.Result{IsSatellite: true, Egress: egress("satellite")}), pc(proxycheck.Result{NetworkType: "Wireless"})}, Satellite, SeenByIPAPI},
		{"vpn seen by one source", Inputs{ia(ipapi.Result{IsDatacenter: true}), pc(proxycheck.Result{VPN: true, Hosting: true})}, VPN, SeenByProxycheck},
		{"mobile", Inputs{ia(ipapi.Result{IsMobile: true}), pc(proxycheck.Result{})}, None, ""},
		{"googlebot", Inputs{ia(ipapi.Result{IsDatacenter: true, Crawler: "GoogleBot"}), pc(proxycheck.Result{})}, Hosting, SeenByIPAPI},
	}
	for _, tc := range cases {
		o := Synthesize(tc.in)
		if o.Verdict != tc.want || o.SeenBy != tc.seenBy {
			t.Errorf("%s: got (%s, %q), want (%s, %q)", tc.name, o.Verdict, o.SeenBy, tc.want, tc.seenBy)
		}
	}
}

// A failure never reads as "no intermediary".
func TestFailureIsUnknownNeverNone(t *testing.T) {
	for name, in := range map[string]Inputs{
		"proxycheck failed":  {ia(ipapi.Result{}), pcFailed},
		"ipapi failed":       {iaFailed, pc(proxycheck.Result{})},
		"both failed":        {iaFailed, pcFailed},
		"only source failed": {iaOff, pcFailed},
	} {
		if o := Synthesize(in); o.Verdict != Unknown || o.SeenBy != "" {
			t.Errorf("%s: got %s, want unknown", name, o.Verdict)
		}
	}
	// A positive answer from the surviving source still stands.
	if o := Synthesize(Inputs{iaFailed, pc(proxycheck.Result{VPN: true})}); o.Verdict != VPN || o.SeenBy != SeenByProxycheck {
		t.Errorf("a failure must not hide what the other source reported: %+v", o)
	}
}

// A source that is not enabled is not a failure: with one key, a clean answer
// is none.
func TestDisabledSourceIsNotAFailure(t *testing.T) {
	if o := Synthesize(Inputs{iaOff, pc(proxycheck.Result{})}); o.Verdict != None {
		t.Fatalf("got %s", o.Verdict)
	}
}

func TestWithoutIPAPITheIdentificationIsUnavailable(t *testing.T) {
	o := Synthesize(Inputs{iaOff, pc(proxycheck.Result{VPN: true, Hosting: true})})
	if o.Verdict != VPN || o.Mobile != nil || len(o.Notes) != 1 || o.Notes[0] != NoIdentification {
		t.Fatalf("got %+v; without ipapi.is, mobile is unknown (nil) and the note says what cannot be told apart", o)
	}
	o = Synthesize(Inputs{iaFailed, pc(proxycheck.Result{})})
	if len(o.Notes) == 0 || o.Notes[0] != NoIdentification {
		t.Fatalf("a failed ipapi.is gets the note too: %+v", o)
	}
}

func TestUnknownEgressTypeFallsThroughWithANote(t *testing.T) {
	o := Synthesize(Inputs{ia(ipapi.Result{IsDatacenter: true, Egress: egress("quantum_tunnel")}), pc(proxycheck.Result{})})
	if o.Verdict != Hosting || len(o.Notes) != 1 || o.Notes[0] != UnknownEgress {
		t.Fatalf("got %+v", o)
	}
}

func TestSatelliteFlagWithoutEgress(t *testing.T) {
	if o := Synthesize(Inputs{ia(ipapi.Result{IsSatellite: true}), pcOff}); o.Verdict != Satellite {
		t.Fatalf("got %s", o.Verdict)
	}
}

func TestMobileAndCrawlerAreCarried(t *testing.T) {
	o := Synthesize(Inputs{ia(ipapi.Result{IsMobile: true, Crawler: "ExampleBot"}), pcOff})
	if o.Mobile == nil || !*o.Mobile || o.Crawler != "ExampleBot" {
		t.Fatalf("got %+v", o)
	}
	o = Synthesize(Inputs{ia(ipapi.Result{}), pcOff})
	if o.Mobile == nil || *o.Mobile {
		t.Fatalf("ipapi.is answered no: Mobile must be false, not nil: %+v", o)
	}
}

func TestProxyKind(t *testing.T) {
	for name, tc := range map[string]struct {
		in   Inputs
		want string
	}{
		"residential operator": {Inputs{iaOff, pc(proxycheck.Result{Proxy: true, Services: []string{"residential_proxies"}})}, ProxyResidential},
		"wireless operator":    {Inputs{iaOff, pc(proxycheck.Result{Proxy: true, Services: []string{"wireless_proxies"}})}, ProxyResidential},
		"public proxy list":    {Inputs{ia(ipapi.Result{IsProxy: true}), pc(proxycheck.Result{})}, ProxyOpen},
		"no telling":           {Inputs{iaOff, pc(proxycheck.Result{Proxy: true})}, ProxyUnspecified},
	} {
		o := Synthesize(tc.in)
		if o.Verdict != Proxy || o.ProxyKind != tc.want {
			t.Errorf("%s: got (%s, %q), want (proxy, %q)", name, o.Verdict, o.ProxyKind, tc.want)
		}
	}
	if o := Synthesize(Inputs{ia(ipapi.Result{IsVPN: true}), pcOff}); o.ProxyKind != "" {
		t.Errorf("ProxyKind is set only for proxy: %+v", o)
	}
}

func TestEveryVerdictIsReachable(t *testing.T) {
	reached := map[Verdict]bool{}
	for _, in := range []Inputs{
		{ia(ipapi.Result{IsTor: true}), pcOff}, {ia(ipapi.Result{IsVPN: true}), pcOff},
		{ia(ipapi.Result{Egress: egress("private_relay")}), pcOff}, {ia(ipapi.Result{Egress: egress("secure_web_gateway")}), pcOff},
		{ia(ipapi.Result{Egress: egress("email_gateway")}), pcOff}, {ia(ipapi.Result{Egress: egress("dns_resolver")}), pcOff},
		{ia(ipapi.Result{Egress: egress("satellite")}), pcOff}, {ia(ipapi.Result{IsProxy: true}), pcOff},
		{ia(ipapi.Result{IsDatacenter: true}), pcOff}, {ia(ipapi.Result{}), pcOff}, {iaFailed, pcOff},
	} {
		reached[Synthesize(in).Verdict] = true
	}
	for _, v := range All {
		if !reached[v] {
			t.Errorf("verdict %s is never produced", v)
		}
	}
}

// A failed source never reads as none (rule 3), and a verdict the surviving
// source gave alone says so: the failed one might have reported more.
func TestFailedSourceIsNamedNextToAVerdict(t *testing.T) {
	o := Synthesize(Inputs{ia(ipapi.Result{IsDatacenter: true}), pcFailed})
	if o.Verdict != Hosting || !hasNote(o, FailedNote("proxycheck.io")) {
		t.Fatalf("got %+v", o)
	}
	o = Synthesize(Inputs{iaFailed, pc(proxycheck.Result{Hosting: true})})
	if !hasNote(o, FailedNote("ipapi.is")) || !hasNote(o, NoIdentification) {
		t.Fatalf("got %+v", o)
	}
	if o := Synthesize(Inputs{ia(ipapi.Result{}), pcFailed}); o.Verdict != Unknown || hasNote(o, FailedNote("proxycheck.io")) {
		t.Fatalf("unknown already says it; got %+v", o)
	}
}

// The managed-service identification takes precedence, but a tor / vpn /
// proxy report is named, not dropped.
func TestRuleOneNamesWhatItOverrode(t *testing.T) {
	o := Synthesize(Inputs{ia(ipapi.Result{IsSatellite: true}), pc(proxycheck.Result{VPN: true})})
	if o.Verdict != Satellite || !hasNote(o, AlsoReportedNote("proxycheck.io", VPN)) {
		t.Fatalf("got %+v", o)
	}
	o = Synthesize(Inputs{ia(ipapi.Result{IsTor: true, Egress: egress("dns_resolver")}), pc(proxycheck.Result{})})
	if o.Verdict != DNSResolver || !hasNote(o, AlsoReportedNote("ipapi.is", Tor)) {
		t.Fatalf("got %+v", o)
	}
	o = Synthesize(Inputs{ia(ipapi.Result{Egress: egress("email_gateway")}), pc(proxycheck.Result{Hosting: true})})
	if len(o.Notes) != 0 {
		t.Fatalf("hosting alongside a managed service is not worth a note: %+v", o)
	}
}

func hasNote(o Outcome, n string) bool {
	for _, x := range o.Notes {
		if x == n {
			return true
		}
	}
	return false
}
