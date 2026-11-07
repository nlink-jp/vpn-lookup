package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/vpn-lookup/internal/engine"
)

// renderText prints one block per address. Every name in it is third-party
// text, already cleaned of control and format characters by the clients.
func renderText(w io.Writer, rep *engine.Report) {
	for i := range rep.Results {
		r := &rep.Results[i]
		fmt.Fprintln(w, r.IP)
		v := string(r.Verdict)
		if r.SeenBy != "" {
			v += " (seen by " + r.SeenBy + ")"
		}
		if r.ProxyKind != "" {
			v += ", " + r.ProxyKind + " proxy"
		}
		fmt.Fprintf(w, "  verdict    : %s\n", v)
		if p := providerLine(r.Providers); p != "" {
			fmt.Fprintf(w, "  provider   : %s\n", p)
		}
		var extra []string
		if r.Mobile != nil && *r.Mobile {
			extra = append(extra, "mobile carrier")
		}
		if r.Crawler != "" {
			extra = append(extra, "crawler "+r.Crawler)
		}
		if len(extra) > 0 {
			fmt.Fprintf(w, "  also       : %s\n", strings.Join(extra, ", "))
		}
		fmt.Fprintf(w, "  ipapi      : %s\n", ipapiLine(r))
		fmt.Fprintf(w, "  proxycheck : %s\n", proxycheckLine(r))
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note       : %s\n", n)
		}
		if i < len(rep.Results)-1 {
			fmt.Fprintln(w)
		}
	}
}

func providerLine(p engine.Providers) string {
	var parts []string
	if p.IPAPI != "" {
		parts = append(parts, "ipapi.is: "+p.IPAPI)
	}
	if p.Proxycheck != "" {
		parts = append(parts, "proxycheck.io: "+p.Proxycheck)
	}
	return strings.Join(parts, " / ")
}

func ipapiLine(r *engine.Result) string {
	s := r.IPAPI
	switch {
	case !s.Enabled:
		return "disabled (no [ipapi] api_key configured)"
	case s.Error != "":
		return "ERROR — " + s.Error
	case s.Result == nil:
		return "no answer"
	}
	a := s.Result
	var flags []string
	for _, f := range []struct {
		on   bool
		name string
	}{
		{a.IsTor, "tor"}, {a.IsVPN, "vpn"}, {a.IsProxy, "proxy"}, {a.IsDatacenter, "datacenter"},
		{a.IsMobile, "mobile"}, {a.IsSatellite, "satellite"}, {a.IsAnycast, "anycast"}, {a.IsAbuser, "abuser"},
	} {
		if f.on {
			flags = append(flags, f.name)
		}
	}
	if len(flags) == 0 {
		flags = append(flags, "no flags")
	}
	line := strings.Join(flags, ", ")
	if a.Egress != nil {
		line += "; egress " + a.Egress.Type
		if a.Egress.Provider != "" {
			line += " (" + a.Egress.Provider + ")"
		}
	}
	if a.VPN != nil {
		line += "; vpn " + a.VPN.Service
		if a.VPN.LastSeen != "" {
			line += ", last seen " + a.VPN.LastSeen
		}
	}
	if a.Datacenter != "" {
		line += "; hosting " + a.Datacenter
	}
	if a.CompanyType != "" {
		line += "; company type " + a.CompanyType
	}
	if s.FromCache {
		line += " (cached)"
	}
	return line
}

func proxycheckLine(r *engine.Result) string {
	s := r.Proxycheck
	switch {
	case !s.Enabled:
		return "disabled (no [proxycheck] api_key configured)"
	case s.Error != "":
		return "ERROR — " + s.Error
	case s.Result == nil:
		return "no answer"
	}
	p := s.Result
	var flags []string
	for _, f := range []struct {
		on   bool
		name string
	}{
		{p.Tor, "tor"}, {p.VPN, "vpn"}, {p.Proxy, "proxy"}, {p.Hosting, "hosting"},
		{p.Compromised, "compromised"}, {p.Scraper, "scraper"},
	} {
		if f.on {
			flags = append(flags, f.name)
		}
	}
	if len(flags) == 0 {
		flags = append(flags, "no detections")
	}
	line := strings.Join(flags, ", ")
	if p.Risk != nil {
		line += fmt.Sprintf("; risk %d", *p.Risk)
	}
	if p.Confidence != nil {
		line += fmt.Sprintf(", confidence %d", *p.Confidence)
	}
	if p.Operator != "" {
		line += "; operator " + p.Operator
		if len(p.Services) > 0 {
			line += " [" + strings.Join(p.Services, ", ") + "]"
		}
	}
	if p.NetworkType != "" {
		line += "; network " + p.NetworkType
	}
	if s.FromCache {
		line += " (cached)"
	}
	return line
}
