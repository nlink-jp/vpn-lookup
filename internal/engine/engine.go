// Package engine is the shared core between the CLI and the MCP server: per
// address, each enabled source is answered from its own cache entry or asked
// in one request for all its misses, and the verdict is synthesized from the
// two answers. The engine is the only clock reader; the clients are injected.
//
// Answers are cached per source and the verdict is recomputed every time, so
// adding a key later, or one source failing, never serves a stale combined
// result and never spends the healthy source's quota again.
package engine

import (
	"encoding/json"
	"time"

	"github.com/nlink-jp/vpn-lookup/internal/cache"
	"github.com/nlink-jp/vpn-lookup/internal/ipapi"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
	"github.com/nlink-jp/vpn-lookup/internal/verdict"
)

// IPAPIClient and ProxycheckClient are the injected source surfaces.
type IPAPIClient interface {
	Lookup(ips []string) (map[string]ipapi.Entry, error)
}

type ProxycheckClient interface {
	Lookup(ips []string) (*proxycheck.Answer, error)
}

// proxycheck.io's caching guidance (measured from its documentation,
// 2026-11-07): clean results 10 minutes to 1 hour, anonymous results 1 to 15
// minutes or until delist_datetime.
const (
	ProxycheckCleanTTL     = time.Hour
	ProxycheckAnonymousTTL = 15 * time.Minute
)

// Engine answers lookups. A nil client means that source has no key.
type Engine struct {
	IPAPI      IPAPIClient
	Proxycheck ProxycheckClient
	Cache      *cache.Store // nil = caching off
	IPAPITTL   time.Duration
	Now        func() time.Time
}

// SourceView is one source's part of a result. Result is null when the source
// is not enabled or failed for this address.
type SourceView[R any] struct {
	Enabled   bool   `json:"enabled"`
	Result    *R     `json:"result"`
	Error     string `json:"error,omitempty"`
	FromCache bool   `json:"from_cache,omitempty"`
}

// Providers names whose infrastructure each source says the address is.
type Providers struct {
	IPAPI      string `json:"ipapi,omitempty"`
	Proxycheck string `json:"proxycheck,omitempty"`
}

// Result is the answer for one address.
type Result struct {
	IP         string                        `json:"ip"`
	Verdict    verdict.Verdict               `json:"verdict"`
	SeenBy     string                        `json:"seen_by,omitempty"`
	ProxyKind  string                        `json:"proxy_kind,omitempty"`
	Mobile     *bool                         `json:"mobile"`
	Crawler    string                        `json:"crawler,omitempty"`
	Providers  Providers                     `json:"providers"`
	IPAPI      SourceView[ipapi.Result]      `json:"ipapi"`
	Proxycheck SourceView[proxycheck.Result] `json:"proxycheck"`
	Notes      []string                      `json:"notes,omitempty"`
	Degraded   bool                          `json:"degraded,omitempty"`
}

// SourceErrors lists this result's per-source failures.
func (r *Result) SourceErrors() []string {
	var errs []string
	if r.IPAPI.Error != "" {
		errs = append(errs, r.IPAPI.Error)
	}
	if r.Proxycheck.Error != "" {
		errs = append(errs, r.Proxycheck.Error)
	}
	return errs
}

// Report is the answer for a batch: one result per input, in input order.
type Report struct {
	Results  []Result `json:"results"`
	Warnings []string `json:"warnings,omitempty"`
	Degraded int      `json:"degraded_count"`
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Lookup answers for addresses already validated and in canonical form (see
// ipaddr.Parse). Duplicates are answered once and reported per input.
func (e *Engine) Lookup(ips []string, noCache bool) *Report {
	uniq := dedupe(ips)
	rep := &Report{}

	iaViews := map[string]SourceView[ipapi.Result]{}
	pcViews := map[string]SourceView[proxycheck.Result]{}
	if e.IPAPI != nil {
		iaViews = e.lookupIPAPI(uniq, noCache)
	}
	if e.Proxycheck != nil {
		var warn string
		pcViews, warn = e.lookupProxycheck(uniq, noCache)
		if warn != "" {
			rep.Warnings = append(rep.Warnings, "proxycheck.io: "+warn)
		}
	}

	for _, ip := range ips {
		r := Result{IP: ip}
		r.IPAPI, r.Proxycheck = iaViews[ip], pcViews[ip]
		r.IPAPI.Enabled, r.Proxycheck.Enabled = e.IPAPI != nil, e.Proxycheck != nil
		out := verdict.Synthesize(verdict.Inputs{
			IPAPI:      verdict.Source[ipapi.Result]{Enabled: r.IPAPI.Enabled, Result: r.IPAPI.Result, Failed: r.IPAPI.Enabled && r.IPAPI.Result == nil},
			Proxycheck: verdict.Source[proxycheck.Result]{Enabled: r.Proxycheck.Enabled, Result: r.Proxycheck.Result, Failed: r.Proxycheck.Enabled && r.Proxycheck.Result == nil},
		})
		r.Verdict, r.SeenBy, r.ProxyKind, r.Mobile, r.Crawler, r.Notes = out.Verdict, out.SeenBy, out.ProxyKind, out.Mobile, out.Crawler, out.Notes
		r.Providers = providers(r.IPAPI.Result, r.Proxycheck.Result)
		r.Degraded = len(r.SourceErrors()) > 0
		if r.Degraded {
			rep.Degraded++
		}
		rep.Results = append(rep.Results, r)
	}
	return rep
}

func (e *Engine) lookupIPAPI(ips []string, noCache bool) map[string]SourceView[ipapi.Result] {
	views := map[string]SourceView[ipapi.Result]{}
	var miss []string
	for _, ip := range ips {
		if !noCache && e.Cache != nil {
			if raw, ok := e.Cache.Get(cache.Key("ipapi", ip), e.now(), e.IPAPITTL); ok {
				var r ipapi.Result
				if json.Unmarshal(raw, &r) == nil {
					views[ip] = SourceView[ipapi.Result]{Result: &r, FromCache: true}
					continue
				}
			}
		}
		miss = append(miss, ip)
	}
	for len(miss) > 0 {
		batch := miss
		if len(batch) > ipapi.MaxBulk {
			batch = miss[:ipapi.MaxBulk]
		}
		miss = miss[len(batch):]
		entries, err := e.IPAPI.Lookup(batch)
		for _, ip := range batch {
			switch {
			case err != nil:
				views[ip] = SourceView[ipapi.Result]{Error: err.Error()}
			case entries[ip].Result == nil:
				msg := entries[ip].Err
				if msg == "" {
					msg = "ipapi.is did not answer for this address"
				}
				views[ip] = SourceView[ipapi.Result]{Error: msg}
			default:
				r := entries[ip].Result
				views[ip] = SourceView[ipapi.Result]{Result: r}
				e.put(cache.Key("ipapi", ip), r)
			}
		}
	}
	return views
}

func (e *Engine) lookupProxycheck(ips []string, noCache bool) (map[string]SourceView[proxycheck.Result], string) {
	views := map[string]SourceView[proxycheck.Result]{}
	var miss []string
	for _, ip := range ips {
		if !noCache && e.Cache != nil {
			if raw, at, ok := e.Cache.Load(cache.Key("proxycheck", ip)); ok {
				var r proxycheck.Result
				if json.Unmarshal(raw, &r) == nil && e.now().Sub(at) <= proxycheckTTL(&r, at) {
					views[ip] = SourceView[proxycheck.Result]{Result: &r, FromCache: true}
					continue
				}
			}
		}
		miss = append(miss, ip)
	}
	if len(miss) == 0 {
		return views, ""
	}
	ans, err := e.Proxycheck.Lookup(miss)
	warn := ""
	if ans != nil {
		warn = ans.Warning
	}
	for _, ip := range miss {
		switch {
		case err != nil:
			views[ip] = SourceView[proxycheck.Result]{Error: err.Error()}
		case ans.Entries[ip].Result == nil:
			msg := ans.Entries[ip].Err
			if msg == "" {
				msg = "proxycheck.io did not answer for this address"
			}
			views[ip] = SourceView[proxycheck.Result]{Error: msg}
		default:
			r := ans.Entries[ip].Result
			views[ip] = SourceView[proxycheck.Result]{Result: r}
			e.put(cache.Key("proxycheck", ip), r)
		}
	}
	return views, warn
}

// proxycheckTTL is how long a proxycheck.io answer stays fresh, from its
// content: a clean result an hour; an anonymous one until its delist_datetime,
// at most 15 minutes.
func proxycheckTTL(r *proxycheck.Result, fetched time.Time) time.Duration {
	if !r.Anonymous && !r.VPN && !r.Proxy && !r.Tor {
		return ProxycheckCleanTTL
	}
	ttl := ProxycheckAnonymousTTL
	if t, err := time.Parse(time.RFC3339, r.DelistDateTime); err == nil {
		if d := t.Sub(fetched); d < ttl {
			ttl = d
		}
	}
	return ttl
}

func (e *Engine) put(key string, v any) {
	if e.Cache == nil {
		return
	}
	if raw, err := json.Marshal(v); err == nil {
		_ = e.Cache.Put(key, raw, e.now()) // a cache write failure never fails a lookup
	}
}

// providers names the provider each source attributes the address to: for
// ipapi.is the managed service, else the VPN service, else the hosting
// provider; for proxycheck.io the operator, else the network's provider when
// it reports hosting.
func providers(ia *ipapi.Result, pc *proxycheck.Result) Providers {
	var p Providers
	if ia != nil {
		switch {
		case ia.Egress != nil && ia.Egress.Provider != "":
			p.IPAPI = ia.Egress.Provider
		case ia.VPN != nil:
			p.IPAPI = ia.VPN.Service
		case ia.Datacenter != "":
			p.IPAPI = ia.Datacenter
		}
	}
	if pc != nil {
		switch {
		case pc.Operator != "":
			p.Proxycheck = pc.Operator
		case pc.Hosting:
			p.Proxycheck = pc.Provider
		}
	}
	return p
}

func dedupe(ips []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}
