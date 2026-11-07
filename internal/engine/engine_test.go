package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/vpn-lookup/internal/cache"
	"github.com/nlink-jp/vpn-lookup/internal/ipapi"
	"github.com/nlink-jp/vpn-lookup/internal/proxycheck"
	"github.com/nlink-jp/vpn-lookup/internal/verdict"
)

type fakeIPAPI struct {
	res   map[string]ipapi.Entry
	err   error
	calls [][]string
}

func (f *fakeIPAPI) Lookup(ips []string) (map[string]ipapi.Entry, error) {
	f.calls = append(f.calls, append([]string(nil), ips...))
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]ipapi.Entry{}
	for _, ip := range ips {
		if e, ok := f.res[ip]; ok {
			out[ip] = e
		} else {
			out[ip] = ipapi.Entry{Err: "ipapi.is did not answer for this address"}
		}
	}
	return out, nil
}

type fakePC struct {
	res   map[string]proxycheck.Entry
	warn  string
	err   error
	calls [][]string
}

func (f *fakePC) Lookup(ips []string) (*proxycheck.Answer, error) {
	f.calls = append(f.calls, append([]string(nil), ips...))
	if f.err != nil {
		return nil, f.err
	}
	a := &proxycheck.Answer{Entries: map[string]proxycheck.Entry{}, Warning: f.warn}
	for _, ip := range ips {
		a.Entries[ip] = f.res[ip]
	}
	return a, nil
}

const (
	vpnIP   = "192.0.2.10"
	cleanIP = "198.51.100.20"
)

func newFakes() (*fakeIPAPI, *fakePC) {
	return &fakeIPAPI{res: map[string]ipapi.Entry{
		vpnIP:   {Result: &ipapi.Result{IsVPN: true, IsDatacenter: true, VPN: &ipapi.VPN{Service: "ExampleVPN"}}},
		cleanIP: {Result: &ipapi.Result{CompanyType: "isp"}},
	}}, &fakePC{res: map[string]proxycheck.Entry{
		vpnIP:   {Result: &proxycheck.Result{VPN: true, Hosting: true, Anonymous: true, Operator: "Example"}},
		cleanIP: {Result: &proxycheck.Result{NetworkType: "Residential"}},
	}}
}

func TestLookupSynthesizesAndKeepsInputOrder(t *testing.T) {
	ia, pc := newFakes()
	e := &Engine{IPAPI: ia, Proxycheck: pc}
	rep := e.Lookup([]string{cleanIP, vpnIP, cleanIP}, false)
	if len(rep.Results) != 3 || rep.Results[0].IP != cleanIP || rep.Results[1].IP != vpnIP || rep.Results[2].IP != cleanIP {
		t.Fatalf("results = %+v", rep.Results)
	}
	if len(ia.calls) != 1 || len(ia.calls[0]) != 2 || len(pc.calls) != 1 || len(pc.calls[0]) != 2 {
		t.Fatalf("calls ipapi=%v proxycheck=%v; one request per source, duplicates asked once", ia.calls, pc.calls)
	}
	v := rep.Results[1]
	if v.Verdict != verdict.VPN || v.SeenBy != verdict.SeenByBoth || v.Providers.IPAPI != "ExampleVPN" || v.Providers.Proxycheck != "Example" {
		t.Fatalf("vpn result = %+v", v)
	}
	if c := rep.Results[0]; c.Verdict != verdict.None || c.Mobile == nil || *c.Mobile || c.Degraded {
		t.Fatalf("clean result = %+v", c)
	}
	if rep.Degraded != 0 {
		t.Fatalf("degraded = %d", rep.Degraded)
	}
}

func TestDisabledSourceIsNullNotFalse(t *testing.T) {
	_, pc := newFakes()
	rep := (&Engine{Proxycheck: pc}).Lookup([]string{vpnIP}, false)
	r := rep.Results[0]
	if r.IPAPI.Enabled || r.IPAPI.Result != nil || r.IPAPI.Error != "" || r.Mobile != nil {
		t.Fatalf("a disabled source must read as not queried: %+v", r)
	}
	if r.Degraded || len(r.Notes) == 0 {
		t.Fatalf("a disabled source is not a failure, but the note must say what cannot be told: %+v", r)
	}
}

func TestWholeRequestFailureMakesUnknownAndDegraded(t *testing.T) {
	ia, pc := newFakes()
	pc.err = errors.New("proxycheck.io: HTTP 502")
	rep := (&Engine{IPAPI: ia, Proxycheck: pc}).Lookup([]string{cleanIP, vpnIP}, false)
	if c := rep.Results[0]; c.Verdict != verdict.Unknown || !c.Degraded || !strings.Contains(c.Proxycheck.Error, "502") {
		t.Fatalf("a failure must never read as none: %+v", c)
	}
	if v := rep.Results[1]; v.Verdict != verdict.VPN || v.SeenBy != verdict.SeenByIPAPI {
		t.Fatalf("the surviving source still speaks: %+v", v)
	}
	if rep.Degraded != 2 {
		t.Fatalf("degraded = %d", rep.Degraded)
	}
}

func TestMissingEntryIsThatAddressesFailure(t *testing.T) {
	ia, pc := newFakes()
	rep := (&Engine{IPAPI: ia, Proxycheck: pc}).Lookup([]string{"203.0.113.5"}, false)
	r := rep.Results[0]
	if r.Verdict != verdict.Unknown || r.IPAPI.Error == "" || r.Proxycheck.Error == "" {
		t.Fatalf("got %+v", r)
	}
}

func TestWarningIsReported(t *testing.T) {
	ia, pc := newFakes()
	pc.warn = "near the daily limit"
	rep := (&Engine{IPAPI: ia, Proxycheck: pc}).Lookup([]string{cleanIP}, false)
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "near the daily limit") || rep.Results[0].Degraded {
		t.Fatalf("rep = %+v", rep)
	}
}

func TestPerSourceCache(t *testing.T) {
	ia, pc := newFakes()
	now := time.Unix(1_700_000_000, 0)
	e := &Engine{IPAPI: ia, Proxycheck: pc, Cache: &cache.Store{Dir: t.TempDir()}, IPAPITTL: 24 * time.Hour, Now: func() time.Time { return now }}

	e.Lookup([]string{cleanIP, vpnIP}, false)
	rep := e.Lookup([]string{cleanIP, vpnIP}, false)
	if len(ia.calls) != 1 || len(pc.calls) != 1 {
		t.Fatalf("second lookup must come from cache: ipapi=%v proxycheck=%v", ia.calls, pc.calls)
	}
	if !rep.Results[0].IPAPI.FromCache || !rep.Results[0].Proxycheck.FromCache {
		t.Fatalf("from_cache not marked: %+v", rep.Results[0])
	}

	// 20 minutes on: the anonymous proxycheck.io answer (15-minute cap) is
	// re-asked; the clean one (1 hour) and both ipapi.is answers are not.
	now = now.Add(20 * time.Minute)
	e.Lookup([]string{cleanIP, vpnIP}, false)
	if len(ia.calls) != 1 || len(pc.calls) != 2 || len(pc.calls[1]) != 1 || pc.calls[1][0] != vpnIP {
		t.Fatalf("calls ipapi=%v proxycheck=%v", ia.calls, pc.calls)
	}

	// --no-cache asks everything again.
	e.Lookup([]string{cleanIP}, true)
	if len(ia.calls) != 2 || len(pc.calls) != 3 {
		t.Fatalf("noCache must bypass: ipapi=%v proxycheck=%v", ia.calls, pc.calls)
	}
}

// One source failing must not throw away, or re-fetch, the other's answer.
func TestFailureIsNotCachedButTheHealthySourceIs(t *testing.T) {
	ia, pc := newFakes()
	pc.err = errors.New("down")
	now := time.Unix(1_700_000_000, 0)
	e := &Engine{IPAPI: ia, Proxycheck: pc, Cache: &cache.Store{Dir: t.TempDir()}, IPAPITTL: 24 * time.Hour, Now: func() time.Time { return now }}
	e.Lookup([]string{cleanIP}, false)
	pc.err = nil
	rep := e.Lookup([]string{cleanIP}, false)
	if len(ia.calls) != 1 {
		t.Fatalf("ipapi.is was asked again (%v); its answer should have been cached", ia.calls)
	}
	if len(pc.calls) != 2 || rep.Results[0].Verdict != verdict.None {
		t.Fatalf("the failed source must be asked again: calls=%v result=%+v", pc.calls, rep.Results[0])
	}
}

func TestAddingAKeyLaterNeverServesAStaleVerdict(t *testing.T) {
	ia, pc := newFakes()
	dir := t.TempDir()
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	only := &Engine{IPAPI: ia, Cache: &cache.Store{Dir: dir}, IPAPITTL: time.Hour, Now: now}
	only.Lookup([]string{vpnIP}, false)
	both := &Engine{IPAPI: ia, Proxycheck: pc, Cache: &cache.Store{Dir: dir}, IPAPITTL: time.Hour, Now: now}
	r := both.Lookup([]string{vpnIP}, false).Results[0]
	if r.SeenBy != verdict.SeenByBoth || len(pc.calls) != 1 {
		t.Fatalf("got %+v; the new source must be asked and the verdict recomputed", r)
	}
}

func TestIPAPIBatchesAtItsCeiling(t *testing.T) {
	ia := &fakeIPAPI{res: map[string]ipapi.Entry{}}
	ips := make([]string, 0, 150)
	for i := 0; i < 150; i++ {
		ips = append(ips, "192.0.2."+string(rune('0'+i%10))+string(rune('a'+i/10)))
	}
	(&Engine{IPAPI: ia}).Lookup(ips, false)
	if len(ia.calls) != 2 || len(ia.calls[0]) != ipapi.MaxBulk || len(ia.calls[1]) != 50 {
		t.Fatalf("batches = %d / %v", len(ia.calls), []int{len(ia.calls[0])})
	}
}

func TestProxycheckTTL(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	if d := proxycheckTTL(&proxycheck.Result{}, at); d != time.Hour {
		t.Fatalf("clean: %v", d)
	}
	if d := proxycheckTTL(&proxycheck.Result{VPN: true}, at); d != 15*time.Minute {
		t.Fatalf("anonymous without delist: %v", d)
	}
	soon := at.Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if d := proxycheckTTL(&proxycheck.Result{Anonymous: true, DelistDateTime: soon}, at); d != 5*time.Minute {
		t.Fatalf("anonymous delisted in 5 minutes: %v", d)
	}
	later := at.Add(3 * time.Hour).UTC().Format(time.RFC3339)
	if d := proxycheckTTL(&proxycheck.Result{Anonymous: true, DelistDateTime: later}, at); d != 15*time.Minute {
		t.Fatalf("the 15-minute cap must hold: %v", d)
	}
}
