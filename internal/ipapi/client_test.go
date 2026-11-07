package ipapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Fixtures are hand-written in the shape measured on 2026-11-07, with
// documentation addresses (RFC 5737 / RFC 3849) — never captured responses.

const fixtureBulk = `{
 "192.0.2.10": {"ip":"192.0.2.10","is_bogon":false,"is_mobile":false,"is_satellite":false,"is_anycast":false,
   "is_crawler":false,"is_datacenter":true,"is_tor":false,"is_proxy":false,"is_vpn":true,"is_abuser":false,
   "vpn":{"ip":"192.0.2.10","service":"ExampleVPN","type":"vpn_server","last_seen_str":"2026-11-06T12:43:23.958Z"},
   "datacenter":{"datacenter":"Example Hosting"},
   "company":{"name":"Example Hosting","type":"business","abuser_score":"0.0010 (Low)"}},
 "198.51.100.20": {"ip":"198.51.100.20","is_bogon":false,"is_mobile":false,"is_satellite":false,"is_anycast":false,
   "is_crawler":false,"is_datacenter":false,"is_tor":false,"is_proxy":false,"is_vpn":false,"is_abuser":false,
   "egress_service":{"type":"secure_web_gateway","provider":"ExampleGW"},
   "company":{"name":"ExampleGW","type":"business"}},
 "2001:db8::1": {"ip":"2001:db8::1","is_bogon":false,"is_mobile":false,"is_satellite":false,"is_anycast":true,
   "is_crawler":"ExampleBot","is_datacenter":true,"is_tor":false,"is_proxy":false,"is_vpn":"yes","is_abuser":false,
   "company":{"name":"Example CDN","type":"hosting"}},
 "total_elapsed_ms": 0.42
}`

type seen struct {
	method, path, ctype string
	body                map[string]any
}

func server(t *testing.T, status int, body string, got *seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			b, _ := io.ReadAll(r.Body)
			got.method, got.path, got.ctype = r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type")
			_ = json.Unmarshal(b, &got.body)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBulkSendsTheKeyInTheBodyAndMapsEveryInput(t *testing.T) {
	var got seen
	srv := server(t, 200, fixtureBulk, &got)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/", APIKey: "k-secret"}
	res, err := c.Lookup([]string{"192.0.2.10", "198.51.100.20", "2001:db8::1", "203.0.113.30"})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/" || got.ctype != "application/json" {
		t.Fatalf("request = %+v", got)
	}
	if got.body["key"] != "k-secret" || len(got.body["ips"].([]any)) != 4 {
		t.Fatalf("body = %v; the key goes in the JSON body with the ips", got.body)
	}
	if strings.Contains(got.path, "k-secret") {
		t.Fatal("the key must never be in the URL")
	}
	if len(res) != 4 {
		t.Fatalf("entries = %d, want one per input", len(res))
	}

	vpn := res["192.0.2.10"].Result
	if vpn == nil || !vpn.IsVPN || !vpn.IsDatacenter || vpn.VPN == nil || vpn.VPN.Service != "ExampleVPN" ||
		vpn.VPN.LastSeen == "" || vpn.Datacenter != "Example Hosting" || vpn.CompanyType != "business" {
		t.Fatalf("vpn entry = %+v", vpn)
	}
	gw := res["198.51.100.20"].Result
	if gw == nil || gw.Egress == nil || gw.Egress.Type != "secure_web_gateway" || gw.Egress.Provider != "ExampleGW" || gw.IsDatacenter {
		t.Fatalf("gateway entry = %+v", gw)
	}
	bot := res["2001:db8::1"].Result
	if bot == nil || !bot.IsVPN || bot.Crawler != "ExampleBot" || !bot.IsAnycast {
		t.Fatalf("a truthy non-boolean is_vpn and a named crawler must be read: %+v", bot)
	}
	missing := res["203.0.113.30"]
	if missing.Result != nil || !strings.Contains(missing.Err, "did not answer") {
		t.Fatalf("an address missing from the response must be its failure, never \"nothing found\": %+v", missing)
	}
}

func TestWholeRequestFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{403, `{"error":"Invalid API key.","error_code":"ERR_FORBIDDEN_INVALID_API_KEY"}`, "check [ipapi] api_key"},
		{429, `{"error":"quota","error_code":"ERR_QUOTA_EXCEEDED"}`, "quota is used up"},
		{400, `{"error":"More than 100","error_code":"ERR_BULK_LIMIT_EXCEEDED"}`, "ERR_BULK_LIMIT_EXCEEDED"},
		{403, ``, "firewall"},
		{404, `<!DOCTYPE html><pre>Cannot POST /v9</pre>`, "check [ipapi] base_url"},
		{302, ``, "redirect refused"},
		{500, `oops`, "HTTP 500"},
	} {
		srv := server(t, tc.status, tc.body, nil)
		hc := srv.Client()
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c := &Client{HTTP: hc, BaseURL: srv.URL, APIKey: "k-secret"}
		_, err := c.Lookup([]string{"192.0.2.10"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("HTTP %d: err = %v, want it to mention %q", tc.status, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "k-secret") {
			t.Errorf("HTTP %d: the key leaked into the error", tc.status)
		}
	}
}

func TestUndecodableAnswerIsAnError(t *testing.T) {
	srv := server(t, 200, `not json`, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	if _, err := c.Lookup([]string{"192.0.2.10"}); err == nil {
		t.Fatal("an undecodable 200 must be an error, never a verdict")
	}
}

func TestEntryErrorIsThatAddressesFailure(t *testing.T) {
	srv := server(t, 200, `{"192.0.2.10":{"error":"No data"}}`, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	res, err := c.Lookup([]string{"192.0.2.10"})
	if err != nil || res["192.0.2.10"].Result != nil || res["192.0.2.10"].Err == "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestCeilingIsEnforcedLocally(t *testing.T) {
	ips := make([]string, MaxBulk+1)
	c := &Client{HTTP: http.DefaultClient, APIKey: "k"}
	if _, err := c.Lookup(ips); err == nil {
		t.Fatal("more than 100 addresses must be refused before sending")
	}
}

func TestThirdPartyTextIsCleaned(t *testing.T) {
	body := `{"192.0.2.10":{"is_vpn":true,"vpn":{"service":"Bad\u001b[31mVPN\u202e"},"company":{"name":"Co\u0007rp","type":"BUSINESS"}}}`
	srv := server(t, 200, body, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	res, err := c.Lookup([]string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	r := res["192.0.2.10"].Result
	if r.VPN.Service != "Bad[31mVPN" || r.CompanyName != "Corp" || r.CompanyType != "business" {
		t.Fatalf("result = %+v", r)
	}
}

func TestBooleanCrawlerIsKeptAsUnnamed(t *testing.T) {
	srv := server(t, 200, `{"192.0.2.10":{"is_crawler":true},"192.0.2.11":{"is_crawler":false}}`, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	res, err := c.Lookup([]string{"192.0.2.10", "192.0.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	if res["192.0.2.10"].Result.Crawler != UnnamedCrawler || res["192.0.2.11"].Result.Crawler != "" {
		t.Fatalf("got %+v / %+v", res["192.0.2.10"].Result, res["192.0.2.11"].Result)
	}
}
