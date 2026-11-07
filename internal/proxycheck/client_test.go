package proxycheck

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Fixtures are hand-written in the shape measured on 2026-11-07, with
// documentation addresses — never captured responses.

const fixture = `{
    "status": "ok",
    "192.0.2.10": {
        "network": {"asn": "AS64500", "type": "Hosting", "provider": "Example Hosting"},
        "detections": {"proxy": false, "vpn": true, "compromised": false, "scraper": false, "tor": false,
            "hosting": true, "anonymous": true, "risk": 50, "confidence": 100},
        "detection_history": {"delisted": false, "delist_datetime": "2026-11-07T03:35:58Z"},
        "operator": {"name": "ExampleVPN", "services": ["datacenter_vpns"]}
    },
    "198.51.100.20": {
        "network": {"asn": "AS64501", "type": "Residential", "provider": "Example ISP"},
        "detections": {"proxy": false, "vpn": false, "compromised": false, "scraper": false, "tor": false,
            "hosting": false, "anonymous": false, "risk": 0, "confidence": 100},
        "operator": null
    },
    "203.0.113.30": {"error": "Invalid or Internal IP Address."},
    "query_time": 12
}`

type seen struct {
	method, ctype string
	query         url.Values
	form          url.Values
}

func server(t *testing.T, status int, body string, got *seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			b, _ := io.ReadAll(r.Body)
			got.method, got.ctype, got.query = r.Method, r.Header.Get("Content-Type"), r.URL.Query()
			got.form, _ = url.ParseQuery(string(b))
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestKeyAndTagGoInTheURLAddressesInTheBody(t *testing.T) {
	var got seen
	srv := server(t, 200, fixture, &got)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k-secret"}
	ans, err := c.Lookup([]string{"192.0.2.10", "198.51.100.20", "203.0.113.30", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.query.Get("key") != "k-secret" || got.query.Get("tag") != "0" {
		t.Fatalf("request = %+v; the key and tag=0 go in the URL (a body key is ignored, measured)", got)
	}
	if got.form.Get("ips") != "192.0.2.10,198.51.100.20,203.0.113.30,2001:db8::1" || got.form.Get("key") != "" {
		t.Fatalf("form = %v", got.form)
	}
	if len(ans.Entries) != 4 || ans.Warning != "" {
		t.Fatalf("answer = %+v", ans)
	}

	vpn := ans.Entries["192.0.2.10"].Result
	if vpn == nil || !vpn.VPN || !vpn.Hosting || vpn.Operator != "ExampleVPN" || len(vpn.Services) != 1 ||
		vpn.Risk == nil || *vpn.Risk != 50 || vpn.DelistDateTime == "" || vpn.NetworkType != "Hosting" {
		t.Fatalf("vpn entry = %+v", vpn)
	}
	clean := ans.Entries["198.51.100.20"].Result
	if clean == nil || clean.VPN || clean.Operator != "" || clean.NetworkType != "Residential" {
		t.Fatalf("clean entry = %+v", clean)
	}
	if e := ans.Entries["203.0.113.30"]; e.Result != nil || !strings.Contains(e.Err, "Invalid or Internal") {
		t.Fatalf("a per-entry error must be that address's failure: %+v", e)
	}
	if e := ans.Entries["2001:db8::1"]; e.Result != nil || !strings.Contains(e.Err, "did not answer") {
		t.Fatalf("a missing entry must be that address's failure: %+v", e)
	}
}

func TestWarningIsAnAnswerWithANote(t *testing.T) {
	body := strings.Replace(fixture, `"status": "ok"`, `"status": "warning", "message": "1,000 of 1,000 queries used today"`, 1)
	srv := server(t, 200, body, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	ans, err := c.Lookup([]string{"192.0.2.10"})
	if err != nil || ans.Warning == "" || ans.Entries["192.0.2.10"].Result == nil {
		t.Fatalf("ans=%+v err=%v", ans, err)
	}
}

func TestFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{200, `{"status": "denied", "message": "Your access has been denied"}`, "denied"},
		{200, `{"status": "error", "message": "x"}`, `"error"`},
		{400, `{"status": "error", "message": "No valid IP Addresses supplied."}`, "No valid IP Addresses supplied."},
		{429, `{"status": "denied", "message": "Daily queries exhausted"}`, "Daily queries exhausted"},
		{404, `<!DOCTYPE html><html>not here</html>`, "check [proxycheck] base_url"},
		{302, ``, "redirect refused"},
		{502, `bad gateway`, "HTTP 502"},
		{200, `not json`, "decode response"},
	} {
		srv := server(t, tc.status, tc.body, nil)
		hc := srv.Client()
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c := &Client{HTTP: hc, BaseURL: srv.URL, APIKey: "k-secret"}
		_, err := c.Lookup([]string{"192.0.2.10"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("HTTP %d %q: err = %v, want %q", tc.status, tc.body, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "k-secret") {
			t.Errorf("HTTP %d: the key leaked into the error: %v", tc.status, err)
		}
	}
}

// The key is in the URL, and Go's url.Error quotes the URL: a transport
// failure must not carry it.
func TestTransportErrorDoesNotLeakTheKey(t *testing.T) {
	c := &Client{HTTP: &http.Client{}, BaseURL: "http://127.0.0.1:1", APIKey: "k-SECRET"}
	_, err := c.Lookup([]string{"192.0.2.10"})
	if err == nil {
		t.Skip("something is listening on 127.0.0.1:1")
	}
	if strings.Contains(err.Error(), "k-SECRET") || strings.Contains(err.Error(), "key=") {
		t.Fatalf("the key leaked: %v", err)
	}
}

func TestEntryWithoutDetectionsIsAFailure(t *testing.T) {
	srv := server(t, 200, `{"status":"ok","192.0.2.10":{"network":{"type":"Hosting"}}}`, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	ans, err := c.Lookup([]string{"192.0.2.10"})
	if err != nil || ans.Entries["192.0.2.10"].Result != nil {
		t.Fatalf("an entry with no detections must not read as \"nothing detected\": %+v %v", ans, err)
	}
}

func TestThirdPartyTextIsCleaned(t *testing.T) {
	body := `{"status":"ok","192.0.2.10":{"detections":{"vpn":true},"operator":{"name":"Ex\u001b[2Jample\u202e","services":["Residential_Proxies"]}}}`
	srv := server(t, 200, body, nil)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k"}
	ans, err := c.Lookup([]string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	r := ans.Entries["192.0.2.10"].Result
	if r.Operator != "Ex[2Jample" || r.Services[0] != "residential_proxies" {
		t.Fatalf("result = %+v", r)
	}
}

func TestUsageReadsTheDashboard(t *testing.T) {
	var gotPath, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey = r.URL.Path, r.URL.Query().Get("key")
		fmt.Fprint(w, `{"Burst Tokens Available": 1, "Queries Today": 42, "Daily Limit": 1000, "Plan Tier": "Free"}`)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/v3", APIKey: "k"}
	u, err := c.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/dashboard/export/usage/" || gotKey != "k" || u.QueriesToday != 42 || u.DailyLimit != 1000 {
		t.Fatalf("path=%q key=%q usage=%+v", gotPath, gotKey, u)
	}
}

func TestUsageFailuresAreErrorsWithoutTheKey(t *testing.T) {
	for _, body := range []string{`{"error":"x"}`, `not json`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		}))
		c := &Client{HTTP: srv.Client(), BaseURL: srv.URL, APIKey: "k-SECRET"}
		_, err := c.Usage()
		srv.Close()
		if err == nil || strings.Contains(err.Error(), "k-SECRET") {
			t.Fatalf("body %q: err = %v", body, err)
		}
	}
	c := &Client{HTTP: &http.Client{}, BaseURL: "http://127.0.0.1:1", APIKey: "k-SECRET"}
	if _, err := c.Usage(); err == nil || strings.Contains(err.Error(), "k-SECRET") {
		t.Fatalf("transport error leaked the key or did not fail: %v", err)
	}
}
