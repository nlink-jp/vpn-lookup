// Package proxycheck is the proxycheck.io v3 client: one POST per lookup, the
// addresses in the form body, the key and tag=0 in the query string.
//
// Measured 2026-11-07: proxycheck.io does not read a key from the POST body
// (only the URL-key queries were counted on the dashboard), and it answers an
// invalid or missing key silently as an unregistered caller, so a response
// cannot show whether the key took effect. tag=0 is always sent — without it,
// an address judged anonymous stays in the account's detection log for 180
// days and one judged clean goes through unpublished "post-query testing".
// Because the key travels in the URL, the URL never reaches an error message
// (guard.ScrubURL) and the client never follows a redirect.
package proxycheck

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nlink-jp/vpn-lookup/internal/guard"
)

// DefaultBaseURL is the proxycheck.io v3 API root.
const DefaultBaseURL = "https://proxycheck.io/v3"

// maxServices caps the operator's service list kept per address.
const maxServices = 10

// Doer is the minimal HTTP surface the client needs.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client queries proxycheck.io.
type Client struct {
	HTTP      Doer // must refuse redirects (guard.RefuseRedirects)
	BaseURL   string
	APIKey    string
	UserAgent string
}

// Result is one address's answer. Every string is third-party text, cleaned.
type Result struct {
	Proxy          bool     `json:"proxy"`
	VPN            bool     `json:"vpn"`
	Tor            bool     `json:"tor"`
	Hosting        bool     `json:"hosting"`
	Anonymous      bool     `json:"anonymous"`
	Compromised    bool     `json:"compromised"`
	Scraper        bool     `json:"scraper"`
	Risk           *int     `json:"risk,omitempty"`
	Confidence     *int     `json:"confidence,omitempty"`
	Operator       string   `json:"operator,omitempty"`
	Services       []string `json:"operator_services,omitempty"`
	NetworkType    string   `json:"network_type,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	DelistDateTime string   `json:"delist_datetime,omitempty"`
}

// Entry is one address's outcome.
type Entry struct {
	Result *Result
	Err    string
}

// Answer is a whole response: one entry per input, and the warning proxycheck.io
// attaches when the account is near its limit (status "warning", HTTP 200) —
// an answer with a note, not a failure.
type Answer struct {
	Entries map[string]Entry
	Warning string
}

// Lookup asks about the given canonical address strings.
func (c *Client) Lookup(ips []string) (*Answer, error) {
	ans := &Answer{Entries: make(map[string]Entry, len(ips))}
	if len(ips) == 0 {
		return ans, nil
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	q := url.Values{}
	q.Set("key", c.APIKey)
	q.Set("tag", "0")
	form := url.Values{}
	form.Set("ips", strings.Join(ips, ","))
	req, err := http.NewRequest(http.MethodPost, base+"/?"+q.Encode(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: %w", guard.ScrubURL(err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: %w", guard.ScrubURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: read response: %w", guard.ScrubURL(err))
	}

	var doc map[string]json.RawMessage
	jsonErr := json.Unmarshal(raw, &doc)
	status, message := field(doc, "status"), field(doc, "message")

	if resp.StatusCode != http.StatusOK {
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			return nil, fmt.Errorf("proxycheck.io: HTTP %d redirect refused (the API key is never sent to another URL)", resp.StatusCode)
		case jsonErr == nil && message != "":
			return nil, fmt.Errorf("proxycheck.io: HTTP %d %s: %s", resp.StatusCode, status, message)
		case resp.StatusCode == http.StatusNotFound:
			return nil, fmt.Errorf("proxycheck.io: HTTP 404 (check [proxycheck] base_url)")
		default:
			return nil, fmt.Errorf("proxycheck.io: HTTP %d: %s", resp.StatusCode, guard.Truncate(raw, 200))
		}
	}
	if jsonErr != nil {
		return nil, fmt.Errorf("proxycheck.io: decode response: %w", jsonErr)
	}
	switch status {
	case "ok":
	case "warning":
		ans.Warning = message
		if ans.Warning == "" {
			ans.Warning = "proxycheck.io returned a warning without a message"
		}
	default:
		// "denied", "error" or anything unknown arriving with 200: not an answer.
		return nil, fmt.Errorf("proxycheck.io: status %q: %s", status, message)
	}

	for _, ip := range ips {
		v, ok := doc[ip]
		if !ok {
			ans.Entries[ip] = Entry{Err: "proxycheck.io did not answer for this address"}
			continue
		}
		r, err := decode(v)
		if err != nil {
			ans.Entries[ip] = Entry{Err: "proxycheck.io: " + err.Error()}
			continue
		}
		ans.Entries[ip] = Entry{Result: r}
	}
	return ans, nil
}

// field reads a top-level string, cleaned and capped: the message lands in
// every address's error and in warnings, and upstream sets no length.
func field(doc map[string]json.RawMessage, name string) string {
	var s string
	if v, ok := doc[name]; ok && json.Unmarshal(v, &s) == nil {
		return guard.Truncate([]byte(s), 200)
	}
	return ""
}

type wire struct {
	Error      string `json:"error"`
	Detections *struct {
		Proxy       bool `json:"proxy"`
		VPN         bool `json:"vpn"`
		Tor         bool `json:"tor"`
		Hosting     bool `json:"hosting"`
		Anonymous   bool `json:"anonymous"`
		Compromised bool `json:"compromised"`
		Scraper     bool `json:"scraper"`
		Risk        *int `json:"risk"`
		Confidence  *int `json:"confidence"`
	} `json:"detections"`
	Network *struct {
		Type     string `json:"type"`
		Provider string `json:"provider"`
	} `json:"network"`
	Operator *struct {
		Name     string   `json:"name"`
		Services []string `json:"services"`
	} `json:"operator"`
	History *struct {
		DelistDateTime string `json:"delist_datetime"`
	} `json:"detection_history"`
}

func decode(v json.RawMessage) (*Result, error) {
	var w wire
	if err := json.Unmarshal(v, &w); err != nil {
		return nil, fmt.Errorf("decode entry: %w", err)
	}
	if w.Error != "" {
		return nil, fmt.Errorf("%s", guard.Truncate([]byte(w.Error), 200))
	}
	if w.Detections == nil {
		// Every v3 answer carries detections; without them there is nothing to
		// read, and an empty result would read as "nothing detected".
		return nil, fmt.Errorf("the answer carries no detections section")
	}
	d := w.Detections
	r := &Result{
		Proxy: d.Proxy, VPN: d.VPN, Tor: d.Tor, Hosting: d.Hosting, Anonymous: d.Anonymous,
		Compromised: d.Compromised, Scraper: d.Scraper, Risk: d.Risk, Confidence: d.Confidence,
	}
	if w.Network != nil {
		r.NetworkType = guard.Name(w.Network.Type)
		r.Provider = guard.Name(w.Network.Provider)
	}
	if w.Operator != nil {
		r.Operator = guard.Name(w.Operator.Name)
		for _, s := range w.Operator.Services {
			if len(r.Services) == maxServices {
				break // a list with no upstream bound, capped so a result fits a client's budget
			}
			if s = strings.ToLower(guard.Name(s)); s != "" {
				r.Services = append(r.Services, s)
			}
		}
	}
	if w.History != nil {
		r.DelistDateTime = guard.Name(w.History.DelistDateTime)
	}
	return r, nil
}

// Usage is the account's daily usage from the dashboard API. Measured
// 2026-11-07: the counts update about an hour late.
type Usage struct {
	QueriesToday int `json:"queries_today"`
	DailyLimit   int `json:"daily_limit"`
}

// Usage reads the account's daily usage (GET /dashboard/export/usage/ on the
// API's host, key in the query string like every proxycheck.io call).
func (c *Client) Usage() (*Usage, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: base URL: %w", guard.ScrubURL(err))
	}
	q := url.Values{}
	q.Set("key", c.APIKey)
	req, err := http.NewRequest(http.MethodGet, u.Scheme+"://"+u.Host+"/dashboard/export/usage/?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: %w", guard.ScrubURL(err))
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: %w", guard.ScrubURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("proxycheck.io: read usage: %w", guard.ScrubURL(err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxycheck.io: usage: HTTP %d: %s", resp.StatusCode, guard.Truncate(raw, 200))
	}
	var w struct {
		QueriesToday *int `json:"Queries Today"`
		DailyLimit   *int `json:"Daily Limit"`
	}
	if err := json.Unmarshal(raw, &w); err != nil || w.QueriesToday == nil || w.DailyLimit == nil {
		return nil, fmt.Errorf("proxycheck.io: usage: unexpected answer: %s", guard.Truncate(raw, 200))
	}
	return &Usage{QueriesToday: *w.QueriesToday, DailyLimit: *w.DailyLimit}, nil
}
