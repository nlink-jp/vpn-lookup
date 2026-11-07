// Package ipapi is the ipapi.is client: one bulk POST per lookup (up to 100
// addresses), the key in the JSON body so it never appears in a URL.
//
// Measured 2026-11-07: the response is an object keyed by the exact strings
// sent (a non-canonical IPv6 comes back under the same spelling), so callers
// send canonical strings; an entry ipapi.is does not accept is dropped
// silently, so an address missing from the response is a failure for that
// address, never "nothing found". Without a key the API returns no detection
// flags, so this client is used only with one.
package ipapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nlink-jp/vpn-lookup/internal/guard"
)

// DefaultBaseURL is the ipapi.is endpoint (one endpoint for GET and POST).
const DefaultBaseURL = "https://api.ipapi.is"

// MaxBulk is the documented ceiling of one bulk request.
const MaxBulk = 100

// Doer is the minimal HTTP surface the client needs.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client queries ipapi.is.
type Client struct {
	HTTP      Doer // must refuse redirects (guard.RefuseRedirects)
	BaseURL   string
	APIKey    string
	UserAgent string
}

// VPN is the vpn object, present when the provider is known.
type VPN struct {
	Service  string `json:"service"`
	Type     string `json:"type,omitempty"`      // exit_node | vpn_server
	LastSeen string `json:"last_seen,omitempty"` // ISO 8601
}

// Egress is the egress_service object: a managed service whose users' traffic
// leaves from the address.
type Egress struct {
	Type     string `json:"type"` // secure_web_gateway | private_relay | satellite | dns_resolver | email_gateway
	Provider string `json:"provider,omitempty"`
}

// Result is one address's answer. Every string is third-party text, cleaned.
type Result struct {
	IsVPN        bool    `json:"is_vpn"`
	IsProxy      bool    `json:"is_proxy"`
	IsTor        bool    `json:"is_tor"`
	IsDatacenter bool    `json:"is_datacenter"`
	IsMobile     bool    `json:"is_mobile"`
	IsSatellite  bool    `json:"is_satellite"`
	IsAnycast    bool    `json:"is_anycast"`
	IsAbuser     bool    `json:"is_abuser"`
	IsBogon      bool    `json:"is_bogon"`
	Crawler      string  `json:"crawler,omitempty"` // the bot's name; "" when none
	VPN          *VPN    `json:"vpn,omitempty"`
	Datacenter   string  `json:"datacenter,omitempty"`
	Egress       *Egress `json:"egress_service,omitempty"`
	CompanyType  string  `json:"company_type,omitempty"`
	CompanyName  string  `json:"company_name,omitempty"`
	AbuserScore  string  `json:"abuser_score,omitempty"` // company.abuser_score, reference only
}

// Entry is one address's outcome inside a bulk answer.
type Entry struct {
	Result *Result
	Err    string // the address's own failure; "" when Result is set
}

// Lookup asks about up to MaxBulk addresses, given as canonical strings. The
// returned map has one entry per input. A whole-request failure is the error.
func (c *Client) Lookup(ips []string) (map[string]Entry, error) {
	if len(ips) == 0 {
		return map[string]Entry{}, nil
	}
	if len(ips) > MaxBulk {
		return nil, fmt.Errorf("ipapi.is: %d addresses in one request; the ceiling is %d", len(ips), MaxBulk)
	}
	body, err := json.Marshal(map[string]any{"ips": ips, "key": c.APIKey})
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	req, err := http.NewRequest(http.MethodPost, base, bytes.NewReader(body))
	if err != nil {
		return nil, guard.ScrubURL(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipapi.is: %w", guard.ScrubURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("ipapi.is: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp, raw)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ipapi.is: decode response: %w", err)
	}
	out := make(map[string]Entry, len(ips))
	for _, ip := range ips {
		v, ok := doc[ip]
		if !ok {
			out[ip] = Entry{Err: "ipapi.is did not answer for this address (it drops entries it does not accept)"}
			continue
		}
		r, err := decode(v)
		if err != nil {
			out[ip] = Entry{Err: "ipapi.is: " + err.Error()}
			continue
		}
		out[ip] = Entry{Result: r}
	}
	return out, nil
}

// statusError turns a non-200 answer into an error. ipapi.is errors are JSON
// with a stable error_code; a wrong path answers HTML; a client banned at the
// firewall gets a bare 403 with an empty body.
func statusError(resp *http.Response, raw []byte) error {
	var e struct {
		Error     string `json:"error"`
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(raw, &e)
	code := guard.Clean(e.ErrorCode)
	switch {
	case code == "ERR_FORBIDDEN_INVALID_API_KEY":
		return fmt.Errorf("ipapi.is: HTTP %d %s (check [ipapi] api_key)", resp.StatusCode, code)
	case code == "ERR_QUOTA_EXCEEDED":
		return fmt.Errorf("ipapi.is: HTTP %d %s (the daily quota is used up)", resp.StatusCode, code)
	case code != "":
		return fmt.Errorf("ipapi.is: HTTP %d %s: %s", resp.StatusCode, code, guard.Truncate([]byte(e.Error), 200))
	case resp.StatusCode == http.StatusForbidden && len(bytes.TrimSpace(raw)) == 0:
		return fmt.Errorf("ipapi.is: HTTP 403 with an empty body (blocked at its firewall; back off before retrying)")
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("ipapi.is: HTTP %d redirect refused (the API key is never sent to another URL)", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("ipapi.is: HTTP 404 (check [ipapi] base_url)")
	default:
		return fmt.Errorf("ipapi.is: HTTP %d: %s", resp.StatusCode, guard.Truncate(raw, 200))
	}
}

type wire struct {
	IsVPN        json.RawMessage `json:"is_vpn"`
	IsProxy      json.RawMessage `json:"is_proxy"`
	IsTor        json.RawMessage `json:"is_tor"`
	IsDatacenter json.RawMessage `json:"is_datacenter"`
	IsMobile     json.RawMessage `json:"is_mobile"`
	IsSatellite  json.RawMessage `json:"is_satellite"`
	IsAnycast    json.RawMessage `json:"is_anycast"`
	IsAbuser     json.RawMessage `json:"is_abuser"`
	IsBogon      json.RawMessage `json:"is_bogon"`
	IsCrawler    json.RawMessage `json:"is_crawler"`
	VPN          *struct {
		Service     string `json:"service"`
		Type        string `json:"type"`
		LastSeenStr string `json:"last_seen_str"`
	} `json:"vpn"`
	Datacenter *struct {
		Datacenter string `json:"datacenter"`
	} `json:"datacenter"`
	Egress *struct {
		Type     string `json:"type"`
		Provider string `json:"provider"`
	} `json:"egress_service"`
	Company *struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		AbuserScore string `json:"abuser_score"`
	} `json:"company"`
	Error string `json:"error"`
}

func decode(v json.RawMessage) (*Result, error) {
	var w wire
	if err := json.Unmarshal(v, &w); err != nil {
		return nil, fmt.Errorf("decode entry: %w", err)
	}
	if w.Error != "" {
		return nil, fmt.Errorf("%s", guard.Truncate([]byte(w.Error), 200))
	}
	r := &Result{
		IsVPN: truthy(w.IsVPN), IsProxy: truthy(w.IsProxy), IsTor: truthy(w.IsTor),
		IsDatacenter: truthy(w.IsDatacenter), IsMobile: truthy(w.IsMobile),
		IsSatellite: truthy(w.IsSatellite), IsAnycast: truthy(w.IsAnycast),
		IsAbuser: truthy(w.IsAbuser), IsBogon: truthy(w.IsBogon),
		Crawler: crawlerName(w.IsCrawler),
	}
	if w.VPN != nil && guard.Clean(w.VPN.Service) != "" {
		r.VPN = &VPN{Service: guard.Clean(w.VPN.Service), Type: guard.Clean(w.VPN.Type), LastSeen: guard.Clean(w.VPN.LastSeenStr)}
	}
	if w.Datacenter != nil {
		r.Datacenter = guard.Clean(w.Datacenter.Datacenter)
	}
	if w.Egress != nil && guard.Clean(w.Egress.Type) != "" {
		r.Egress = &Egress{Type: strings.ToLower(guard.Clean(w.Egress.Type)), Provider: guard.Clean(w.Egress.Provider)}
	}
	if w.Company != nil {
		r.CompanyType = strings.ToLower(guard.Clean(w.Company.Type))
		r.CompanyName = guard.Clean(w.Company.Name)
		r.AbuserScore = guard.Clean(w.Company.AbuserScore)
	}
	return r, nil
}

// truthy reads an is_* flag. The documentation asks clients to test for
// truthiness, not === true: a VPN record may carry a value other than true.
func truthy(v json.RawMessage) bool {
	s := strings.TrimSpace(string(v))
	switch s {
	case "", "null", "false", "0", `""`:
		return false
	}
	return true
}

// crawlerName reads is_crawler, which is false or the bot's name.
func crawlerName(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return guard.Clean(s)
	}
	return ""
}
