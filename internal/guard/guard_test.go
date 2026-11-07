package guard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCleanStripsControlAndFormatCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"Mull\u001b[31mvad\u0007": "Mull[31mvad",
		"Emo\u202etet\u200b":      "Emotet",
		"  Zscaler\r\n":           "Zscaler",
		"日本\u2066語\u2069":         "日本語",
		"plain":                   "plain",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameIsCleanedAndCapped(t *testing.T) {
	long := strings.Repeat("あ", MaxName+50)
	got := Name(long)
	if r := []rune(got); len(r) != MaxName+1 || r[MaxName] != '…' {
		t.Fatalf("Name kept %d runes; want %d plus an ellipsis", len(r), MaxName)
	}
	if Name("Ex\u001bample") != "Example" {
		t.Fatal("Name must clean too")
	}
}

func TestTruncateCleansToo(t *testing.T) {
	if got := Truncate([]byte("bad\u001b[2Jthing"), 100); got != "bad[2Jthing" {
		t.Fatalf("Truncate = %q", got)
	}
	if got := Truncate([]byte("abcdef"), 3); got != "abc..." {
		t.Fatalf("Truncate = %q", got)
	}
}

// A key in the query string must never reach an error message: Go's
// url.Error quotes the whole URL.
func TestScrubURLDropsTheURL(t *testing.T) {
	c := &http.Client{}
	_, err := c.Get("http://127.0.0.1:1/v3/192.0.2.1?key=SECRET-KEY&tag=0")
	if err == nil {
		t.Skip("something is listening on 127.0.0.1:1")
	}
	if !strings.Contains(err.Error(), "SECRET-KEY") {
		t.Fatalf("precondition: Go's error was expected to quote the URL: %v", err)
	}
	if s := ScrubURL(err).Error(); strings.Contains(s, "SECRET-KEY") || strings.Contains(s, "key=") {
		t.Fatalf("ScrubURL left the key in: %s", s)
	}
}

func TestRefuseRedirectsKeepsTheKeyHome(t *testing.T) {
	var leaked string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.URL.RawQuery + r.Header.Get("X-Key")
	}))
	defer elsewhere.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer origin.Close()

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/v3/?key=SECRET", nil)
	req.Header.Set("X-Key", "SECRET")
	resp, err := (&http.Client{CheckRedirect: RefuseRedirects}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || leaked != "" {
		t.Fatalf("status %d, leaked %q; the redirect must not be followed", resp.StatusCode, leaked)
	}
}
