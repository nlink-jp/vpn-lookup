// Package guard holds the three rules every upstream client follows: third-party
// text is cleaned before it can reach a terminal or an MCP client, the HTTP
// client that carries an API key never follows a redirect, and a network
// error never quotes the request URL.
package guard

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// Clean strips control (Cc) and format (Cf) characters from third-party text —
// terminal escapes, bidi overrides, zero-width characters — and trims the
// result. Provider names, WHOIS names and upstream error text are written by
// whoever holds the data; the words survive as claims, the control does not.
func Clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s))
}

// Truncate shortens third-party text for an error message, cleaned.
func Truncate(b []byte, n int) string {
	if len(b) > n {
		return Clean(string(b[:n])) + "..."
	}
	return Clean(string(b))
}

// RefuseRedirects is the CheckRedirect for every http.Client that carries a
// key. Go strips Authorization and Cookie on a cross-host redirect but not a
// custom header, and a key in the query string travels with the URL itself,
// so following a redirect could hand the key to whatever host it names,
// possibly over plain HTTP. Neither API redirects; a 3xx is reported instead.
func RefuseRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// ScrubURL returns err without the request URL: Go's *url.Error formats as
// `Op "URL": Err`, and proxycheck.io takes its key in the query string, so the
// URL must never reach an error message.
func ScrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return errors.New(ue.Op + ": " + ue.Err.Error())
	}
	return err
}
