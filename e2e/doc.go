// Package e2e holds the live tests against ipapi.is and proxycheck.io (build
// tag "e2e", run by make e2e). They skip unless both
// VPN_LOOKUP_IPAPI_API_KEY and VPN_LOOKUP_PROXYCHECK_API_KEY are set; a run
// spends one lookup per fixture address on each free tier.
package e2e
