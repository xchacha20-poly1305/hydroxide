package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
)

const (
	// torAPIEndpoint is the ProtonMail API exposed as a Tor onion service.
	torAPIEndpoint  = "https://mail.protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/api"
	defaultTorProxy = "socks5://127.0.0.1:9050"
)

// newProxyHTTPClientFunc returns a function creating the HTTP client of a new
// ProtonMail session, sending requests through the proxy at rawURL.
//
// If isolate is set, the proxy must be a Tor SOCKS port: each client then
// authenticates with random credentials, which makes Tor (IsolateSOCKSAuth,
// enabled by default) use a separate circuit per session, so that sessions of
// different accounts cannot be linked to each other.
func newProxyHTTPClientFunc(rawURL string, isolate bool) (func() *http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: expected scheme://host:port", rawURL)
	}

	if !isolate {
		c := &http.Client{Transport: newProxyTransport(u)}
		return func() *http.Client { return c }, nil
	}

	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("invalid Tor proxy URL %q: expected a socks5:// URL", rawURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("invalid Tor proxy URL %q: credentials are generated per session and must not be set", rawURL)
	}
	return func() *http.Client {
		isolated := *u
		isolated.User = url.UserPassword(rand.Text(), rand.Text())
		return &http.Client{Transport: newProxyTransport(&isolated)}
	}, nil
}

func newProxyTransport(proxyURL *url.URL) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyURL(proxyURL)
	return t
}
