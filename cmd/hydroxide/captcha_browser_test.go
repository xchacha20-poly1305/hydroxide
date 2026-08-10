package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// protonCaptchaCSP is the Content-Security-Policy the challenge page is served
// under, as sent by the per-app API hosts. The whole approach rests on what it
// permits, so the test reproduces it verbatim rather than paraphrasing it.
const protonCaptchaCSP = "default-src 'self'; media-src https:; connect-src https: wss:; " +
	"script-src 'self' 'unsafe-eval' 'nonce-testnonce' 'strict-dynamic' https:; " +
	"style-src 'self' 'unsafe-inline'; img-src http: https: data: blob: cid:; frame-src https:"

func findChrome() string {
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func runChrome(t *testing.T, chrome, url string) {
	t.Helper()

	cmd := exec.Command(chrome,
		"--headless=new", "--disable-gpu", "--no-sandbox",
		"--virtual-time-budget=5000", "--dump-dom", url)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("browser failed: %v\n%s", err, out)
	}
}

// The snippet reports the token with an image request because the challenge
// page's CSP allows one to a loopback address. Prove that in a real browser,
// under that exact policy, rather than trusting the reading of the header.
func TestCaptchaSnippetReportsTokenUnderProtonCSP(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome-family browser available")
	}

	tokens := make(chan string, 1)

	srv := httptest.NewUnstartedServer(nil)
	beaconURL := "http://" + srv.Listener.Addr().String() + "/token"

	// The page stands in for the challenge: same policy, and it emits the same
	// message a solved CAPTCHA does. prompt() is stripped, as headless Chrome
	// dismisses dialogs and the fallback is not what is under test.
	page := fmt.Sprintf(`<!doctype html><meta charset="utf-8">
<script nonce="testnonce">
%v
window.postMessage({type: 'pm_captcha', token: %q}, '*');
</script>`,
		strings.Replace(
			fmt.Sprintf(captchaSnippet, beaconURL),
			"  prompt('hydroxide token (only needed if your terminal has not continued)', e.data.token);\n",
			"", 1),
		testToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", protonCaptchaCSP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	mux.Handle("/token", captchaHandler(tokens))

	srv.Config.Handler = mux
	srv.Start()
	defer srv.Close()

	runChrome(t, chrome, srv.URL)

	select {
	case got := <-tokens:
		if got != testToken {
			t.Errorf("got token %q, want %q", got, testToken)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the snippet never reported the token")
	}
}

// The counterpart: a fetch to the same address is refused by that policy. If
// this ever starts passing, the image request is no longer necessary.
func TestFetchToLoopbackIsBlockedUnderProtonCSP(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome-family browser available")
	}

	reached := make(chan string, 1)

	srv := httptest.NewUnstartedServer(nil)
	beaconURL := "http://" + srv.Listener.Addr().String() + "/token"

	page := fmt.Sprintf(`<!doctype html><meta charset="utf-8">
<script nonce="testnonce">fetch(%q + '?t=viafetch');</script>`, beaconURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", protonCaptchaCSP)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	mux.Handle("/token", captchaHandler(reached))

	srv.Config.Handler = mux
	srv.Start()
	defer srv.Close()

	runChrome(t, chrome, srv.URL)

	select {
	case got := <-reached:
		t.Fatalf("connect-src no longer blocks a fetch to loopback (got %q)", got)
	case <-time.After(2 * time.Second):
	}
}
