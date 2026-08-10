package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testToken = "sVL8xLGm-tok:03AFcWeA-solved"

func TestCaptchaHandlerCollectsToken(t *testing.T) {
	tokens := make(chan string, 1)
	srv := httptest.NewServer(captchaHandler(tokens))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/token?t=" + url.QueryEscape(testToken))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		t.Errorf("got status %v, want %v", res.StatusCode, http.StatusNoContent)
	}

	select {
	case got := <-tokens:
		if got != testToken {
			t.Errorf("got token %q, want %q", got, testToken)
		}
	default:
		t.Fatal("no token was delivered")
	}
}

// The browser may report more than once, and nothing is reading the channel
// after the first result, so later reports must not wedge the handler.
func TestCaptchaHandlerSecondTokenDoesNotBlock(t *testing.T) {
	tokens := make(chan string, 1)
	srv := httptest.NewServer(captchaHandler(tokens))
	defer srv.Close()

	for i := range 3 {
		res, err := http.Get(srv.URL + "/token?t=tok")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("report %v: got status %v", i, res.StatusCode)
		}
	}
}

func TestCaptchaHandlerRejectsEmptyToken(t *testing.T) {
	srv := httptest.NewServer(captchaHandler(make(chan string, 1)))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("got status %v, want %v", res.StatusCode, http.StatusBadRequest)
	}
}

// The snippet is pasted verbatim into a browser console, so the beacon address
// has to end up in it intact.
func TestCaptchaSnippetCarriesBeaconURL(t *testing.T) {
	const beacon = "http://127.0.0.1:33505/token"

	snippet := strings.ReplaceAll(captchaSnippet, "%v", beacon)
	if !strings.Contains(snippet, "'"+beacon+"?t=' + encodeURIComponent(e.data.token)") {
		t.Errorf("beacon address missing from the snippet:\n%v", snippet)
	}
	if strings.Contains(snippet, "%v") {
		t.Errorf("unfilled placeholder left in the snippet:\n%v", snippet)
	}
}
