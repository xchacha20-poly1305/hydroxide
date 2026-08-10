package protonmail

import (
	"encoding/json"
	"testing"
)

func TestHumanVerificationDetails(t *testing.T) {
	const body = `{
		"Code": 9001,
		"Error": "For security reasons, please complete CAPTCHA.",
		"Details": {
			"HumanVerificationMethods": ["captcha", "email"],
			"HumanVerificationToken": "sVL8xLGm-tok"
		}
	}`

	var r resp
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	err, ok := r.Err().(*APIError)
	if !ok {
		t.Fatalf("expected an *APIError, got %T", r.Err())
	}
	if err.Code != CodeHumanVerificationRequired {
		t.Errorf("got code %v, want %v", err.Code, CodeHumanVerificationRequired)
	}

	token, methods, ok := err.HumanVerification()
	if !ok {
		t.Fatal("expected a human verification challenge")
	}
	if token != "sVL8xLGm-tok" {
		t.Errorf("got token %q", token)
	}
	if len(methods) != 2 || methods[0] != HumanVerificationCaptcha || methods[1] != HumanVerificationEmail {
		t.Errorf("got methods %v", methods)
	}
}

// Details is not an object for every error, and a successful response may carry
// one without an Error at all. Neither should be mistaken for a challenge.
func TestHumanVerificationIgnoresUnrelatedDetails(t *testing.T) {
	for name, body := range map[string]string{
		"empty details":    `{"Code": 2001, "Error": "Invalid input", "Details": {}}`,
		"details is array": `{"Code": 2001, "Error": "Invalid input", "Details": ["nope"]}`,
		"wrong code":       `{"Code": 2001, "Error": "Invalid input", "Details": {"HumanVerificationToken": "t"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var r resp
			if err := json.Unmarshal([]byte(body), &r); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if _, _, ok := r.Err().(*APIError).HumanVerification(); ok {
				t.Error("expected no human verification challenge")
			}
		})
	}

	t.Run("no error", func(t *testing.T) {
		var r resp
		if err := json.Unmarshal([]byte(`{"Code": 1000, "Details": {}}`), &r); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if err := r.Err(); err != nil {
			t.Errorf("expected a successful response, got %v", err)
		}
	})
}

// The CAPTCHA host is independent of RootURL, because the host the rest of the
// API is spoken to serves the challenge page under a CSP that stops it running.
func TestCaptchaURL(t *testing.T) {
	c := &Client{RootURL: "https://mail.proton.me/api"}

	got := c.CaptchaURL("sVL8xLGm-tok")
	want := DefaultCaptchaRootURL + "/core/v4/captcha?ForceWebMessaging=1&Token=sVL8xLGm-tok"
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCaptchaURLOverride(t *testing.T) {
	c := &Client{
		RootURL:        "https://mail.proton.me/api",
		CaptchaRootURL: "https://verify-api.proton.me",
	}

	got := c.CaptchaURL("sVL8xLGm-tok")
	want := "https://verify-api.proton.me/core/v4/captcha?ForceWebMessaging=1&Token=sVL8xLGm-tok"
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
