package protonmail

import (
	"fmt"
	"net/http"
	"net/url"
)

// Human verification methods, as returned in the HumanVerificationMethods list
// of a CodeHumanVerificationRequired error.
const (
	HumanVerificationCaptcha = "captcha"
	HumanVerificationEmail   = "email"
	HumanVerificationSMS     = "sms"
)

// DefaultCaptchaRootURL is the API host CAPTCHA challenges are fetched from.
//
// This is deliberately not RootURL. Every host serves the same challenge page,
// but only some serve one that runs:
//
//   - mail.proton.me/api and account.proton.me send a Content-Security-Policy
//     whose script-src carries a fixed hash and omits the very nonce the page's
//     own inline script is tagged with, so the browser refuses to run it and no
//     CAPTCHA ever appears.
//   - api.protonmail.ch sends a matching nonce, but sits outside proton.me, so
//     the session cookie the page sets for Domain=proton.me is rejected, and it
//     does not host the challenge assets either.
//
// That leaves the per-app API hosts, which send a matching nonce and a cookie
// for a domain they belong to. They restrict framing to their own sibling app
// origin, so the page has to be opened top-level rather than embedded.
const DefaultCaptchaRootURL = "https://mail-api.proton.me"

// CaptchaURL returns the address of the CAPTCHA challenge page for a
// verification token obtained from a CodeHumanVerificationRequired error.
//
// The page has to be loaded in a browser. Once solved, it hands the resulting
// verification token to its parent window as a message of the form
//
//	{"type": "pm_captcha", "token": "<verification token>"}
//
// and that token is what SetHumanVerification expects. It also reports the
// height it wants as {"type": "pm_height", "height": <pixels>}, and announces
// a challenge that went stale as {"type": "pm_captcha_expired"}.
func (c *Client) CaptchaURL(token string) string {
	root := c.CaptchaRootURL
	if root == "" {
		root = DefaultCaptchaRootURL
	}

	v := make(url.Values)
	v.Set("Token", token)
	// Ask for browser-style message passing rather than the native app hooks
	// the page otherwise sniffs for.
	v.Set("ForceWebMessaging", "1")

	return root + "/core/v4/captcha?" + v.Encode()
}

type verificationCodeReq struct {
	Type        string
	Destination verificationCodeDestination
}

type verificationCodeDestination struct {
	Address string `json:",omitempty"`
	Phone   string `json:",omitempty"`
}

// RequestVerificationCode asks the API to send a verification code to
// destination, which is an email address for HumanVerificationEmail and a
// phone number for HumanVerificationSMS.
//
// The code that arrives forms the verification token together with the
// destination it was sent to, as "<destination>:<code>".
func (c *Client) RequestVerificationCode(method, destination string) error {
	reqData := &verificationCodeReq{Type: method}

	switch method {
	case HumanVerificationEmail:
		reqData.Destination.Address = destination
	case HumanVerificationSMS:
		reqData.Destination.Phone = destination
	default:
		return fmt.Errorf("cannot request a verification code for method %q", method)
	}

	req, err := c.newJSONRequest(http.MethodPost, "/users/code", reqData)
	if err != nil {
		return err
	}

	return c.doJSON(req, nil)
}
