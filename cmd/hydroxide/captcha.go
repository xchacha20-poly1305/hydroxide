package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// captchaBeaconTimeout bounds how long we wait for the browser to report the
// solved challenge before falling back to asking for it by hand.
const captchaBeaconTimeout = 5 * time.Minute

// captchaSnippet is pasted into the browser console on the challenge page. It
// catches the message the page emits once solved and reports the token back.
//
// The report goes out as an image request rather than a fetch on purpose: the
// challenge page is served under a Content-Security-Policy of
//
//	connect-src https: wss:; img-src http: https: data: blob: cid:
//
// so a fetch to a loopback address is refused while an image request to one is
// not. The prompt is a fallback for when even that is blocked, and comes second
// so the report is already on its way before the dialog blocks the page.
const captchaSnippet = `addEventListener('message', e => {
  if (!e.data || e.data.type !== 'pm_captcha') return;
  new Image().src = '%v?t=' + encodeURIComponent(e.data.token);
  prompt('hydroxide token (only needed if your terminal has not continued)', e.data.token);
});`

// solveCaptcha walks the user through the CAPTCHA challenge at captchaURL and
// returns the verification token it yields.
//
// The challenge cannot be embedded in a page we serve: every host that runs it
// correctly restricts framing to its own sibling app origin, and the one host
// that permits framing serves neither the challenge assets nor a usable session
// cookie. So it is opened top-level, where the page ends up posting its result
// to itself, and a listener pasted into the console forwards it to us.
func solveCaptcha(captchaURL string) (string, error) {
	// Bind to the loopback interface only: this is a one-shot channel for the
	// browser on this machine, not something to expose to the network.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to listen for the verification result: %v", err)
	}
	defer ln.Close()

	tokens := make(chan string, 1)

	srv := &http.Server{Handler: captchaHandler(tokens)}
	defer srv.Close()
	go srv.Serve(ln)

	beaconURL := (&url.URL{Scheme: "http", Host: ln.Addr().String(), Path: "/token"}).String()

	fmt.Fprintf(os.Stderr, "\nProton is asking for a CAPTCHA before it will accept this login.\n\n")
	fmt.Fprintf(os.Stderr, "1. Open this address in a browser:\n\n     %v\n\n", captchaURL)
	fmt.Fprintf(os.Stderr, "2. Open the developer console (F12) and paste:\n\n%v\n\n",
		indent(fmt.Sprintf(captchaSnippet, beaconURL), "     "))
	fmt.Fprintf(os.Stderr, "3. Solve the CAPTCHA. hydroxide continues on its own.\n\n")

	select {
	case token := <-tokens:
		fmt.Fprintf(os.Stderr, "Verification solved.\n\n")
		return token, nil

	case <-time.After(captchaBeaconTimeout):
		// The browser never reached us — an extension or a proxy may have
		// eaten the request. The dialog on the page still has the token.
		fmt.Fprintf(os.Stderr, "No result received automatically.\n")
		return askLine("Verification token")
	}
}

// captchaHandler accepts the solved verification token from the browser and
// hands it to tokens.
func captchaHandler(tokens chan<- string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("t")
		if token == "" {
			http.Error(w, "no token in the request", http.StatusBadRequest)
			return
		}

		select {
		case tokens <- token:
		default:
			// Already solved; nothing more to do.
		}

		// The response is never rendered — the image is not in a document.
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}
