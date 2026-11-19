package signintest

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/memstore"
)

func newApp(t *testing.T, owner bool) http.Handler {
	t.Helper()
	seal, err := signin.NewSealer(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := signin.Open(signin.Config{Domain: "alpha", Store: memstore.New(), Seal: seal, Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	mux := http.NewServeMux()
	mux.Handle(signin.APIPrefix, auth.Handler())
	mux.Handle(signin.BrowserPrefix, auth.Handler())
	return auth.Guard(mux)
}

func TestThePackagePassesItsOwnContract(t *testing.T) {
	Run(t, newApp(t, true), Options{Password: "a good long password"})
	Run(t, newApp(t, false), Options{Password: "a good long password", Name: "admin"})
}

func TestRunNoticesAnAppThatBreaksTheContract(t *testing.T) {
	app := newApp(t, true)
	broken := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/me") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"via": "nowhere"}`))
			return
		}
		r.Header.Del("Sec-Fetch-Site")
		app.ServeHTTP(w, r)
	})
	issues := check(broken, Options{Password: "a good long password"})
	joined := strings.Join(issues, "\n")
	for _, want := range []string{"GET me does not match Me", "POST logout from another site"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Run did not notice %q in:\n%s", want, joined)
		}
	}
}
