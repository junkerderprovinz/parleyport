package group

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// The tag and the signature are checked against values worked out apart from
// this code, so an instance on the kit and one on an older release still take
// each other's announces and direct calls.
func TestTheDirectFormatMatchesTheReference(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	p := lan.Peer{ID: string(bytes.Repeat([]byte("a"), 40)), URL: "https://192.168.1.10:3443", Name: "Cellar",
		Deployment: "container", Address: "https://cellar.example", Sent: 1700000000}
	if got := announceTag(key, p); got != "b08252555d4a14488e301996a366346c61b8e34b4d95b2e36c3d0575d665b64a" {
		t.Errorf("announce tag = %s", got)
	}
	sig := directSignature(key, string(bytes.Repeat([]byte("b"), 40)), "1700000000", []byte(`{"requestId":"r"}`))
	if sig != "7a1e6ef8901f5d1f30de94c440f1164f2e2c00b83343da3685ff2eac1427032b" {
		t.Errorf("direct signature = %s", sig)
	}
	h := headersFor(keys.Domain("alpha-beta"))
	if h.peer != "X-Alpha-Beta-Peer" || h.target != "X-Alpha-Beta-Target" || h.time != "X-Alpha-Beta-Time" || h.signature != "X-Alpha-Beta-Signature" {
		t.Errorf("headers = %+v", h)
	}
}

// onOneNetwork opens two instances whose multicast announces are handed over
// by the test, with no relay between them.
func onOneNetwork(t *testing.T, s setup) (a, b *node) {
	t.Helper()
	la, lb := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close(); _ = lb.Close() })
	sa, sb := s, s
	sa.lan, sb.lan = la, lb
	a = open(t, "alpha", sa)
	b = open(t, "bravo", sb)
	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: b.srv.URL, Deployment: "container"}))
	lb.Observe(tagged(b.g, lan.Peer{ID: a.id, Name: "alpha", URL: a.srv.URL, Deployment: "container"}))
	return a, b
}

func TestAMemberOnTheNetworkIsCalledDirectly(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	meet(t, a, b)
	if id := whoami(t, a, b); id != a.id {
		t.Errorf("bravo's app saw %q, want alpha", id)
	}
	if m, _ := memberOf(a.g, b.id); !m.Direct || m.Relay || m.State != StateApproved {
		t.Errorf("alpha lists %+v", m)
	}
}

func TestADirectAnswerMayBeAsLargeAsTheAppAllows(t *testing.T) {
	sizes := func(t *testing.T, a, b *node, fits, tooLarge int) {
		t.Helper()
		status, body, err := call(t, a, b, http.MethodGet, "/api/size/"+strconv.Itoa(fits), nil)
		if err != nil || status != http.StatusOK || len(body) != fits {
			t.Errorf("an answer of %d bytes = %d, %d bytes, %v", fits, status, len(body), err)
		}
		status, body, err = call(t, a, b, http.MethodGet, "/api/size/"+strconv.Itoa(tooLarge), nil)
		if err != nil || status != http.StatusInternalServerError || !bytes.Contains(body, []byte("answerTooLarge")) {
			t.Errorf("an answer of %d bytes = %d %.80q %v, want answerTooLarge", tooLarge, status, body, err)
		}
	}
	t.Run("by default", func(t *testing.T) {
		a, b := onOneNetwork(t, setup{})
		meet(t, a, b)
		sizes(t, a, b, maxAnswerBytes, maxAnswerBytes+1)
	})
	t.Run("set larger", func(t *testing.T) {
		a, b := onOneNetwork(t, setup{maxAnswer: 6 << 20})
		meet(t, a, b)
		sizes(t, a, b, 6<<20, 6<<20+1)
	})
}

func TestARelayedAnswerStaysWithinARelayFrame(t *testing.T) {
	url := relayServer(t)
	a := open(t, "alpha", setup{relay: url, maxAnswer: 6 << 20})
	b := open(t, "bravo", setup{relay: url, maxAnswer: 6 << 20})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	meet(t, a, b)
	status, body, err := call(t, a, b, http.MethodGet, "/api/size/"+strconv.Itoa(maxAnswerBytes+1), nil)
	if err != nil || status != http.StatusInternalServerError || !bytes.Contains(body, []byte("answerTooLarge")) {
		t.Errorf("a relayed answer past a frame = %d %.80q %v, want answerTooLarge", status, body, err)
	}
	if !a.g.RelayConnected() || !b.g.RelayConnected() {
		t.Error("the large answer cost an instance its relay connection")
	}
}

func TestARelayedAnswerMayBeAsLargeAsTheAppAllows(t *testing.T) {
	sizes := func(t *testing.T, s setup, fits int) {
		t.Helper()
		s.relay = relayServer(t)
		a, b := open(t, "alpha", s), open(t, "bravo", s)
		waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
		meet(t, a, b)
		// No deadline of its own: how long a large answer takes depends on the
		// machine, and the relay client stops waiting once nothing comes in.
		size := func(n int) (int, []byte, error) {
			return a.g.Call(context.Background(), b.id, http.MethodGet, "/api/size/"+strconv.Itoa(n), nil)
		}
		status, body, err := size(fits)
		if err != nil || status != http.StatusOK || len(body) != fits {
			t.Errorf("a relayed answer of %d bytes = %d, %d bytes, %v", fits, status, len(body), err)
		}
		status, body, err = size(fits + 1)
		if err != nil || status != http.StatusInternalServerError || !bytes.Contains(body, []byte("answerTooLarge")) {
			t.Errorf("a relayed answer of %d bytes = %d %.80q %v, want answerTooLarge", fits+1, status, body, err)
		}
		if !a.g.RelayConnected() || !b.g.RelayConnected() {
			t.Error("a large answer cost an instance its relay connection")
		}
	}
	t.Run("set larger", func(t *testing.T) {
		sizes(t, setup{maxRelay: 4<<20 + 256<<10}, 4<<20+256<<10)
	})
	t.Run("set to 8 MiB", func(t *testing.T) {
		sizes(t, setup{maxRelay: 8 << 20}, 8<<20)
	})
	t.Run("set past what a frame carries", func(t *testing.T) {
		sizes(t, setup{maxRelay: 32 << 20}, relay.MaxAnswerBytes)
	})
}

func TestAnAnnounceWithoutThePhraseIsNoMember(t *testing.T) {
	la := lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close() })
	a := open(t, "alpha", setup{lan: la})
	p := lan.Peer{ID: identity(t, "eve").ID(), URL: "http://192.168.1.66:3443", Sent: time.Now().Unix()}
	p.Tag = announceTag(testDomain.PeerAuthKey([]byte("another phrase..")), p)
	la.Observe(p)
	if _, listed := memberOf(a.g, p.ID); listed {
		t.Error("an announce tagged under another phrase made a member")
	}
	old := tagged(a.g, lan.Peer{ID: p.ID, URL: p.URL})
	old.Sent -= int64(2 * relay.ClockSkew / time.Second)
	old.Tag = announceTag(a.g.peerAuth, old)
	la.Observe(old)
	if _, listed := memberOf(a.g, p.ID); listed {
		t.Error("an announce played back long after it was sent made a member")
	}
}

// direct builds the direct request from to b for path, signed and sealed.
func direct(t *testing.T, from, to *node, path string) (*http.Request, []byte) {
	t.Helper()
	req, _, _, err := from.g.newDirectRequest(context.Background(), to.srv.URL, to.id, relay.ProxyCall{Method: http.MethodGet, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return req, body
}

func serveDirect(g *Group, req *http.Request, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(req.Method, DirectPath, bytes.NewReader(body))
	r.Header = req.Header.Clone()
	w := httptest.NewRecorder()
	g.DirectHandler().ServeHTTP(w, r)
	return w
}

func TestTheDirectRouteRefusesWhatNoMemberSends(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	h := headersFor(testDomain)
	cases := map[string]func(r *http.Request, body []byte) []byte{
		"wrong target": func(r *http.Request, body []byte) []byte { r.Header.Set(h.target, a.id); return body },
		"no sender":    func(r *http.Request, body []byte) []byte { r.Header.Del(h.peer); return body },
		"bad time":     func(r *http.Request, body []byte) []byte { r.Header.Set(h.time, "soon"); return body },
		"stale": func(r *http.Request, body []byte) []byte {
			r.Header.Set(h.time, strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
			return body
		},
		"forged signature": func(r *http.Request, body []byte) []byte {
			r.Header.Set(h.signature, directSignature(make([]byte, 32), a.id, r.Header.Get(h.time), body))
			return body
		},
		"changed body": func(_ *http.Request, body []byte) []byte {
			return bytes.Replace(body, []byte(`"requestId":"`), []byte(`"requestId":"x`), 1)
		},
		"not json": func(r *http.Request, _ []byte) []byte { return signedBody(a, r, []byte("hello")) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			req, body := direct(t, a, b, "/api/whoami")
			body = change(req, body)
			if w := serveDirect(b.g, req, body); w.Code != http.StatusForbidden {
				t.Errorf("= %d %s, want 403", w.Code, w.Body)
			}
		})
	}
	t.Run("get", func(t *testing.T) {
		req, body := direct(t, a, b, "/api/whoami")
		req.Method = http.MethodGet
		if w := serveDirect(b.g, req, body); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("= %d, want 405", w.Code)
		}
	})
	t.Run("too large", func(t *testing.T) {
		req, _ := direct(t, a, b, "/api/whoami")
		big := make([]byte, maxDirectRequest+1)
		if w := serveDirect(b.g, req, signedBody(a, req, big)); w.Code != http.StatusForbidden {
			t.Errorf("= %d, want 403", w.Code)
		}
	})
	t.Run("replayed", func(t *testing.T) {
		req, body := direct(t, a, b, "/api/whoami")
		if w := serveDirect(b.g, req, body); w.Code != http.StatusOK {
			t.Fatalf("first = %d %s", w.Code, w.Body)
		}
		if w := serveDirect(b.g, req, body); w.Code != http.StatusForbidden {
			t.Errorf("again = %d, want 403", w.Code)
		}
	})
}

// signedBody signs body as from would, so a test reaches what comes after
// the signature check.
func signedBody(from *node, r *http.Request, body []byte) []byte {
	h := headersFor(testDomain)
	r.Header.Set(h.signature, directSignature(from.g.peerAuth, from.id, r.Header.Get(h.time), body))
	return body
}

func TestAClosedGroupAnswersLikeNoGroup(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	req, body := direct(t, a, b, "/api/whoami")
	_ = b.g.Close()
	if w := serveDirect(b.g, req, body); w.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404", w.Code)
	}
}

func TestTheSweepFindsAMemberMulticastMisses(t *testing.T) {
	la, lb := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close(); _ = lb.Close() })
	a := open(t, "alpha", setup{lan: la})
	b := open(t, "bravo", setup{lan: lb, ports: []int{testPort(t, a.srv.URL)}})

	a.g.sweepWith(context.Background(), []string{httpDeadAddress(t), b.srv.URL})
	if m, _ := memberOf(a.g, b.id); !m.Direct || m.Name != "bravo" {
		t.Errorf("alpha lists %+v after the sweep, want bravo on the network", m)
	}
	// The probe told bravo where alpha answers, so bravo needs no sweep.
	waitFor(t, "bravo to probe alpha back", func() bool { m, _ := memberOf(b.g, a.id); return m.Direct })

	meet(t, a, b)
	if id := whoami(t, b, a); id != b.id {
		t.Errorf("alpha's app saw %q, want bravo", id)
	}
}

func TestAProberIsProbedBackOnlyOnANearbyAddress(t *testing.T) {
	la := lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close() })
	a := open(t, "alpha", setup{})
	b := open(t, "bravo", setup{lan: la, ports: []int{testPort(t, a.srv.URL)}})
	port := strconv.Itoa(testPort(t, a.srv.URL))
	for _, named := range []string{
		"http://203.0.113.7:" + port,
		"http://localhost:" + port,
		"http://127.0.0.1:1",
		"ftp://127.0.0.1:" + port,
		"http://user@127.0.0.1:" + port,
	} {
		intro, _ := json.Marshal(probeIntro{URL: named})
		req, _, _, err := a.g.newDirectRequest(context.Background(), b.srv.URL, probeTarget, relay.ProxyCall{Method: http.MethodGet, Path: helloPath, Body: intro})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(req.Body)
		if w := serveDirect(b.g, req, body); w.Code != http.StatusOK {
			t.Fatalf("a probe naming %s = %d, want the hello", named, w.Code)
		}
		b.g.mu.Lock()
		kept := b.g.addrs[a.id]
		b.g.mu.Unlock()
		if kept != nil {
			t.Errorf("bravo kept %s, which a prober named, as alpha's address", kept.url)
		}
	}
	intro, _ := json.Marshal(probeIntro{URL: a.srv.URL})
	req, _, _, _ := a.g.newDirectRequest(context.Background(), b.srv.URL, probeTarget, relay.ProxyCall{Method: http.MethodGet, Path: helloPath, Body: intro})
	body, _ := io.ReadAll(req.Body)
	serveDirect(b.g, req, body)
	waitFor(t, "bravo to probe alpha back on its port", func() bool { m, _ := memberOf(b.g, a.id); return m.Direct })
}

func TestAProbeOnlyReachesTheHello(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	req, _, _, err := a.g.newDirectRequest(context.Background(), b.srv.URL, probeTarget, relay.ProxyCall{Method: http.MethodGet, Path: "/api/whoami"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if w := serveDirect(b.g, req, body); w.Code != http.StatusForbidden {
		t.Errorf("a probe for an app route = %d, want 403", w.Code)
	}
}

func TestTheLearnedAddressIsAnnouncedAndKept(t *testing.T) {
	a := open(t, "alpha", setup{})
	for _, host := range []string{"localhost:3443", "127.0.0.1:3443"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		a.g.NoteAddress(r)
	}
	if got := a.g.directURL(); got != a.srv.URL {
		t.Fatalf("direct address = %s after loopback requests, want the configured one", got)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host, r.TLS = "192.168.1.10:3443", &tls.ConnectionState{}
	a.g.NoteAddress(r)
	if got := a.g.directURL(); got != "https://192.168.1.10:3443" {
		t.Errorf("direct address = %s, want the one the browser used", got)
	}
	if err := a.g.Close(); err != nil {
		t.Fatal(err)
	}
	a.g = openGroup(t, a, setup{store: a.store})
	if got := a.g.directURL(); got != "https://192.168.1.10:3443" {
		t.Errorf("direct address after a restart = %s", got)
	}
}

func TestAnUnexpectedDirectStatusIsNoStranger(t *testing.T) {
	a := open(t, "alpha", setup{})
	b := identity(t, "bravo").ID()
	for status, stranger := range map[int]bool{
		http.StatusForbidden:            true,
		http.StatusNotFound:             true,
		http.StatusUnsupportedMediaType: false,
		http.StatusBadGateway:           false,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		_, err := a.g.callDirect(context.Background(), srv.URL, b, relay.ProxyCall{Method: http.MethodGet, Path: "/api/whoami"})
		srv.Close()
		var got *StatusError
		switch {
		case stranger && !errors.Is(err, ErrStranger):
			t.Errorf("HTTP %d: %v, want ErrStranger", status, err)
		case !stranger && (errors.Is(err, ErrStranger) || !errors.As(err, &got) || got.Status != status || !strings.Contains(err.Error(), strconv.Itoa(status))):
			t.Errorf("HTTP %d: %v, want a StatusError that names it", status, err)
		}
	}
}
