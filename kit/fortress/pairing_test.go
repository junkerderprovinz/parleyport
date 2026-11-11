package fortress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/lan"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// inPairing waits until a and b, two instances of one app, approved each other in
// their pairing.
func inPairing(t *testing.T, a, b *node) {
	t.Helper()
	waitFor(t, "the pairing to follow the fortress", func() bool {
		pa, _ := pairedWith(a.f.Pairing(), b.id)
		pb, _ := pairedWith(b.f.Pairing(), a.id)
		return pa.State == group.StateApproved && pb.State == group.StateApproved
	})
}

func TestThePairingRunsOnTheAppsOwnSettings(t *testing.T) {
	url := relayServer(t)
	var changes atomic.Int32
	own := group.Config{
		Kinds:               []member.Kind{member.KindInstance},
		MaxRelayAnswerBytes: 6 << 20,
		OnChange:            func() { changes.Add(1) },
	}
	a := open(t, "alpha", "alpha-1", setup{relay: url, pairing: own})
	b := open(t, "alpha", "alpha-2", setup{relay: url, pairing: own})
	meet(t, a, b)
	inPairing(t, a, b)

	if changes.Load() == 0 {
		t.Error("the pairing never told the app it changed")
	}
	const size = 5 << 20
	if status, body, err := a.f.Pairing().Call(ctx(t), b.id, http.MethodGet, "/api/big/"+strconv.Itoa(size), nil); err != nil || status != http.StatusOK || len(body) != size {
		t.Errorf("a relayed answer of %d bytes in the pairing = %d, %d bytes, %v", size, status, len(body), err)
	}

	phone, err := member.FromSeed(member.KindMobile, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	app := keys.Domain("alpha")
	c, err := relay.NewClient(relay.ClientOptions{
		URL:      url,
		Key:      app.GroupKey(testSecret),
		FrameKey: app.FrameKey(testSecret),
		Signing:  app.Signing(),
		Self:     relay.Announce{Name: "phone", Deployment: string(member.KindMobile), Client: true, Member: phone.ID()},
		Identity: &phone,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	t.Cleanup(func() { _ = c.Close() })
	waitFor(t, "the phone on the relay", func() bool { return c.Connected() && len(c.Siblings()) > 0 })
	body, status, err := c.Proxy(ctx(t), a.id, http.MethodGet, "/api/whoami", nil)
	if err != nil || status != http.StatusForbidden || !strings.Contains(string(body), "memberKindRefused") {
		t.Errorf("a phone calls a pairing that takes instances alone = %d %s %v", status, body, err)
	}
}

// taggedUnder is p as a member of the test fortress announces it now in the
// group of domain d.
func taggedUnder(d keys.Domain, p lan.Peer) lan.Peer {
	p.Sent = time.Now().Unix()
	mac := hmac.New(sha256.New, d.Keys(testSecret).PeerAuth)
	mac.Write([]byte("announce\x00" + p.ID + "\x00" + p.URL + "\x00" + p.Name + "\x00" + p.Deployment + "\x00" + p.Address + "\x00" + strconv.FormatInt(p.Sent, 10)))
	p.Tag = hex.EncodeToString(mac.Sum(nil))
	return p
}

func TestThePairingStreamsAndTakesUploadsOnTheNetwork(t *testing.T) {
	data := backupOf(3<<20 + 99)
	var uploaded atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /backup", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /restore", func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, data) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		uploaded.Add(1)
	})
	own := group.Config{Stream: mux, Upload: mux}

	fa, fb, pa, pb := lan.New(lan.Config{}), lan.New(lan.Config{}), lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = fa.Close(); _ = fb.Close(); _ = pa.Close(); _ = pb.Close() })
	a := open(t, "alpha", "alpha-1", setup{lan: fa, pairLAN: pa, pairing: own})
	b := open(t, "alpha", "alpha-2", setup{lan: fb, pairLAN: pb, pairing: own})
	for _, s := range []struct {
		fortress, pairing *lan.Service
		to                *node
	}{{fa, pa, b}, {fb, pb, a}} {
		peer := lan.Peer{ID: s.to.id, Name: s.to.name, URL: s.to.srv.URL, Deployment: "container"}
		s.fortress.Observe(tagged(peer))
		s.pairing.Observe(taggedUnder("alpha", peer))
	}
	meet(t, a, b)
	inPairing(t, a, b)

	status, body, err := a.f.Pairing().Stream(ctx(t), b.id, "/backup")
	if err != nil || status != http.StatusOK {
		t.Fatalf("a stream in the pairing = %d %v", status, err)
	}
	got, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("the stream brought %d of %d bytes, %v", len(got), len(data), err)
	}
	status, _, err = a.f.Pairing().Upload(ctx(t), b.id, "/restore", bytes.NewReader(data), int64(len(data)))
	if err != nil || status != http.StatusOK || uploaded.Load() != 1 {
		t.Errorf("an upload in the pairing = %d %v, taken %d times", status, err, uploaded.Load())
	}
}

func TestThePairingTakesTheAppsPortsAndAnswerSizes(t *testing.T) {
	n := &node{name: "alpha-1", app: "alpha", store: &memStore{}, pairStore: &memStore{}}
	cfg := config(t, n, setup{maxAnswer: 12 << 20, maxRelay: 5 << 20, pairing: group.Config{Ports: []int{8749}, MaxAnswerBytes: 32 << 20}})
	got := pairingConfig(cfg)
	if !slices.Equal(got.Ports, []int{8749}) || got.MaxAnswerBytes != 32<<20 || got.MaxRelayAnswerBytes != 5<<20 {
		t.Errorf("the pairing runs on ports %v with answers of %d and %d bytes", got.Ports, got.MaxAnswerBytes, got.MaxRelayAnswerBytes)
	}
	if got.Domain != "alpha" || !bytes.Equal(got.Secret, testSecret) || got.Self.Name != "alpha-1" {
		t.Errorf("the pairing runs as %q under another secret or as %q", got.Domain, got.Self.Name)
	}
}

func TestAPairingCannotSetWhatTheFortressDecides(t *testing.T) {
	for name, spoil := range map[string]func(*group.Config){
		"domain":         func(c *group.Config) { c.Domain = "bravo" },
		"secret":         func(c *group.Config) { c.Secret = []byte("another phrase..") },
		"keys":           func(c *group.Config) { c.Keys = keys.Domain("alpha").Keys(testSecret) },
		"join by phrase": func(c *group.Config) { c.JoinByPhrase = true },
		"self":           func(c *group.Config) { c.Self = group.Self{Name: "elsewhere"} },
		"relay":          func(c *group.Config) { c.Relay = group.RelayOwn },
		"relay address":  func(c *group.Config) { c.RelayURL = "https://relay.example" },
		"on removed":     func(c *group.Config) { c.OnRemoved = func() {} },
		"on remove":      func(c *group.Config) { c.OnRemove = func(string) {} },
		"vouch":          func(c *group.Config) { c.Vouch = func(string, ed25519.PublicKey) bool { return true } },
		"no store":       func(c *group.Config) { c.Store = nil },
	} {
		t.Run(name, func(t *testing.T) {
			n := &node{name: "alpha-1", app: "alpha", store: &memStore{}, pairStore: &memStore{}}
			cfg := config(t, n, setup{})
			spoil(&cfg.Pairing.Group)
			if f, err := Open(cfg); err == nil {
				_ = f.Close()
				t.Error("the fortress opened")
			}
		})
	}
}

func TestAPairingWithoutAStreamSendsNone(t *testing.T) {
	fa, fb, pa, pb := lan.New(lan.Config{}), lan.New(lan.Config{}), lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = fa.Close(); _ = fb.Close(); _ = pa.Close(); _ = pb.Close() })
	a := open(t, "alpha", "alpha-1", setup{lan: fa, pairLAN: pa})
	b := open(t, "alpha", "alpha-2", setup{lan: fb, pairLAN: pb})
	for _, s := range []struct {
		fortress, pairing *lan.Service
		to                *node
	}{{fa, pa, b}, {fb, pb, a}} {
		peer := lan.Peer{ID: s.to.id, Name: s.to.name, URL: s.to.srv.URL, Deployment: "container"}
		s.fortress.Observe(tagged(peer))
		s.pairing.Observe(taggedUnder("alpha", peer))
	}
	meet(t, a, b)
	inPairing(t, a, b)
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if status, _, err := a.f.Pairing().Stream(c, b.id, "/backup"); err != nil || status != http.StatusNotFound {
		t.Errorf("a stream from a pairing that sends none = %d %v, want 404", status, err)
	}
}
