package group

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// backupOf is the n bytes the test app streams as its backup.
func backupOf(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(b)
	return b
}

// streamRoutes answer stream calls: a backup of any size, one that says it is
// longer or shorter than it turns out, a refusal, and a 200 without a length.
func streamRoutes(served *atomic.Int32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /backup/{n}", func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		n, _ := strconv.Atoi(r.PathValue("n"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = w.Write(backupOf(n))
	})
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		c, _ := CallerOf(r.Context())
		w.Header().Set("Content-Length", strconv.Itoa(len(c.ID)))
		_, _ = io.WriteString(w, c.ID)
	})
	mux.HandleFunc("GET /short", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write(make([]byte, 500))
	})
	mux.HandleFunc("GET /long", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "500")
		_, _ = w.Write(make([]byte, 1000))
	})
	mux.HandleFunc("GET /refuse", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"busy_backing_up"}`))
	})
	mux.HandleFunc("GET /unmeasured", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("no length"))
	})
	return mux
}

// streamingPair opens alpha and bravo on one network, bravo answering stream
// calls. Alpha finds bravo at the address via returns, given bravo's own.
func streamingPair(t *testing.T, via func(string) string) (a, b *node, served *atomic.Int32) {
	t.Helper()
	served = &atomic.Int32{}
	la, lb := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close(); _ = lb.Close() })
	a = open(t, "alpha", setup{lan: la})
	b = open(t, "bravo", setup{lan: lb, stream: streamRoutes(served)})
	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: via(b.srv.URL), Deployment: "container"}))
	lb.Observe(tagged(b.g, lan.Peer{ID: a.id, Name: "alpha", URL: a.srv.URL, Deployment: "container"}))
	meet(t, a, b)
	return a, b, served
}

func unchanged(u string) string { return u }

func stream(t *testing.T, from, to *node, path string) (int, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status, body, err := from.g.Stream(ctx, to.id, path)
	if err != nil {
		return status, nil, err
	}
	defer func() { _ = body.Close() }()
	out, err := io.ReadAll(body)
	return status, out, err
}

func TestAStreamLargerThanAnyAnswerArrivesWhole(t *testing.T) {
	a, b, _ := streamingPair(t, unchanged)
	const size = 9<<20 + 12345
	status, got, err := stream(t, a, b, "/backup/"+strconv.Itoa(size))
	if err != nil || status != http.StatusOK || !bytes.Equal(got, backupOf(size)) {
		t.Fatalf("a stream of %d bytes = %d, %d bytes, %v", size, status, len(got), err)
	}
	status, got, err = stream(t, a, b, "/backup/0")
	if err != nil || status != http.StatusOK || len(got) != 0 {
		t.Errorf("an empty stream = %d, %d bytes, %v", status, len(got), err)
	}
}

func TestAStreamSeesItsCaller(t *testing.T) {
	a, b, _ := streamingPair(t, unchanged)
	if _, got, err := stream(t, a, b, "/whoami"); err != nil || string(got) != a.id {
		t.Errorf("bravo's stream saw %q, %v, want alpha", got, err)
	}
}

func TestAStreamRefusalComesBackAsTheAppGaveIt(t *testing.T) {
	a, b, _ := streamingPair(t, unchanged)
	status, got, err := stream(t, a, b, "/refuse")
	if err != nil || status != http.StatusConflict || string(got) != `{"error":"busy_backing_up"}` {
		t.Errorf("a refused stream = %d %q %v", status, got, err)
	}
}

func TestAStreamThatBreaksItsLengthFails(t *testing.T) {
	a, b, _ := streamingPair(t, unchanged)
	for _, path := range []string{"/short", "/long"} {
		if _, _, err := stream(t, a, b, path); !errors.Is(err, ErrStreamBroken) {
			t.Errorf("%s: %v, want ErrStreamBroken", path, err)
		}
	}
	if status, body, err := stream(t, a, b, "/unmeasured"); err != nil || status != http.StatusInternalServerError || !bytes.Contains(body, []byte("streamLength")) {
		t.Errorf("a stream without a length = %d %q %v, want streamLength", status, body, err)
	}
}

// tampering is a proxy in front of a member that hands on every answer but
// passes a stream through damage.
func tampering(t *testing.T, damage func([]byte) []byte) func(string) string {
	return func(target string) string {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ModifyResponse = func(r *http.Response) error {
			if r.Header.Get("Content-Type") != streamType {
				return nil
			}
			raw, err := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				return err
			}
			r.Body = io.NopCloser(bytes.NewReader(damage(raw)))
			r.ContentLength = -1
			r.Header.Del("Content-Length")
			return nil
		}
		srv := httptest.NewServer(proxy)
		t.Cleanup(srv.Close)
		return srv.URL
	}
}

func TestADamagedStreamFails(t *testing.T) {
	const size = 1 << 20
	for name, damage := range map[string]func([]byte) []byte{
		"a flipped bit": func(b []byte) []byte {
			b[len(b)/2] ^= 0x01
			return b
		},
		"cut in the middle":    func(b []byte) []byte { return b[:len(b)/2] },
		"cut by its last byte": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			a, b, _ := streamingPair(t, tampering(t, damage))
			status, got, err := stream(t, a, b, "/backup/"+strconv.Itoa(size))
			if !errors.Is(err, ErrStreamBroken) {
				t.Fatalf("a damaged stream = %d, %d bytes, %v, want ErrStreamBroken", status, len(got), err)
			}
		})
	}
	t.Run("cut in its head", func(t *testing.T) {
		a, b, _ := streamingPair(t, tampering(t, func(b []byte) []byte { return b[:100] }))
		if _, _, err := stream(t, a, b, "/backup/"+strconv.Itoa(size)); err == nil {
			t.Fatal("a stream cut in its head read as good")
		}
	})
}

func TestAStreamGoesOnlyDirectly(t *testing.T) {
	url := relayServer(t)
	var served atomic.Int32
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, stream: streamRoutes(&served)})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	meet(t, a, b)
	if _, _, err := stream(t, a, b, "/backup/10"); !errors.Is(err, ErrNotDirect) {
		t.Errorf("a stream from a member on the relay alone: %v, want ErrNotDirect", err)
	}
	// An older or hostile caller may send the call through the relay all the
	// same.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, status, err := a.g.client.Proxy(ctx, b.id, http.MethodGet, streamPrefix+"/backup/10", nil)
	if err != nil || status != http.StatusMisdirectedRequest || !bytes.Contains(body, []byte("streamDirectOnly")) {
		t.Errorf("a stream call through the relay = %d %s %v, want 421", status, body, err)
	}
	if n := served.Load(); n != 0 {
		t.Errorf("bravo streamed %d times through the relay", n)
	}
}

func TestAnInstanceWithoutStreamsSaysSo(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	meet(t, a, b)
	if status, _, err := stream(t, a, b, "/backup/10"); err != nil || status != http.StatusNotFound {
		t.Errorf("a stream from an instance that takes none = %d %v, want 404", status, err)
	}
}
