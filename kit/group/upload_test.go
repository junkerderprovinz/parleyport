package group

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/lan"
)

// keeper is an app that takes uploads: it keeps an upload only once it read
// the whole of it without an error.
type keeper struct {
	mu     sync.Mutex
	kept   [][]byte
	failed []error
	asked  atomic.Int32
}

func (k *keeper) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /restore", func(w http.ResponseWriter, r *http.Request) {
		k.asked.Add(1)
		got, err := io.ReadAll(r.Body)
		k.mu.Lock()
		defer k.mu.Unlock()
		if err != nil {
			k.failed = append(k.failed, err)
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"damaged"}`)
			return
		}
		if int64(len(got)) != r.ContentLength {
			k.failed = append(k.failed, errors.New("length differs"))
			w.WriteHeader(http.StatusConflict)
			return
		}
		k.kept = append(k.kept, got)
		sum := sha256.Sum256(got)
		_, _ = io.WriteString(w, hex.EncodeToString(sum[:]))
	})
	mux.HandleFunc("POST /whoami", func(w http.ResponseWriter, r *http.Request) {
		c, _ := CallerOf(r.Context())
		_, _ = io.WriteString(w, c.ID)
	})
	mux.HandleFunc("POST /refuse", func(w http.ResponseWriter, _ *http.Request) {
		k.asked.Add(1)
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":"busy_restoring"}`)
	})
	return mux
}

func (k *keeper) state() (kept [][]byte, failed []error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.kept, k.failed
}

// uploadingPair opens alpha and bravo on one network, bravo taking uploads.
// Alpha finds bravo at the address via returns, given bravo's own.
func uploadingPair(t *testing.T, via func(string) string) (a, b *node, k *keeper) {
	t.Helper()
	k = &keeper{}
	la, lb := lan.New(lan.Config{}), lan.New(lan.Config{})
	t.Cleanup(func() { _ = la.Close(); _ = lb.Close() })
	a = open(t, "alpha", setup{lan: la})
	b = open(t, "bravo", setup{lan: lb, upload: k.routes()})
	la.Observe(tagged(a.g, lan.Peer{ID: b.id, Name: "bravo", URL: via(b.srv.URL), Deployment: "container"}))
	lb.Observe(tagged(b.g, lan.Peer{ID: a.id, Name: "alpha", URL: a.srv.URL, Deployment: "container"}))
	meet(t, a, b)
	return a, b, k
}

func upload(t *testing.T, from, to *node, path string, body io.Reader, n int64) (int, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return from.g.Upload(ctx, to.id, path, body, n)
}

func TestAnUploadLargerThanAnyAnswerArrivesWhole(t *testing.T) {
	a, b, k := uploadingPair(t, unchanged)
	const size = 9<<20 + 12345
	data := backupOf(size)
	status, got, err := upload(t, a, b, "/restore", bytes.NewReader(data), size)
	sum := sha256.Sum256(data)
	if err != nil || status != http.StatusOK || string(got) != hex.EncodeToString(sum[:]) {
		t.Fatalf("an upload of %d bytes = %d %q %v", size, status, got, err)
	}
	if kept, _ := k.state(); len(kept) != 1 || !bytes.Equal(kept[0], data) {
		t.Errorf("bravo kept %d uploads", len(kept))
	}
	if status, _, err := upload(t, a, b, "/restore", bytes.NewReader(nil), 0); err != nil || status != http.StatusOK {
		t.Errorf("an empty upload = %d %v", status, err)
	}
}

func TestAnUploadSeesItsCaller(t *testing.T) {
	a, b, _ := uploadingPair(t, unchanged)
	if _, got, err := upload(t, a, b, "/whoami", bytes.NewReader(nil), 0); err != nil || string(got) != a.id {
		t.Errorf("bravo's upload saw %q, %v, want alpha", got, err)
	}
}

// counting is a reader that tells how much of it was read.
type counting struct {
	r    io.Reader
	read atomic.Int64
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func TestARefusedUploadComesBackAsTheAppGaveIt(t *testing.T) {
	a, b, k := uploadingPair(t, unchanged)
	const size = 9 << 20
	body := &counting{r: bytes.NewReader(backupOf(size))}
	status, got, err := upload(t, a, b, "/refuse", body, size)
	if err != nil || status != http.StatusConflict || string(got) != `{"error":"busy_restoring"}` {
		t.Fatalf("a refused upload = %d %q %v", status, got, err)
	}
	if k.asked.Load() != 1 {
		t.Errorf("bravo was asked %d times", k.asked.Load())
	}
	if n := body.read.Load(); n > pieceBytes {
		t.Errorf("alpha read %d bytes of an upload refused before its body", n)
	}
}

func TestAnUploadThatBreaksItsLengthFails(t *testing.T) {
	a, b, k := uploadingPair(t, unchanged)
	for name, data := range map[string][]byte{"short": make([]byte, 500), "long": make([]byte, 1500)} {
		if _, _, err := upload(t, a, b, "/restore", bytes.NewReader(data), 1000); err == nil {
			t.Errorf("a %s upload went through", name)
		}
	}
	waitFor(t, "bravo to see both uploads break off", func() bool { _, failed := k.state(); return len(failed) == 2 })
	if kept, failed := k.state(); len(kept) != 0 || !errors.Is(failed[0], ErrStreamBroken) {
		t.Errorf("bravo kept %d, failed with %v", len(kept), failed)
	}
}

// damagingUpload is a proxy in front of a member that hands on every call but
// passes the body of an upload through damage.
func damagingUpload(t *testing.T, damage func([]byte) []byte) func(string) string {
	return func(target string) string {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			r := pr.Out
			if r.Header.Get("Content-Type") != uploadType {
				return
			}
			raw, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			raw = damage(raw)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			r.ContentLength = int64(len(raw))
			r.TransferEncoding = nil
			r.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		}}
		srv := httptest.NewServer(proxy)
		t.Cleanup(srv.Close)
		return srv.URL
	}
}

func TestADamagedUploadFailsBeforeTheAppKeepsIt(t *testing.T) {
	// Larger than any direct call, and the proxy hands it on with its length.
	const size = 3 << 20
	for name, damage := range map[string]func([]byte) []byte{
		"a flipped bit": func(b []byte) []byte {
			b[len(b)/2] ^= 0x01
			return b
		},
		"cut in the middle":    func(b []byte) []byte { return b[:len(b)/2] },
		"cut by its last byte": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			a, b, k := uploadingPair(t, damagingUpload(t, damage))
			status, _, err := upload(t, a, b, "/restore", bytes.NewReader(backupOf(size)), size)
			if err == nil && status == http.StatusOK {
				t.Fatal("a damaged upload went through")
			}
			kept, failed := k.state()
			if len(kept) != 0 || len(failed) != 1 || !errors.Is(failed[0], ErrStreamBroken) {
				t.Errorf("bravo kept %d, failed with %v", len(kept), failed)
			}
		})
	}
}

func TestAnUploadGoesOnlyDirectly(t *testing.T) {
	url := relayServer(t)
	k := &keeper{}
	a := open(t, "alpha", setup{relay: url})
	b := open(t, "bravo", setup{relay: url, upload: k.routes()})
	waitFor(t, "alpha to see bravo", func() bool { _, ok := memberOf(a.g, b.id); return ok })
	meet(t, a, b)
	if _, _, err := upload(t, a, b, "/restore", bytes.NewReader([]byte("x")), 1); !errors.Is(err, ErrNotDirect) {
		t.Errorf("an upload to a member on the relay alone: %v, want ErrNotDirect", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, status, err := a.g.client.Proxy(ctx, b.id, http.MethodPost, uploadPrefix+"/restore", []byte("x"))
	if err != nil || status != http.StatusMisdirectedRequest || !bytes.Contains(body, []byte("uploadDirectOnly")) {
		t.Errorf("an upload call through the relay = %d %s %v, want 421", status, body, err)
	}
	if n := k.asked.Load(); n != 0 {
		t.Errorf("bravo took %d uploads through the relay", n)
	}
}

func TestAnInstanceWithoutUploadsSaysSo(t *testing.T) {
	a, b := onOneNetwork(t, setup{})
	meet(t, a, b)
	if status, _, err := upload(t, a, b, "/restore", bytes.NewReader([]byte("x")), 1); err != nil || status != http.StatusNotFound {
		t.Errorf("an upload to an instance that takes none = %d %v, want 404", status, err)
	}
}
