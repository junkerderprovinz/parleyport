package fortress

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// live adds a websocket that answers every message with "echo " and the
// message, and an event stream that counts, to the test app's interface.
func live(ui *UI) *UI {
	mux := http.NewServeMux()
	mux.Handle("/", ui.Handler)
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := Opened(r); !ok {
			http.Error(w, "not through the fortress", http.StatusForbidden)
			return
		}
		if c, err := r.Cookie("session"); err != nil || c.Value != "s3cr3t" {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		for {
			typ, msg, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, append([]byte("echo "), msg...)); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("GET /big-ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		for range 3 {
			if err := c.Write(r.Context(), websocket.MessageText, []byte(strings.Repeat("t", 600_000))); err != nil {
				return
			}
		}
		_, _, _ = c.Read(r.Context())
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; ; i++ {
			if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
				return
			}
			flusher.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	})
	out := *ui
	out.Handler = mux
	return &out
}

func liveOpening(t *testing.T) (a, b *node, path string, br *browser) {
	t.Helper()
	app := &webApp{password: true}
	url := relayServer(t)
	a = open(t, "alpha", "alpha-1", setup{relay: url, uses: []string{OpenAction}, noPair: true})
	b = open(t, "bravo", "bravo-1", setup{relay: url, ui: live(app.ui()), noPair: true})
	meet(t, a, b)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	br = browse(t, a)
	if res := br.do(http.MethodPost, path+"/login", []byte("secret")); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", res.StatusCode)
	}
	return a, b, path, br
}

func dialThrough(t *testing.T, br *browser, path string) (*websocket.Conn, error) {
	t.Helper()
	c, _, err := websocket.Dial(ctx(t), "ws"+strings.TrimPrefix(br.srv.URL, "http")+path, &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {"null"}},
	})
	if err == nil {
		c.SetReadLimit(1 << 20)
		t.Cleanup(func() { _ = c.CloseNow() })
	}
	return c, err
}

func TestAWebsocketOfTheOpenedAppWorksThroughTheRelay(t *testing.T) {
	_, _, path, br := liveOpening(t)
	c, err := dialThrough(t, br, path+"/ws")
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"one", "two", strings.Repeat("x", 30000)} {
		if err := c.Write(ctx(t), websocket.MessageText, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		typ, got, err := c.Read(ctx(t))
		if err != nil || typ != websocket.MessageText || string(got) != "echo "+msg {
			t.Fatalf("read %v %q %v", typ, got[:min(len(got), 20)], err)
		}
	}
}

func TestAWebsocketTheOpenedAppRefusesIsRefused(t *testing.T) {
	app := &webApp{password: true}
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url, uses: []string{OpenAction}, noPair: true})
	b := open(t, "bravo", "bravo-1", setup{relay: url, ui: live(app.ui()), noPair: true})
	meet(t, a, b)
	path, err := a.f.Open(ctx(t), visit(a, b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialThrough(t, browse(t, a), path+"/ws"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a websocket before signing in: %v", err)
	}
}

func TestAnEventStreamOfTheOpenedAppWorksThroughTheRelay(t *testing.T) {
	_, _, path, br := liveOpening(t)
	res := br.get(path+"/events", "Accept", "text/event-stream", "Origin", "null")
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/event-stream" || res.Header.Get("Access-Control-Allow-Origin") != "null" {
		t.Fatalf("event stream: %d %v", res.StatusCode, res.Header)
	}
	lines := bufio.NewScanner(res.Body)
	var got []string
	for len(got) < 3 && lines.Scan() {
		if l := lines.Text(); l != "" {
			got = append(got, l)
		}
	}
	if strings.Join(got, ",") != "data: 0,data: 1,data: 2" {
		t.Fatalf("events %q", got)
	}
}

func TestAStreamEndsWhenItsMemberIsTakenOut(t *testing.T) {
	a, b, path, br := liveOpening(t)
	c, err := dialThrough(t, br, path+"/ws")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx(t), websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Read(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if err := b.f.Remove(a.id); err != nil {
		t.Fatal(err)
	}
	read, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := c.Read(read); err == nil || read.Err() != nil {
		t.Fatalf("the stream went on after its member was taken out: %v", err)
	}
	if n := b.f.streams.count(a.id); n != 0 {
		t.Fatalf("bravo keeps %d streams of the member it took out", n)
	}
}

func TestTheStreamsOfOpenedPagesStayFew(t *testing.T) {
	a, b, path, br := liveOpening(t)
	dial := func(path string, n int) int {
		open := 0
		for range n {
			if _, err := dialThrough(t, br, path+"/ws"); err == nil {
				open++
			}
		}
		return open
	}
	if n := dial(path, maxTabStreams+1); n != maxTabStreams {
		t.Fatalf("%d websockets in one tab, want %d", n, maxTabStreams)
	}
	more := 0
	for range 2 {
		tab, err := a.f.Open(ctx(t), visit(a, b))
		if err != nil {
			t.Fatal(err)
		}
		more += dial(tab, maxTabStreams)
	}
	if maxTabStreams+more != maxStreamsPerCaller {
		t.Fatalf("%d websockets for one member, want %d", maxTabStreams+more, maxStreamsPerCaller)
	}
}

func TestALargeFirstMessageOfAWebsocketArrivesWhole(t *testing.T) {
	_, _, path, br := liveOpening(t)
	c, err := dialThrough(t, br, path+"/big-ws")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_, msg, err := c.Read(ctx(t))
		if err != nil || len(msg) != 600_000 {
			t.Fatalf("message %d: %d bytes, %v", i, len(msg), err)
		}
	}
}

func TestAPageWithManySocketsLeavesRoomForItsRequests(t *testing.T) {
	_, _, path, br := liveOpening(t)
	var conns []*websocket.Conn
	for range maxTabStreams {
		c, err := dialThrough(t, br, path+"/ws")
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for i, c := range conns {
		if err := c.Write(ctx(t), websocket.MessageText, []byte(fmt.Sprintf("socket %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range conns {
		if _, got, err := c.Read(ctx(t)); err != nil || string(got) != fmt.Sprintf("echo socket %d", i) {
			t.Fatalf("socket %d read %q %v", i, got, err)
		}
	}
	for range 4 {
		if res := br.get(path + "/private"); res.StatusCode != http.StatusOK {
			t.Fatalf("a request beside %d sockets: %d", len(conns), res.StatusCode)
		}
	}
}
