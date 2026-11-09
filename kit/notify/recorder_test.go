package notify_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

type hit struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

// recorder is an HTTP server that keeps every request it got and answers with
// reply, or 200 when reply is nil.
type recorder struct {
	*httptest.Server
	mu    sync.Mutex
	hits  []hit
	reply func(n int, w http.ResponseWriter, r *http.Request)
}

func newRecorder(t *testing.T, reply func(n int, w http.ResponseWriter, r *http.Request)) *recorder {
	t.Helper()
	rec := &recorder{reply: reply}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.hits = append(rec.hits, hit{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: string(body)})
		n := len(rec.hits)
		rec.mu.Unlock()
		if rec.reply != nil {
			rec.reply(n, w, r)
		}
	}))
	t.Cleanup(rec.Close)
	return rec
}

func (r *recorder) all() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hit(nil), r.hits...)
}

func (r *recorder) only(t *testing.T) hit {
	t.Helper()
	hits := r.all()
	if len(hits) != 1 {
		t.Fatalf("got %d requests, want 1: %+v", len(hits), hits)
	}
	return hits[0]
}

// dispatcher builds a Dispatcher whose waits between attempts return at once
// and are recorded in waits.
func dispatcher(t *testing.T, chs []notify.Channel, opt notify.Options) (*notify.Dispatcher, *[]time.Duration) {
	t.Helper()
	d, err := notify.NewDispatcher(chs, opt)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	waits := &[]time.Duration{}
	notify.SetSleep(d, func(ctx context.Context, wait time.Duration) bool {
		mu.Lock()
		*waits = append(*waits, wait)
		mu.Unlock()
		return ctx.Err() == nil
	})
	return d, waits
}

func slack(id, url string, on notify.On) notify.Channel {
	return notify.Channel{ID: id, Kind: notify.KindSlack, Enabled: true, On: on, Slack: &notify.Slack{URL: url}}
}
