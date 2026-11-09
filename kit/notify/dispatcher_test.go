package notify_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

func TestNewDispatcher_RefusesAnInvalidChannel(t *testing.T) {
	_, err := notify.NewDispatcher([]notify.Channel{{ID: "a", Kind: "pager"}}, notify.Options{})
	if err == nil {
		t.Fatal("want an error")
	}
}

func TestDispatcher_Send_FollowsOnAndSeverity(t *testing.T) {
	tests := []struct {
		severity notify.Severity
		want     []string
	}{
		{notify.SeverityInfo, []string{"always"}},
		{notify.SeveritySuccess, []string{"always"}},
		{notify.SeverityWarning, []string{"always", "failure", "default"}},
		{notify.SeverityFailure, []string{"always", "failure", "default"}},
		{notify.SeverityCritical, []string{"always", "failure", "default"}},
		{"", []string{"always"}},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			rec := newRecorder(t, nil)
			chs := []notify.Channel{
				slack("always", rec.URL+"/always", notify.OnAlways),
				slack("failure", rec.URL+"/failure", notify.OnFailure),
				slack("default", rec.URL+"/default", ""),
				slack("never", rec.URL+"/never", notify.OnNever),
			}
			off := slack("off", rec.URL+"/off", notify.OnAlways)
			off.Enabled = false
			chs = append(chs, off)
			d, _ := dispatcher(t, chs, notify.Options{})

			results := d.Send(t.Context(), notify.Event{Severity: tt.severity, Title: "t"})

			var got []string
			for _, r := range results {
				if !r.OK() {
					t.Errorf("%s: %v", r.Channel, r.Err)
				}
				got = append(got, r.Channel)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("results for %v, want %v", got, tt.want)
			}
			if len(rec.all()) != len(tt.want) {
				t.Errorf("%d requests, want %d", len(rec.all()), len(tt.want))
			}
		})
	}
}

func TestDispatcher_Send_HonoursEvents(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := slack("s", rec.URL, notify.OnAlways)
	ch.Events = []string{"run.failed"}
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	if r := d.Send(t.Context(), notify.Event{Kind: "run.done", Severity: notify.SeveritySuccess}); len(r) != 0 {
		t.Errorf("an unlisted kind was sent: %+v", r)
	}
	if r := d.Send(t.Context(), notify.Event{Kind: "run.failed", Severity: notify.SeverityFailure}); len(r) != 1 || !r[0].OK() {
		t.Errorf("a listed kind was not sent: %+v", r)
	}
}

func TestDispatcher_Send_RetriesWhatAnotherTryCanFix(t *testing.T) {
	rec := newRecorder(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	d, waits := dispatcher(t, []notify.Channel{slack("s", rec.URL, notify.OnAlways)}, notify.Options{})

	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if !r.OK() || r.Attempts != 3 {
		t.Fatalf("result = %+v, want a success on the third attempt", r)
	}
	if len(*waits) != 2 || (*waits)[0] >= (*waits)[1] {
		t.Errorf("waits = %v, want two growing pauses", *waits)
	}
}

func TestDispatcher_Send_GivesUpOnARefusal(t *testing.T) {
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid token"}`))
	})
	d, _ := dispatcher(t, []notify.Channel{slack("s", rec.URL, notify.OnAlways)}, notify.Options{})

	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if r.OK() || r.Attempts != 1 || r.Code != notify.CodeAuth || r.Status != http.StatusUnauthorized {
		t.Fatalf("result = %+v", r)
	}
	if !strings.Contains(r.Err.Error(), "invalid token") {
		t.Errorf("the error leaves out what the server said: %v", r.Err)
	}
}

func TestDispatcher_Send_StopsAfterTheLastAttempt(t *testing.T) {
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	ch := slack("s", rec.URL, notify.OnAlways)
	ch.Attempts = 2
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if r.Attempts != 2 || r.Code != notify.CodeServer || len(rec.all()) != 2 {
		t.Fatalf("result = %+v after %d requests", r, len(rec.all()))
	}
}

func TestDispatcher_Send_WaitsAsLongAsTheServerAsks(t *testing.T) {
	rec := newRecorder(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.Header().Set("Retry-After", "12")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	d, waits := dispatcher(t, []notify.Channel{slack("s", rec.URL, notify.OnAlways)}, notify.Options{})

	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if !r.OK() || len(*waits) != 1 || (*waits)[0] != 12*time.Second {
		t.Fatalf("result = %+v, waits = %v", r, *waits)
	}
}

func TestDispatcher_Send_ReadsDiscordsRetryAfter(t *testing.T) {
	rec := newRecorder(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"retry_after": 4.5, "global": false}`))
		}
	})
	d, waits := dispatcher(t, []notify.Channel{slack("s", rec.URL, notify.OnAlways)}, notify.Options{})

	d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})

	if len(*waits) != 1 || (*waits)[0] != 4500*time.Millisecond {
		t.Fatalf("waits = %v, want the 4.5 s of the body, which is finer than the header", *waits)
	}
}

func TestDispatcher_Send_BoundsEachAttempt(t *testing.T) {
	release := make(chan struct{})
	rec := newRecorder(t, func(_ int, _ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ch := slack("s", rec.URL, notify.OnAlways)
	ch.Attempts, ch.TimeoutSeconds = 1, 1
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	start := time.Now()
	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if r.Code != notify.CodeTimeout {
		t.Errorf("code = %q, want %q (%v)", r.Code, notify.CodeTimeout, r.Err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the send took %s", took)
	}
}

func TestDispatcher_Send_ReportsAConnectionRefused(t *testing.T) {
	rec := newRecorder(t, nil)
	url := rec.URL
	rec.Close()
	ch := slack("s", url, notify.OnAlways)
	ch.Attempts = 1
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if r.Code != notify.CodeRefused {
		t.Errorf("code = %q (%v)", r.Code, r.Err)
	}
}

func TestDispatcher_Send_DoesNotFollowARedirectToAnotherHost(t *testing.T) {
	other := newRecorder(t, nil)
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/in", http.StatusTemporaryRedirect)
	})
	ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Enabled: true, On: notify.OnAlways,
		Webhook: &notify.Webhook{URL: rec.URL, Headers: map[string]string{"X-Api-Key": "s3cret-key"}}}
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]

	if r.Code != notify.CodeRedirect || r.Attempts != 1 {
		t.Errorf("result = %+v", r)
	}
	if len(other.all()) != 0 {
		t.Error("the request, key and all, went on to the other host")
	}
}

func TestDispatcher_Send_FollowsARedirectOnTheSameHost(t *testing.T) {
	rec := newRecorder(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			http.Redirect(w, r, "/hooks/in/", http.StatusPermanentRedirect)
		}
	})
	d, _ := dispatcher(t, []notify.Channel{slack("s", rec.URL+"/hooks/in", notify.OnAlways)}, notify.Options{})

	if r := d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})[0]; !r.OK() {
		t.Fatalf("result = %+v", r)
	}
	if hits := rec.all(); len(hits) != 2 || hits[1].Path != "/hooks/in/" {
		t.Errorf("hits = %+v", hits)
	}
}

func TestDispatcher_Send_UsesTheGivenClient(t *testing.T) {
	rec := newRecorder(t, nil)
	var used bool
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	d, _ := dispatcher(t, []notify.Channel{slack("s", rec.URL, notify.OnAlways)}, notify.Options{HTTP: client})

	d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})

	if !used {
		t.Error("Options.HTTP was not used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDispatcher_Send_StopsWhenTheContextEnds(t *testing.T) {
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	d, err := notify.NewDispatcher([]notify.Channel{slack("s", rec.URL, notify.OnAlways)}, notify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	r := d.Send(ctx, notify.Event{Severity: notify.SeverityFailure})[0]

	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("Send waited %s past its context", took)
	}
	if r.OK() || r.Attempts != 1 {
		t.Errorf("result = %+v", r)
	}
}

func TestDispatcher_Ping(t *testing.T) {
	rec := newRecorder(t, nil)
	hc := func(id string, on notify.On) notify.Channel {
		return notify.Channel{ID: id, Kind: notify.KindHealthchecks, Enabled: true, On: on,
			Healthchecks: &notify.Healthchecks{URL: rec.URL + "/" + id, ByKey: map[string]string{"flash": rec.URL + "/" + id + "-flash"}}}
	}
	chs := []notify.Channel{hc("a", notify.OnAlways), hc("f", notify.OnFailure), hc("n", notify.OnNever), slack("s", rec.URL+"/slack", notify.OnAlways)}
	d, _ := dispatcher(t, chs, notify.Options{})

	results := d.Ping(t.Context(), notify.Event{Ping: notify.PingStart, Key: "flash"})

	if len(results) != 2 {
		t.Fatalf("results = %+v, want the two healthchecks channels that are not off", results)
	}
	var paths []string
	for _, h := range rec.all() {
		paths = append(paths, h.Method+" "+h.Path)
	}
	if strings.Join(paths, ",") != "GET /a-flash/start,GET /f-flash/start" && strings.Join(paths, ",") != "GET /f-flash/start,GET /a-flash/start" {
		t.Errorf("requests = %v", paths)
	}
}

func TestDispatcher_Ping_Phases(t *testing.T) {
	tests := []struct {
		ping notify.Ping
		body string
		want string
	}{
		{notify.PingStart, "", "GET /c/start"},
		{notify.PingSuccess, "", "GET /c"},
		{notify.PingFail, "", "GET /c/fail"},
		{notify.PingLog, "", "GET /c/log"},
		{notify.PingFail, "1 of 3 failed", "POST /c/fail 1 of 3 failed"},
	}
	for _, tt := range tests {
		t.Run(string(tt.ping)+tt.body, func(t *testing.T) {
			rec := newRecorder(t, nil)
			ch := notify.Channel{ID: "h", Kind: notify.KindHealthchecks, Enabled: true, Healthchecks: &notify.Healthchecks{URL: rec.URL + "/c/"}}
			d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

			d.Ping(t.Context(), notify.Event{Ping: tt.ping, Body: tt.body})

			h := rec.only(t)
			if got := strings.TrimSpace(h.Method + " " + h.Path + " " + h.Body); got != tt.want {
				t.Errorf("request = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDispatcher_Ping_SkipsAKeyWithoutCheck(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "h", Kind: notify.KindHealthchecks, Enabled: true, Healthchecks: &notify.Healthchecks{ByKey: map[string]string{"flash": rec.URL}}}
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	if r := d.Ping(t.Context(), notify.Event{Ping: notify.PingStart, Key: "vm"}); len(r) != 0 {
		t.Errorf("results = %+v", r)
	}
}

func TestDispatcher_Send_PingsAndMessagesTogether(t *testing.T) {
	rec := newRecorder(t, nil)
	chs := []notify.Channel{
		{ID: "h", Kind: notify.KindHealthchecks, Enabled: true, Healthchecks: &notify.Healthchecks{URL: rec.URL + "/check"}},
		slack("s", rec.URL+"/slack", notify.OnFailure),
	}
	d, _ := dispatcher(t, chs, notify.Options{})

	results := d.Send(t.Context(), notify.Event{Severity: notify.SeveritySuccess, Ping: notify.PingSuccess})
	if len(results) != 1 || results[0].Channel != "h" {
		t.Errorf("a success pings the check and stays off a failure-only channel: %+v", results)
	}
	results = d.Send(t.Context(), notify.Event{Severity: notify.SeverityFailure})
	if len(results) != 1 || results[0].Channel != "s" {
		t.Errorf("an event without Ping leaves the check alone: %+v", results)
	}
}

func TestDispatcher_Test(t *testing.T) {
	rec := newRecorder(t, nil)
	d, _ := dispatcher(t, nil, notify.Options{})
	draft := slack("draft", rec.URL, notify.OnNever)
	draft.Enabled = false

	r := d.Test(t.Context(), draft, notify.Event{Title: "Test", Body: "It works."})

	if !r.OK() || r.Channel != "draft" {
		t.Fatalf("result = %+v", r)
	}
	if h := rec.only(t); !strings.Contains(h.Body, "It works.") {
		t.Errorf("body = %s", h.Body)
	}
}

func TestDispatcher_Test_LogsToEveryCheck(t *testing.T) {
	rec := newRecorder(t, nil)
	d, _ := dispatcher(t, nil, notify.Options{})
	ch := notify.Channel{ID: "h", Kind: notify.KindHealthchecks, Healthchecks: &notify.Healthchecks{
		URL: rec.URL + "/all", ByKey: map[string]string{"flash": rec.URL + "/flash", "vm": rec.URL + "/all"},
	}}

	r := d.Test(t.Context(), ch, notify.Event{Body: "test"})

	if !r.OK() {
		t.Fatal(r.Err)
	}
	var paths []string
	for _, h := range rec.all() {
		paths = append(paths, h.Path)
	}
	if len(paths) != 2 || !strings.Contains(strings.Join(paths, ","), "/all/log") || !strings.Contains(strings.Join(paths, ","), "/flash/log") {
		t.Errorf("paths = %v, want one log ping per distinct check", paths)
	}
}

func TestDispatcher_Test_RefusesAnIncompleteChannel(t *testing.T) {
	d, _ := dispatcher(t, nil, notify.Options{})

	r := d.Test(t.Context(), notify.Channel{ID: "m", Kind: notify.KindMatrix, Matrix: &notify.Matrix{}}, notify.Event{})

	if r.OK() || r.Code != notify.CodeInvalid {
		t.Errorf("result = %+v", r)
	}
}
