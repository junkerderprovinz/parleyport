package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

var failed = notify.Event{
	Kind:     "run.failed",
	Severity: notify.SeverityFailure,
	Title:    "Backup failed",
	Body:     `Der "Direktor" & co`,
	Link:     "https://tower.example/runs/7",
	Key:      "flash",
	At:       time.Date(2026, 11, 9, 10, 2, 11, 0, time.UTC),
}

func sendOne(t *testing.T, ch notify.Channel, opt notify.Options, e notify.Event) notify.Result {
	t.Helper()
	ch.Enabled, ch.On = true, notify.OnAlways
	d, _ := dispatcher(t, []notify.Channel{ch}, opt)
	results := d.Send(t.Context(), e)
	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
	return results[0]
}

func decodeJSON(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	return m
}

func TestWebhook_ExpandsEachPlaceholderForItsPlace(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{
		URL:    rec.URL + "/in/%%key%%?m=%%body%%",
		Method: "put",
		Headers: map[string]string{
			"Content-Type": "application/json",
			"X-Title":      "%%title%%\r\nInjected: yes",
			"X-Empty":      "",
		},
		Body: `{"msg":"%%body%%","ok":%%ok%%,"sev":"%%Severity%%","at":"%%time%%","from":"%%source%%","task":"%%task.name%%","typo":"%%tilte%%"}`,
	}}
	e := failed
	e.Fields = map[string]string{"task.name": `a "b".mkv`}

	r := sendOne(t, ch, notify.Options{Source: "Alpha"}, e)

	if !r.OK() {
		t.Fatal(r.Err)
	}
	h := rec.only(t)
	if h.Method != http.MethodPut || h.Path != "/in/flash" || h.Query != "m=Der+%22Direktor%22+%26+co" {
		t.Errorf("request = %s %s?%s", h.Method, h.Path, h.Query)
	}
	if got := h.Header.Get("X-Title"); got != "Backup failedInjected: yes" {
		t.Errorf("X-Title = %q, want the line break removed", got)
	}
	if _, ok := h.Header["X-Empty"]; ok {
		t.Error("an empty header value was sent")
	}
	body := decodeJSON(t, h.Body)
	want := map[string]any{
		"msg": failed.Body, "ok": false, "sev": "failure", "at": "2026-11-09T10:02:11Z",
		"from": "Alpha", "task": `a "b".mkv`, "typo": "%%tilte%%",
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %#v, want %#v", k, body[k], v)
		}
	}
}

func TestWebhook_SendsNoBodyWithGet(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: rec.URL, Method: "GET", Body: "x"}}

	sendOne(t, ch, notify.Options{}, failed)

	if h := rec.only(t); h.Method != http.MethodGet || h.Body != "" {
		t.Errorf("request = %+v", h)
	}
}

func TestWebhook_EscapesAFormBody(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{
		URL: rec.URL, Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}, Body: "text=%%body%%",
	}}

	sendOne(t, ch, notify.Options{}, failed)

	if h := rec.only(t); h.Body != "text=Der+%22Direktor%22+%26+co" {
		t.Errorf("body = %q", h.Body)
	}
}

func TestDiscord(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "d", Kind: notify.KindDiscord, Discord: &notify.Discord{URL: rec.URL + "/api/webhooks/1/tok"}}
	e := failed
	e.Title = "Backup *failed*"
	e.Facts = []notify.Fact{{Name: "Domain", Value: "flash"}, {Name: "Empty"}}

	r := sendOne(t, ch, notify.Options{Source: "Alpha"}, e)

	if !r.OK() {
		t.Fatal(r.Err)
	}
	h := rec.only(t)
	var msg struct {
		Embeds []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
			Color       int    `json:"color"`
			Fields      []struct {
				Name, Value string
			} `json:"fields"`
			Footer    struct{ Text string } `json:"footer"`
			Timestamp string                `json:"timestamp"`
		} `json:"embeds"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal([]byte(h.Body), &msg); err != nil {
		t.Fatal(err)
	}
	em := msg.Embeds[0]
	if em.Title != `Backup \*failed\*` || em.URL != failed.Link || em.Description != `Der "Direktor" & co` {
		t.Errorf("embed = %+v", em)
	}
	if em.Color != 0xED4245 || em.Footer.Text != "Alpha" || em.Timestamp != "2026-11-09T10:02:11Z" {
		t.Errorf("embed = %+v", em)
	}
	if len(em.Fields) != 1 || em.Fields[0].Name != "Domain" || em.Fields[0].Value != "flash" {
		t.Errorf("fields = %+v", em.Fields)
	}
	if msg.AllowedMentions.Parse == nil || len(msg.AllowedMentions.Parse) != 0 {
		t.Errorf("allowed_mentions must be an empty list, so @everyone pings nobody: %s", h.Body)
	}
}

func TestDiscord_ShortensALongText(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "d", Kind: notify.KindDiscord, Discord: &notify.Discord{URL: rec.URL}}
	e := failed
	e.Title = strings.Repeat("x", 300)

	sendOne(t, ch, notify.Options{}, e)

	title := decodeJSON(t, rec.only(t).Body)["embeds"].([]any)[0].(map[string]any)["title"].(string)
	if n := len([]rune(title)); n != 256 || !strings.HasSuffix(title, "…") {
		t.Errorf("title has %d runes: %q", n, title)
	}
}

func TestWebhook_RendersTheDiscordMessageForAnEmptyBody(t *testing.T) {
	var got string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		got = r.Header.Get("Content-Type") + " " + string(body)
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: http.Header{}}, nil
	})}
	ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://discord.com/api/webhooks/1/tok"}}

	r := sendOne(t, ch, notify.Options{HTTP: client}, failed)

	if !r.OK() || !strings.HasPrefix(got, "application/json {\"embeds\"") {
		t.Errorf("result %+v, sent %q", r, got)
	}
}

func TestSlack(t *testing.T) {
	rec := newRecorder(t, nil)

	sendOne(t, notify.Channel{ID: "s", Kind: notify.KindSlack, Slack: &notify.Slack{URL: rec.URL}}, notify.Options{}, failed)

	if got := decodeJSON(t, rec.only(t).Body)["text"]; got != "Backup failed\n"+failed.Body+"\n"+failed.Link {
		t.Errorf("text = %q", got)
	}
}

func TestGotify(t *testing.T) {
	tests := []struct {
		name     string
		gotify   notify.Gotify
		severity notify.Severity
		path     string
		query    string
		key      string
		priority float64
	}{
		{"token in the header", notify.Gotify{Token: "AppTok"}, notify.SeverityFailure, "/message", "", "AppTok", 8},
		{"default success priority", notify.Gotify{Token: "AppTok"}, notify.SeveritySuccess, "/message", "", "AppTok", 5},
		{"own priorities", notify.Gotify{Token: "AppTok", PriorityFailure: ptr(10), PrioritySuccess: ptr(0)}, notify.SeveritySuccess, "/message", "", "AppTok", 0},
		{"address with the token", notify.Gotify{}, notify.SeverityCritical, "/message", "token=AppTok", "", 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newRecorder(t, nil)
			g := tt.gotify
			g.URL = rec.URL + "/"
			if tt.query != "" {
				g.URL = rec.URL + "/message?" + tt.query
			}
			e := failed
			e.Severity = tt.severity

			r := sendOne(t, notify.Channel{ID: "g", Kind: notify.KindGotify, Gotify: &g}, notify.Options{}, e)

			if !r.OK() {
				t.Fatal(r.Err)
			}
			h := rec.only(t)
			if h.Path != tt.path || h.Query != tt.query || h.Header.Get("X-Gotify-Key") != tt.key {
				t.Errorf("request = %s?%s key %q", h.Path, h.Query, h.Header.Get("X-Gotify-Key"))
			}
			body := decodeJSON(t, h.Body)
			if body["priority"] != tt.priority || body["title"] != "Backup failed" || body["message"] != failed.Body {
				t.Errorf("body = %v", body)
			}
		})
	}
}

func TestGotify_TellsATokenFromAnOutage(t *testing.T) {
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })

	r := sendOne(t, notify.Channel{ID: "g", Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: rec.URL, Token: "x"}}, notify.Options{}, failed)

	if r.Code != notify.CodeAuth {
		t.Errorf("code = %q", r.Code)
	}
}

func TestNtfy(t *testing.T) {
	tests := []struct {
		severity notify.Severity
		priority string
		tags     string
	}{
		{notify.SeverityFailure, "high", "warning"},
		{notify.SeverityCritical, "urgent", "rotating_light"},
		{notify.SeveritySuccess, "", ""},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			rec := newRecorder(t, nil)
			e := failed
			e.Severity = tt.severity
			e.Title = "Sicherung fehlgeschlagen: Größe"

			sendOne(t, notify.Channel{ID: "n", Kind: notify.KindNtfy, Ntfy: &notify.Ntfy{URL: rec.URL + "/alpha", Token: "tk_1"}}, notify.Options{}, e)

			h := rec.only(t)
			if h.Path != "/alpha" || h.Body != failed.Body {
				t.Errorf("request = %+v", h)
			}
			if h.Header.Get("Priority") != tt.priority || h.Header.Get("Tags") != tt.tags {
				t.Errorf("priority %q tags %q", h.Header.Get("Priority"), h.Header.Get("Tags"))
			}
			if h.Header.Get("Authorization") != "Bearer tk_1" || h.Header.Get("Click") != failed.Link {
				t.Errorf("headers = %v", h.Header)
			}
			if title := h.Header.Get("Title"); !strings.HasPrefix(title, "=?utf-8?") {
				t.Errorf("a title with umlauts goes out RFC 2047 encoded, got %q", title)
			}
		})
	}
}

func TestMatrix(t *testing.T) {
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/directory/room/") {
			_, _ = w.Write([]byte(`{"room_id":"!abc:m.example"}`))
		}
	})
	ch := notify.Channel{ID: "m", Kind: notify.KindMatrix, Matrix: &notify.Matrix{Homeserver: rec.URL + "/", Room: "#ops:m.example", Token: "syt_x"}}
	e := failed
	e.HTML = "<b>Backup failed</b>"

	r := sendOne(t, ch, notify.Options{}, e)

	if !r.OK() {
		t.Fatal(r.Err)
	}
	hits := rec.all()
	if len(hits) != 2 || hits[0].Path != "/_matrix/client/v3/directory/room/%23ops:m.example" {
		t.Fatalf("hits = %+v", hits)
	}
	send := hits[1]
	if send.Method != http.MethodPut || !strings.HasPrefix(send.Path, "/_matrix/client/v3/rooms/%21abc:m.example/send/m.room.message/") {
		t.Errorf("send = %s %s", send.Method, send.Path)
	}
	if send.Header.Get("Authorization") != "Bearer syt_x" {
		t.Errorf("authorization = %q", send.Header.Get("Authorization"))
	}
	body := decodeJSON(t, send.Body)
	if body["msgtype"] != "m.text" || body["body"] != "Backup failed\n"+failed.Body+"\n"+failed.Link || body["formatted_body"] != e.HTML || body["format"] != "org.matrix.custom.html" {
		t.Errorf("body = %v", body)
	}
}

func TestMatrix_UsesAFreshTransactionEachTime(t *testing.T) {
	rec := newRecorder(t, nil)
	ch := notify.Channel{ID: "m", Kind: notify.KindMatrix, Enabled: true, On: notify.OnAlways, Matrix: &notify.Matrix{Homeserver: rec.URL, Room: "!r:m.example", Token: "t"}}
	d, _ := dispatcher(t, []notify.Channel{ch}, notify.Options{})

	d.Send(t.Context(), failed)
	d.Send(t.Context(), failed)

	if hits := rec.all(); len(hits) != 2 || hits[0].Path == hits[1].Path {
		t.Errorf("hits = %+v", hits)
	}
}

func TestApprise(t *testing.T) {
	tests := []struct {
		name     string
		apprise  notify.Apprise
		severity notify.Severity
		want     map[string]any
	}{
		{"key", notify.Apprise{Tags: "ops,phone"}, notify.SeverityFailure,
			map[string]any{"title": "Backup failed", "body": failed.Body + "\n" + failed.Link, "type": "failure", "tag": "ops,phone"}},
		{"addresses", notify.Apprise{URLs: []string{"tgram://bot/chat", "pover://user@token"}}, notify.SeverityWarning,
			map[string]any{"urls": "tgram://bot/chat pover://user@token", "type": "warning"}},
		{"info", notify.Apprise{}, notify.SeverityInfo, map[string]any{"type": "info"}},
		{"success", notify.Apprise{}, notify.SeveritySuccess, map[string]any{"type": "success"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newRecorder(t, nil)
			a := tt.apprise
			a.URL = rec.URL + "/notify/alpha"
			e := failed
			e.Severity = tt.severity

			sendOne(t, notify.Channel{ID: "a", Kind: notify.KindApprise, Apprise: &a}, notify.Options{}, e)

			h := rec.only(t)
			body := decodeJSON(t, h.Body)
			for k, v := range tt.want {
				if body[k] != v {
					t.Errorf("%s = %#v, want %#v", k, body[k], v)
				}
			}
			if _, ok := body["urls"]; ok != (len(a.URLs) > 0) {
				t.Errorf("urls present = %v", ok)
			}
		})
	}
}

type runner struct {
	name string
	args []string
	err  error
}

func (r *runner) Run(_ context.Context, name string, args ...string) error {
	r.name, r.args = name, args
	return r.err
}

func TestUnraid(t *testing.T) {
	notify.SetUnraidSpacing(t, 0)
	tests := []struct {
		severity   notify.Severity
		importance string
	}{
		{notify.SeverityInfo, "normal"},
		{notify.SeveritySuccess, "normal"},
		{notify.SeverityWarning, "warning"},
		{notify.SeverityFailure, "warning"},
		{notify.SeverityCritical, "alert"},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			run := &runner{}
			e := failed
			e.Severity = tt.severity

			r := sendOne(t, notify.Channel{ID: "u", Kind: notify.KindUnraid}, notify.Options{Source: "Alpha", Unraid: run}, e)

			if !r.OK() {
				t.Fatal(r.Err)
			}
			want := []string{"-e", "Alpha", "-s", "Backup failed", "-d", "Der Direktor & co", "-i", tt.importance, "-l", failed.Link}
			if run.name != notify.UnraidNotifyScript || !slices.Equal(run.args, want) {
				t.Errorf("ran %s %q", run.name, run.args)
			}
		})
	}
}

func TestUnraid_ReportsAFailedScript(t *testing.T) {
	notify.SetUnraidSpacing(t, 0)
	run := &runner{err: errors.New("exit status 1: no such agent")}

	r := sendOne(t, notify.Channel{ID: "u", Kind: notify.KindUnraid}, notify.Options{Unraid: run}, failed)

	if r.OK() || r.Code != notify.CodeScript || r.Attempts != 1 {
		t.Errorf("result = %+v", r)
	}
}

// clock notes when each run started, from any goroutine.
type clock struct {
	mu     sync.Mutex
	starts []time.Time
}

func (c *clock) Run(context.Context, string, ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts = append(c.starts, time.Now())
	return nil
}

func TestUnraidSpacesSendsOneSecondApart(t *testing.T) {
	run := &clock{}
	chs := []notify.Channel{
		{ID: "u1", Kind: notify.KindUnraid, Enabled: true, On: notify.OnAlways},
		{ID: "u2", Kind: notify.KindUnraid, Enabled: true, On: notify.OnAlways},
	}
	d, _ := dispatcher(t, chs, notify.Options{Unraid: run})

	for _, r := range d.Send(t.Context(), failed) {
		if !r.OK() {
			t.Fatalf("result = %+v", r)
		}
	}

	if len(run.starts) != 2 {
		t.Fatalf("ran %d times", len(run.starts))
	}
	gap := run.starts[1].Sub(run.starts[0]).Abs()
	if gap < time.Second {
		t.Errorf("the two notifications went out %v apart", gap)
	}
}

func TestUnraidStripsBackslashesAndQuotes(t *testing.T) {
	notify.SetUnraidSpacing(t, 0)
	run := &runner{}
	e := failed
	e.Title = `Backup "flash" failed`
	e.Body = `C:\share\x said "no"`
	e.Link = `https://tower.example/runs/7?q="a\b"`

	sendOne(t, notify.Channel{ID: "u", Kind: notify.KindUnraid}, notify.Options{Source: `Al"pha\`, Unraid: run}, e)

	want := []string{"-e", "Alpha", "-s", "Backup flash failed", "-d", "C:sharex said no", "-i", "warning", "-l", "https://tower.example/runs/7?q=ab"}
	if !slices.Equal(run.args, want) {
		t.Errorf("ran with %q", run.args)
	}
}

func TestUnraid_RunsTheScriptOnThisMachineByDefault(t *testing.T) {
	notify.SetUnraidSpacing(t, 0)
	d, err := notify.NewDispatcher(nil, notify.Options{})
	if err != nil {
		t.Fatal(err)
	}

	r := d.Test(t.Context(), notify.Channel{ID: "u", Kind: notify.KindUnraid, Attempts: 1}, failed)

	if r.OK() || r.Code != notify.CodeScript {
		t.Errorf("result = %+v; outside Unraid the script is missing and the result has to say so", r)
	}
}
