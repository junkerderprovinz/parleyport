package notify_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// echo answers 400 and repeats the whole request, the way some push servers
// quote what they refused.
func echo(_ int, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, "refused %s %s auth=%q key=%q", r.Method, r.URL.String(), r.Header.Get("Authorization"), r.Header.Get("X-Gotify-Key"))
}

func TestResult_ErrCarriesNoSecret(t *testing.T) {
	rec := newRecorder(t, echo)
	closed := newRecorder(t, nil)
	gone := closed.URL
	closed.Close()

	const (
		pathToken   = "11111111-2222-3333-4444-555555555555"
		queryToken  = "qqqq1111qqqq"
		headerToken = "hdr-7Yt3Kq"
		gotifyToken = "AbCdEfGhIj"
		matrixToken = "syt_c2VjcmV0"
		ntfyToken   = "tk_ntfyntfy"
		password    = "pw-hunter22"
	)
	basic := base64.StdEncoding.EncodeToString([]byte("alpha:" + password))
	secrets := []string{pathToken, queryToken, headerToken, gotifyToken, matrixToken, ntfyToken, password, basic}
	for _, base := range []string{rec.URL, gone} {
		host := strings.TrimPrefix(base, "http://")
		chs := []notify.Channel{
			{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{
				URL:     base + "/hook/" + pathToken + "?token=" + queryToken + "&m=%%title%%",
				Headers: map[string]string{"Authorization": "Bearer " + headerToken},
			}},
			{ID: "d", Kind: notify.KindDiscord, Discord: &notify.Discord{URL: base + "/api/webhooks/1/" + pathToken}},
			{ID: "g", Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: base, Token: gotifyToken}},
			{ID: "n", Kind: notify.KindNtfy, Ntfy: &notify.Ntfy{URL: base + "/alpha", Token: ntfyToken}},
			{ID: "m", Kind: notify.KindMatrix, Matrix: &notify.Matrix{Homeserver: base, Room: "!r:m.example", Token: matrixToken}},
			{ID: "a", Kind: notify.KindApprise, Apprise: &notify.Apprise{URL: "http://alpha:" + password + "@" + host + "/notify/" + pathToken}},
			{ID: "h", Kind: notify.KindHealthchecks, Healthchecks: &notify.Healthchecks{URL: base + "/ping/" + pathToken}},
		}
		for _, ch := range chs {
			t.Run(string(ch.Kind)+" "+base, func(t *testing.T) {
				ch.Attempts = 1
				e := failed
				e.Ping = notify.PingFail
				r := sendOne(t, ch, notify.Options{}, e)
				if r.OK() {
					t.Fatal("want a failure")
				}
				msg := r.Err.Error()
				for _, s := range secrets {
					for _, form := range []string{s, url.QueryEscape(s), url.PathEscape(s)} {
						if strings.Contains(msg, form) {
							t.Errorf("the error carries %q: %s", form, msg)
						}
					}
				}
			})
		}
	}
}

func TestResult_ErrKeepsTheCause(t *testing.T) {
	rec := newRecorder(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errcode":"M_NOT_FOUND"}`))
	})
	ch := notify.Channel{ID: "m", Kind: notify.KindMatrix, Matrix: &notify.Matrix{Homeserver: rec.URL, Room: "!r:m.example", Token: "t0ken-abc"}}

	r := sendOne(t, ch, notify.Options{}, failed)

	if r.Code != notify.CodeNotFound || !strings.Contains(r.Err.Error(), "M_NOT_FOUND") || !strings.Contains(r.Err.Error(), "404") {
		t.Errorf("result = %+v", r)
	}
}

func TestSend_MasksPasswordsInTheMessage(t *testing.T) {
	rec := newRecorder(t, nil)
	e := failed
	e.Title = "Mount sftp://alpha:hunter22@nas.example/share failed"
	e.Body = "tried https://bob:pa55@host.example/x"

	sendOne(t, notify.Channel{ID: "s", Kind: notify.KindSlack, Slack: &notify.Slack{URL: rec.URL}}, notify.Options{}, e)

	if body := rec.only(t).Body; containsAny(body, "hunter22", "pa55", "alpha:", "bob:") {
		t.Errorf("a password went out: %s", body)
	}
}

func TestRedact(t *testing.T) {
	_, err := http.Get("http://user:pa55word@127.0.0.1:1/hook/s3cretpath?token=abc123")
	if err == nil {
		t.Skip("something answered on port 1")
	}
	got := notify.Redact(fmt.Errorf("send: %w", err))
	if containsAny(got.Error(), "pa55word", "s3cretpath", "abc123", "user") {
		t.Errorf("Redact left a secret: %v", got)
	}
	if !strings.Contains(got.Error(), "127.0.0.1:1") {
		t.Errorf("Redact dropped the host: %v", got)
	}
	if notify.Redact(nil) != nil {
		t.Error("Redact(nil) must be nil")
	}
	if got := notify.Redact(errors.New("plain")); got.Error() != "plain" {
		t.Errorf("an error without an address must read the same, got %q", got)
	}
}

func TestRedacted(t *testing.T) {
	chs := []notify.Channel{
		{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://h.example/in", Headers: map[string]string{"Authorization": "Bearer x", "X-Empty": ""}}},
		{ID: "g", Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: "https://g.example", Token: "tok"}},
		{ID: "n", Kind: notify.KindNtfy, Ntfy: &notify.Ntfy{URL: "https://ntfy.example/a", Token: "tok"}},
		{ID: "m", Kind: notify.KindMatrix, Matrix: &notify.Matrix{Homeserver: "https://m.example", Room: "!r", Token: "tok"}},
		{ID: "s", Kind: notify.KindSMTP, SMTP: &notify.SMTP{Host: "mail.example", Username: "u", Password: "pw", From: "a@x", To: "b@x"}},
		{ID: "a", Kind: notify.KindApprise, Apprise: &notify.Apprise{URL: "http://apprise/notify", URLs: []string{"tgram://bot/chat"}}},
	}

	out := notify.Redacted(chs)

	if out[0].Webhook.Headers["Authorization"] != notify.RedactedValue || out[0].Webhook.Headers["X-Empty"] != "" {
		t.Errorf("headers = %v", out[0].Webhook.Headers)
	}
	if out[1].Gotify.Token != notify.RedactedValue || out[2].Ntfy.Token != notify.RedactedValue || out[3].Matrix.Token != notify.RedactedValue || out[4].SMTP.Password != notify.RedactedValue || out[5].Apprise.URLs[0] != "tgram://"+notify.RedactedValue+"/chat" {
		t.Errorf("redacted = %+v", out)
	}
	if chs[0].Webhook.Headers["Authorization"] != "Bearer x" || chs[1].Gotify.Token != "tok" || chs[5].Apprise.URLs[0] != "tgram://bot/chat" {
		t.Error("Redacted changed the channels it was given")
	}
}

func TestMerge(t *testing.T) {
	prev := []notify.Channel{
		{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://h.example/in", Headers: map[string]string{"Authorization": "Bearer x"}}},
		{ID: "g", Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: "https://g.example", Token: "tok"}},
		{ID: "s", Kind: notify.KindSMTP, SMTP: &notify.SMTP{Host: "mail.example", Username: "u", Password: "pw"}},
		{ID: "a", Kind: notify.KindApprise, Apprise: &notify.Apprise{URL: "http://apprise/notify", URLs: []string{"tgram://bot/chat", "pover://u@t"}}},
	}
	tests := []struct {
		name  string
		edit  func(chs []notify.Channel)
		check func(t *testing.T, got []notify.Channel)
	}{
		{"untouched", func([]notify.Channel) {}, func(t *testing.T, got []notify.Channel) {
			if got[0].Webhook.Headers["Authorization"] != "Bearer x" || got[1].Gotify.Token != "tok" || got[2].SMTP.Password != "pw" || got[3].Apprise.URLs[1] != "pover://u@t" {
				t.Errorf("merged = %+v", got)
			}
		}},
		{"address changed", func(chs []notify.Channel) {
			chs[0].Webhook.URL = "https://attacker.example/in"
			chs[1].Gotify.URL = "https://attacker.example"
			chs[2].SMTP.Host = "attacker.example"
		}, func(t *testing.T, got []notify.Channel) {
			if got[0].Webhook.Headers["Authorization"] != "" || got[1].Gotify.Token != "" || got[2].SMTP.Password != "" {
				t.Errorf("a secret followed a new address: %+v", got)
			}
		}},
		{"retyped", func(chs []notify.Channel) { chs[1].Gotify.Token = "new" }, func(t *testing.T, got []notify.Channel) {
			if got[1].Gotify.Token != "new" {
				t.Errorf("token = %q", got[1].Gotify.Token)
			}
		}},
		{"moved into another row", func(chs []notify.Channel) { chs[1].ID = "other" }, func(t *testing.T, got []notify.Channel) {
			if got[1].Gotify.Token != "" {
				t.Errorf("token = %q", got[1].Gotify.Token)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := notify.Redacted(prev)
			tt.edit(next)
			got := notify.Merge(next, prev)
			tt.check(t, got)
		})
	}
}

// addressed is a channel of every kind whose addresses carry a key.
var addressed = []notify.Channel{
	{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://alpha:hunter22@maker.example/trigger/run/with/key/dK3jx9Qm2LpZ?m=%%title%%"}},
	{ID: "d", Kind: notify.KindDiscord, Discord: &notify.Discord{URL: "https://discord.com/api/webhooks/123456789012345678/AbCd-EfGh_IjKlMnOpQrStUv"}},
	{ID: "s", Kind: notify.KindSlack, Slack: &notify.Slack{URL: "https://hooks.slack.com/services/T0001/B0002/XxXxXxXxXxXxXxXxXxXxXxXx"}},
	{ID: "g", Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: "https://gotify.example/message?token=AqZ7wLx"}},
	{ID: "n", Kind: notify.KindNtfy, Ntfy: &notify.Ntfy{URL: "https://ntfy.example/tr7alerts?auth=QmFzaWM"}},
	{ID: "m", Kind: notify.KindMatrix, Matrix: &notify.Matrix{Homeserver: "https://bot:s3cr3tpw@matrix.example", Room: "!r", Token: "tok"}},
	{ID: "a", Kind: notify.KindApprise, Apprise: &notify.Apprise{URL: "http://apprise.example:8000/notify/tollroll"}},
	{ID: "as", Kind: notify.KindApprise, Apprise: &notify.Apprise{URL: "http://apprise.example:8000/notify", URLs: []string{"tgram://123456:ABCdef/4711", "pover://ukey9@apptoken9"}}},
	{ID: "h", Kind: notify.KindHealthchecks, Healthchecks: &notify.Healthchecks{
		URL:   "https://hc.example/ping/11112222-3333-4444-5555-666677778888",
		ByKey: map[string]string{"flash": "https://hc.example/ping/Kq8vX2mN4pR7sT1wY3zB5c/flash"},
	}},
}

func TestRedactedMasksKeysInAddresses(t *testing.T) {
	secrets := []string{
		"alpha", "hunter22", "dK3jx9Qm2LpZ", "AbCd-EfGh_IjKlMnOpQrStUv", "XxXxXxXxXxXxXxXxXxXxXxXx",
		"AqZ7wLx", "tr7alerts", "QmFzaWM", "s3cr3tpw", "tollroll", "123456:ABCdef", "ukey9", "apptoken9",
		"11112222-3333-4444-5555-666677778888", "Kq8vX2mN4pR7sT1wY3zB5c",
	}
	kept := []string{
		"maker.example/trigger/run/with/key/", "m=%%title%%", "discord.com/api/webhooks/", "hooks.slack.com/services/",
		"gotify.example/message?token=", "ntfy.example/", "matrix.example", "apprise.example:8000/notify/",
		"tgram://", "pover://", "hc.example/ping/", "/flash",
	}

	out, err := json.Marshal(notify.Redacted(addressed))
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range secrets {
		if strings.Contains(string(out), s) {
			t.Errorf("Redacted left %q", s)
		}
	}
	for _, s := range kept {
		if !strings.Contains(string(out), s) {
			t.Errorf("Redacted took out %q", s)
		}
	}
}

func TestRedactedMasksTokenInQuery(t *testing.T) {
	ch := notify.Channel{ID: "g", Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: "https://gotify.example/message?token=AqZ7wLx"}}

	got := notify.Redacted([]notify.Channel{ch})[0].Gotify.URL

	if got != "https://gotify.example/message?token="+notify.RedactedValue {
		t.Errorf("url = %q", got)
	}
}

func TestMergeRestoresMaskedAddresses(t *testing.T) {
	got := notify.Merge(notify.Redacted(addressed), addressed)

	if !reflect.DeepEqual(got, addressed) {
		t.Errorf("merged = %+v", got)
	}
}

func TestMergeDropsAMaskedAddressThatMoved(t *testing.T) {
	next := notify.Redacted(addressed)
	next[4].Ntfy.URL = strings.Replace(next[4].Ntfy.URL, "ntfy.example", "attacker.example", 1)
	next[7].Apprise.URL = "http://attacker.example:8000/notify"
	next[8].Healthchecks.ByKey["flash"] = strings.Replace(next[8].Healthchecks.ByKey["flash"], "hc.example", "attacker.example", 1)

	got := notify.Merge(next, addressed)

	if got[4].Ntfy.URL != "" || got[8].Healthchecks.ByKey["flash"] != "" {
		t.Errorf("a masked address came back at a new host: %q %q", got[4].Ntfy.URL, got[8].Healthchecks.ByKey["flash"])
	}
	if got[7].Apprise.URL != "http://attacker.example:8000/notify" || !slices.Equal(got[7].Apprise.URLs, []string{"", ""}) {
		t.Errorf("the service addresses followed a new Apprise server: %+v", got[7].Apprise)
	}
}

func TestRedactedMasksKeyValuesInAJSONBody(t *testing.T) {
	body := `{"token": "aPpT0k3n", "user": "u9", "message": "%%title%%",
  "auth": {"API_KEY": "nested-k3y", "Access_Token": "acc3ss"}, "author": "Ann",
  "client_secret":"cl1ent", "password": "%%pw%%", "items": [{"Password": "pa\"55"}],
  "key": "", "priority": %%prio%%}`
	want := `{"token": "********", "user": "u9", "message": "%%title%%",
  "auth": {"API_KEY": "********", "Access_Token": "********"}, "author": "Ann",
  "client_secret":"********", "password": "%%pw%%", "items": [{"Password": "********"}],
  "key": "", "priority": %%prio%%}`
	ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://api.pushover.net/1/messages.json", Body: body}}

	if got := notify.Redacted([]notify.Channel{ch})[0].Webhook.Body; got != want {
		t.Errorf("body =\n%s\nwant\n%s", got, want)
	}
	if ch.Webhook.Body != body {
		t.Error("Redacted changed the body it was given")
	}
}

func TestRedactedMasksKeyValuesInAFormBody(t *testing.T) {
	for body, want := range map[string]string{
		"token=abc123&user=u9&message=%%title%%&api_key=xyz789&apikey=&author=Ann\n": "token=********&user=u9&message=%%title%%&api_key=********&apikey=&author=Ann\n",
		"Backup failed on %%host%%, token sent":                                      "Backup failed on %%host%%, token sent",
	} {
		ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://h.example/in", Body: body}}
		if got := notify.Redacted([]notify.Channel{ch})[0].Webhook.Body; got != want {
			t.Errorf("body %q = %q, want %q", body, got, want)
		}
	}
}

// bodies are webhook channels whose bodies carry a key.
var bodies = []notify.Channel{
	{ID: "j", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://api.pushover.net/1/messages.json", Body: `{"token":"aPpT0k3n","user":"u9","message":"%%title%%"}`}},
	{ID: "f", Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: "https://h.example/in", Body: "secret=s3cr3t&m=%%title%%"}},
}

func TestMergeRestoresAMaskedBody(t *testing.T) {
	got := notify.Merge(notify.Redacted(bodies), bodies)

	if !reflect.DeepEqual(got, bodies) {
		t.Errorf("merged = %+v %+v", got[0].Webhook, got[1].Webhook)
	}
}

func TestMergeDropsAMaskedBodyThatChanged(t *testing.T) {
	tests := []struct {
		name string
		edit func(w *notify.Webhook)
		want string
	}{
		{"text around the key edited", func(w *notify.Webhook) {
			w.Body = strings.Replace(w.Body, "%%title%%", "%%body%%", 1)
		}, ""},
		{"key renamed", func(w *notify.Webhook) {
			w.Body = strings.Replace(w.Body, `"token"`, `"message2"`, 1)
		}, ""},
		{"address moved", func(w *notify.Webhook) {
			w.URL = "https://attacker.example/in"
		}, ""},
		{"key retyped", func(w *notify.Webhook) {
			w.Body = `{"token":"n3w","user":"u9","message":"%%body%%"}`
		}, `{"token":"n3w","user":"u9","message":"%%body%%"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := notify.Redacted(bodies)
			tt.edit(next[0].Webhook)
			if got := notify.Merge(next, bodies)[0].Webhook.Body; got != tt.want {
				t.Errorf("body = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResult_ErrCarriesNoKeyFromTheBody(t *testing.T) {
	var rec *recorder
	rec = newRecorder(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, "refused %s", rec.all()[n-1].Body)
	})
	for _, body := range []string{`{"token":"aPpT0k3n\/x","message":"%%title%%"}`, "api_key=xyz%2F789&m=%%title%%"} {
		ch := notify.Channel{ID: "w", Kind: notify.KindWebhook, Attempts: 1, Webhook: &notify.Webhook{URL: rec.URL, Body: body}}
		r := sendOne(t, ch, notify.Options{}, failed)
		if r.OK() {
			t.Fatal("want a failure")
		}
		if containsAny(r.Err.Error(), "aPpT0k3n", "xyz%2F789", "xyz/789") {
			t.Errorf("the error carries a key from the body: %v", r.Err)
		}
	}
}
