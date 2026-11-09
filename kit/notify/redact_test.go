package notify_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// echo answers 400 and repeats the whole request, the way some push servers
// quote what they refused.
func echo(_ int, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, "refused %s %s auth=%q key=%q", r.Method, r.URL.String(), r.Header.Get("Authorization"), r.Header.Get("X-Gotify-Key"))
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
	if out[1].Gotify.Token != notify.RedactedValue || out[2].Ntfy.Token != notify.RedactedValue || out[3].Matrix.Token != notify.RedactedValue || out[4].SMTP.Password != notify.RedactedValue || out[5].Apprise.URLs[0] != "tgram://bot/chat" {
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
