package notify_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

func TestChannel_JSONRoundTrip(t *testing.T) {
	const stored = `[
		{"id":"ops","kind":"webhook","name":"Ops","enabled":true,"on":"always","events":["run.failed"],
		 "attempts":2,"timeoutSeconds":20,
		 "webhook":{"url":"https://hooks.example/in?m=%%title%%","method":"PUT",
		            "headers":{"Authorization":"Bearer abc"},"body":"{\"t\":\"%%title%%\"}"}},
		{"id":"phone","kind":"gotify","enabled":false,
		 "gotify":{"url":"https://gotify.example","token":"AbCdEf","priorityFailure":0}},
		{"id":"checks","kind":"healthchecks","enabled":true,
		 "healthchecks":{"url":"https://hc.example/ping/1","byKey":{"flash":"https://hc.example/ping/2"}}}
	]`
	var chs []notify.Channel
	if err := json.Unmarshal([]byte(stored), &chs); err != nil {
		t.Fatal(err)
	}
	if got := chs[0].Webhook.Headers["Authorization"]; got != "Bearer abc" {
		t.Errorf("header = %q", got)
	}
	if p := chs[1].Gotify.PriorityFailure; p == nil || *p != 0 {
		t.Errorf("an explicit priority 0 must survive decoding, got %v", p)
	}
	if chs[1].Gotify.PrioritySuccess != nil {
		t.Errorf("an absent priority must stay nil")
	}
	out, err := json.Marshal(chs)
	if err != nil {
		t.Fatal(err)
	}
	var again []notify.Channel
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatal(err)
	}
	if again[2].Healthchecks.ByKey["flash"] != "https://hc.example/ping/2" {
		t.Errorf("byKey lost in a round trip: %s", out)
	}
}

func TestValidate(t *testing.T) {
	webhook := func(url string) notify.Channel {
		return notify.Channel{ID: "w", Kind: notify.KindWebhook, Enabled: true, Webhook: &notify.Webhook{URL: url}}
	}
	tests := []struct {
		name  string
		chs   []notify.Channel
		code  string
		field string
	}{
		{name: "missing id", chs: []notify.Channel{{Kind: notify.KindUnraid}}, code: notify.ProblemMissingID},
		{name: "duplicate id", chs: []notify.Channel{{ID: "a", Kind: notify.KindUnraid}, {ID: "a", Kind: notify.KindUnraid}}, code: notify.ProblemDuplicateID},
		{name: "unknown kind", chs: []notify.Channel{{ID: "a", Kind: "pager"}}, code: notify.ProblemUnknownKind, field: "kind"},
		{name: "bad on", chs: []notify.Channel{{ID: "a", Kind: notify.KindUnraid, On: "sometimes"}}, code: notify.ProblemBadOn, field: "on"},
		{name: "too many attempts", chs: []notify.Channel{{ID: "a", Kind: notify.KindUnraid, Attempts: 6}}, code: notify.ProblemBadAttempts, field: "attempts"},
		{name: "timeout too long", chs: []notify.Channel{{ID: "a", Kind: notify.KindUnraid, TimeoutSeconds: 61}}, code: notify.ProblemBadTimeout, field: "timeoutSeconds"},
		{name: "enabled without settings", chs: []notify.Channel{{ID: "a", Kind: notify.KindMatrix, Enabled: true}}, code: notify.ProblemMissingSettings, field: "matrix"},
		{name: "no url", chs: []notify.Channel{webhook("")}, code: notify.ProblemMissingField, field: "webhook.url"},
		{name: "file url", chs: []notify.Channel{webhook("file:///etc/passwd")}, code: notify.ProblemBadURL, field: "webhook.url"},
		{name: "url without host", chs: []notify.Channel{webhook("https:///x")}, code: notify.ProblemBadURL, field: "webhook.url"},
		{name: "unclosed placeholder in url", chs: []notify.Channel{webhook("https://h.example/?m=%%title")}, code: notify.ProblemBadTemplate, field: "webhook.url"},
		{
			name: "unclosed placeholder in body",
			chs:  []notify.Channel{{ID: "w", Kind: notify.KindWebhook, Enabled: true, Webhook: &notify.Webhook{URL: "https://h.example", Body: "100%% done"}}},
			code: notify.ProblemBadTemplate, field: "webhook.body",
		},
		{
			name: "unclosed placeholder in header",
			chs:  []notify.Channel{{ID: "w", Kind: notify.KindWebhook, Enabled: true, Webhook: &notify.Webhook{URL: "https://h.example", Headers: map[string]string{"X-T": "%%title"}}}},
			code: notify.ProblemBadTemplate, field: "webhook.headers.X-T",
		},
		{
			name: "blank header name",
			chs:  []notify.Channel{{ID: "w", Kind: notify.KindWebhook, Enabled: true, Webhook: &notify.Webhook{URL: "https://h.example", Headers: map[string]string{" ": "v"}}}},
			code: notify.ProblemBadHeader, field: "webhook.headers",
		},
		{
			name: "delete method",
			chs:  []notify.Channel{{ID: "w", Kind: notify.KindWebhook, Enabled: true, Webhook: &notify.Webhook{URL: "https://h.example", Method: "DELETE"}}},
			code: notify.ProblemBadMethod, field: "webhook.method",
		},
		{
			name: "gotify priority above ten",
			chs:  []notify.Channel{{ID: "g", Kind: notify.KindGotify, Enabled: true, Gotify: &notify.Gotify{URL: "https://g.example", Token: "t", PriorityFailure: ptr(11)}}},
			code: notify.ProblemBadPriority, field: "gotify.priorityFailure",
		},
		{
			name: "matrix without room",
			chs:  []notify.Channel{{ID: "m", Kind: notify.KindMatrix, Enabled: true, Matrix: &notify.Matrix{Homeserver: "https://m.example", Token: "t"}}},
			code: notify.ProblemMissingField, field: "matrix.room",
		},
		{
			name: "smtp with unknown tls mode",
			chs:  []notify.Channel{{ID: "s", Kind: notify.KindSMTP, Enabled: true, SMTP: &notify.SMTP{Host: "mail.example", From: "a@example", To: "b@example", TLS: "ssl"}}},
			code: notify.ProblemBadTLS, field: "smtp.tls",
		},
		{
			name: "smtp port out of range",
			chs:  []notify.Channel{{ID: "s", Kind: notify.KindSMTP, Enabled: true, SMTP: &notify.SMTP{Host: "mail.example", From: "a@example", To: "b@example", Port: 70000}}},
			code: notify.ProblemBadPort, field: "smtp.port",
		},
		{
			name: "healthchecks without any url",
			chs:  []notify.Channel{{ID: "h", Kind: notify.KindHealthchecks, Enabled: true, Healthchecks: &notify.Healthchecks{}}},
			code: notify.ProblemMissingField, field: "healthchecks.url",
		},
		{
			name: "healthchecks with a bad key url",
			chs:  []notify.Channel{{ID: "h", Kind: notify.KindHealthchecks, Enabled: true, Healthchecks: &notify.Healthchecks{ByKey: map[string]string{"flash": "nope"}}}},
			code: notify.ProblemBadURL, field: "healthchecks.byKey.flash",
		},
		{
			name: "apprise with a blank service url",
			chs:  []notify.Channel{{ID: "a", Kind: notify.KindApprise, Enabled: true, Apprise: &notify.Apprise{URL: "http://apprise:8000/notify", URLs: []string{"tgram://x/y", " "}}}},
			code: notify.ProblemMissingField, field: "apprise.urls.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := notify.Validate(tt.chs)
			var problems notify.Problems
			if !errors.As(err, &problems) {
				t.Fatalf("Validate = %v, want Problems", err)
			}
			if !slices.ContainsFunc(problems, func(p notify.Problem) bool { return p.Code == tt.code && p.Field == tt.field }) {
				t.Errorf("problems = %+v, want code %q at %q", problems, tt.code, tt.field)
			}
		})
	}
}

func TestValidate_AcceptsEveryKind(t *testing.T) {
	chs := []notify.Channel{
		{ID: "1", Kind: notify.KindWebhook, Enabled: true, On: notify.OnAlways, Webhook: &notify.Webhook{URL: "https://%%key%%.example/in?m=%%title%%", Method: "get"}},
		{ID: "2", Kind: notify.KindDiscord, Enabled: true, Discord: &notify.Discord{URL: "https://discord.com/api/webhooks/1/abc"}},
		{ID: "3", Kind: notify.KindSlack, Enabled: true, Slack: &notify.Slack{URL: "https://hooks.slack.com/services/T/B/x"}},
		{ID: "4", Kind: notify.KindGotify, Enabled: true, Gotify: &notify.Gotify{URL: "https://g.example", Token: "t", PriorityFailure: ptr(0)}},
		{ID: "5", Kind: notify.KindNtfy, Enabled: true, Ntfy: &notify.Ntfy{URL: "https://ntfy.sh/alpha"}},
		{ID: "6", Kind: notify.KindMatrix, Enabled: true, Matrix: &notify.Matrix{Homeserver: "https://m.example", Room: "#ops:m.example", Token: "t"}},
		{ID: "7", Kind: notify.KindSMTP, Enabled: true, SMTP: &notify.SMTP{Host: "mail.example", From: "a@example", To: "b@example; c@example", TLS: "tls"}},
		{ID: "8", Kind: notify.KindApprise, Enabled: true, Apprise: &notify.Apprise{URL: "http://apprise:8000/notify/alpha", Tags: "ops"}},
		{ID: "9", Kind: notify.KindHealthchecks, Enabled: true, Healthchecks: &notify.Healthchecks{ByKey: map[string]string{"flash": "https://hc.example/ping/2"}}},
		{ID: "10", Kind: notify.KindUnraid, Enabled: true},
	}
	if err := notify.Validate(chs); err != nil {
		t.Fatal(err)
	}
}

func TestValidate_LetsADisabledChannelBeIncomplete(t *testing.T) {
	chs := []notify.Channel{
		{ID: "draft", Kind: notify.KindMatrix, Matrix: &notify.Matrix{Homeserver: "https://m.example"}},
		{ID: "empty", Kind: notify.KindWebhook},
	}
	if err := notify.Validate(chs); err != nil {
		t.Fatal(err)
	}
}

func TestProblems_ErrorNamesNoSecret(t *testing.T) {
	err := notify.Validate([]notify.Channel{{ID: "w", Kind: notify.KindWebhook, Enabled: true, Webhook: &notify.Webhook{URL: "ftp://user:hunter22@h.example/"}}})
	if err == nil {
		t.Fatal("want a problem")
	}
	if got := err.Error(); containsAny(got, "hunter22", "ftp://") {
		t.Errorf("the problem text quotes the address: %s", got)
	}
}
