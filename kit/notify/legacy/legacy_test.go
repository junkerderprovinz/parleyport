package legacy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/notify"
	"github.com/junkerderprovinz/parleyport/kit/notify/legacy"
)

func ptr[T any](v T) *T { return &v }

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// same compares channel by channel and checks that the result is a set the
// dispatcher accepts.
func same(t *testing.T, got, want []notify.Channel) {
	t.Helper()
	if err := notify.Validate(got); err != nil {
		t.Errorf("the migrated channels do not validate: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d channels, want %d:\n%s", len(got), len(want), dump(got))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("channel %d:\n got  %s\n want %s", i, dump(got[i]), dump(want[i]))
		}
	}
	if _, err := notify.NewDispatcher(got, notify.Options{}); err != nil {
		t.Error(err)
	}
}

func dump(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

const (
	flatGeneric = `{"title":"%%title%%","message":"%%body%%","ok":%%ok%%}`
	jsonType    = "application/json"
)

func TestFromFlat(t *testing.T) {
	got, err := legacy.FromFlat(read(t, "flat.json"))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, []notify.Channel{
		{ID: "webhook", Kind: notify.KindSlack, Enabled: true, On: notify.OnFailure,
			Slack: &notify.Slack{URL: "https://hooks.slack.com/services/T0000/B0000/XXXXXXXXXXXXXXXXXXXXXXXX"}},
		{ID: "matrix", Kind: notify.KindMatrix, Enabled: true, On: notify.OnFailure,
			Matrix: &notify.Matrix{Homeserver: "https://matrix.example.org", Room: "!backups:example.org", Token: "syt_YWxwaGE_token"}},
		{ID: "gotify", Kind: notify.KindGotify, Enabled: true, On: notify.OnFailure,
			Gotify: &notify.Gotify{URL: "https://gotify.example.org", Token: "AbCdEfGhIjKlMnO", PriorityFailure: ptr(9), PrioritySuccess: ptr(0)}},
		{ID: "smtp", Kind: notify.KindSMTP, Enabled: true, On: notify.OnFailure,
			SMTP: &notify.SMTP{Host: "smtp.example.org", Port: 587, Username: "alpha@example.org", Password: "app-password",
				From: "alpha@example.org", To: "ops@example.org, beta@example.org", TLS: "starttls"}},
		{ID: "apprise", Kind: notify.KindApprise, Enabled: false, On: notify.OnFailure,
			Apprise: &notify.Apprise{URL: "http://apprise:8000/notify/alpha", Tags: "backup"}},
		{ID: "healthchecks", Kind: notify.KindHealthchecks, Enabled: true, On: notify.OnAlways,
			Healthchecks: &notify.Healthchecks{URL: "https://hc-ping.com/5f0b6c1e-8d4a-4e8a-9a51-0c2d7e6b3f19", ByKey: map[string]string{
				"container": "https://hc-ping.com/0c2d7e6b-3f19-4e8a-9a51-5f0b6c1e8d4a",
				"VM":        "https://hc-ping.com/9a510c2d-7e6b-4e8a-3f19-5f0b6c1e8d4a",
			}}},
		{ID: "unraid", Kind: notify.KindUnraid, Enabled: true, On: notify.OnFailure},
	})
}

func TestFromFlat_WebhookFormats(t *testing.T) {
	const url = "https://push.example.org/in"
	tests := []struct {
		format string
		want   notify.Channel
	}{
		{"", notify.Channel{Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: url, Method: "POST", Headers: map[string]string{"Content-Type": jsonType}, Body: flatGeneric}}},
		{"generic", notify.Channel{Kind: notify.KindWebhook, Webhook: &notify.Webhook{URL: url, Method: "POST", Headers: map[string]string{"Content-Type": jsonType}, Body: flatGeneric}}},
		{"discord", notify.Channel{Kind: notify.KindDiscord, Discord: &notify.Discord{URL: url}}},
		{"slack", notify.Channel{Kind: notify.KindSlack, Slack: &notify.Slack{URL: url}}},
		{"gotify", notify.Channel{Kind: notify.KindGotify, Gotify: &notify.Gotify{URL: url}}},
		{"ntfy", notify.Channel{Kind: notify.KindNtfy, Ntfy: &notify.Ntfy{URL: url}}},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got, err := legacy.FromFlat([]byte(`{"on":"always","webhookUrl":"` + url + `","webhookFormat":"` + tt.format + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			want := tt.want
			want.ID, want.Enabled, want.On = "webhook", true, notify.OnAlways
			same(t, got, []notify.Channel{want})
		})
	}
}

func TestFromFlat_ReadsAbsentSwitchesAsTheirFields(t *testing.T) {
	got, err := legacy.FromFlat([]byte(`{
		"webhookUrl": "https://push.example.org/in",
		"matrixHomeserver": "https://matrix.example.org", "matrixRoom": "!r:example.org",
		"gotifyUrl": "https://gotify.example.org", "gotifyToken": "tok1"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[string]bool{}
	for _, c := range got {
		enabled[c.ID] = c.Enabled
		if c.On != notify.OnFailure {
			t.Errorf("%s: on = %q, want the old default failure", c.ID, c.On)
		}
		if c.Gotify != nil && (*c.Gotify.PriorityFailure != 8 || *c.Gotify.PrioritySuccess != 5) {
			t.Errorf("gotify priorities = %d/%d", *c.Gotify.PriorityFailure, *c.Gotify.PrioritySuccess)
		}
	}
	want := map[string]bool{"webhook": true, "matrix": false, "gotify": true}
	if !reflect.DeepEqual(enabled, want) {
		t.Errorf("enabled = %v, want %v: a filled channel stays on, one without a token never could send", enabled, want)
	}
	same(t, got, got)
}

func TestFromFlat_KeepsAnIncompleteChannelOff(t *testing.T) {
	got, err := legacy.FromFlat([]byte(`{"on":"always","smtpEnabled":true,"smtpHost":"smtp.example.org"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Enabled || got[0].SMTP.Host != "smtp.example.org" {
		t.Errorf("got %s", dump(got))
	}
	same(t, got, got)
}

func TestFromFlat_Empty(t *testing.T) {
	for _, blob := range []string{`{}`, `{"on":"never","unraid":false}`} {
		got, err := legacy.FromFlat([]byte(blob))
		if err != nil || len(got) != 0 {
			t.Errorf("%s: %s, %v", blob, dump(got), err)
		}
	}
	if _, err := legacy.FromFlat([]byte(`[`)); err == nil {
		t.Error("broken JSON must fail")
	}
}

func TestFromNested(t *testing.T) {
	got, err := legacy.FromNested(read(t, "nested.json"))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, []notify.Channel{
		{ID: "matrix", Kind: notify.KindMatrix, Enabled: true, On: notify.OnAlways,
			Matrix: &notify.Matrix{Homeserver: "https://matrix.example.org", Room: "!sync:example.org", Token: "syt_YmV0YQ_token"}},
		{ID: "webhook", Kind: notify.KindNtfy, Enabled: false, On: notify.OnAlways,
			Ntfy: &notify.Ntfy{URL: "https://ntfy.example.org/beta-sync"}},
		{ID: "smtp", Kind: notify.KindSMTP, Enabled: true, On: notify.OnAlways,
			SMTP: &notify.SMTP{Host: "smtp.example.org", Port: 465, Username: "beta", Password: "app-password", From: "beta@example.org", To: "ops@example.org", TLS: "tls"}},
		{ID: "apprise", Kind: notify.KindApprise, Enabled: true, On: notify.OnAlways,
			Apprise: &notify.Apprise{URL: "http://apprise:8000/notify/beta", Tags: "sync"}},
		{ID: "healthchecks", Kind: notify.KindHealthchecks, Enabled: true, On: notify.OnAlways,
			Healthchecks: &notify.Healthchecks{URL: "https://hc.example.org/ping/7d1e0c2a", ByKey: map[string]string{"photos": "https://hc.example.org/ping/3b9f4e11"}}},
	})
}

func TestFromNested_On(t *testing.T) {
	tests := []struct {
		blob string
		want notify.On
	}{
		{`{"apprise":{"url":"http://a/notify/k"}}`, notify.OnFailure},
		{`{"onSuccess":true,"apprise":{"url":"http://a/notify/k"}}`, notify.OnAlways},
		{`{"on":"never","onSuccess":true,"apprise":{"url":"http://a/notify/k"}}`, notify.OnNever},
	}
	for _, tt := range tests {
		got, err := legacy.FromNested([]byte(tt.blob))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].On != tt.want {
			t.Errorf("%s: %s, want on %q", tt.blob, dump(got), tt.want)
		}
	}
}

func TestFromNested_SilencesTheChecksWithNever(t *testing.T) {
	got, err := legacy.FromNested([]byte(`{"on":"never","healthchecks":{"url":"https://hc.example.org/ping/1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].On != notify.OnNever || !got[0].Enabled {
		t.Errorf("got %s", dump(got))
	}
}

func TestFromNested_GenericWebhook(t *testing.T) {
	got, err := legacy.FromNested([]byte(`{"webhook":"https://push.example.org/in"}`))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, []notify.Channel{{ID: "webhook", Kind: notify.KindWebhook, Enabled: true, On: notify.OnFailure,
		Webhook: &notify.Webhook{URL: "https://push.example.org/in", Method: "POST", Headers: map[string]string{"Content-Type": jsonType},
			Body: `{"subject":"%%title%%","body":"%%body%%","ok":%%ok%%}`}}})
}

func TestFromTargets(t *testing.T) {
	got, err := legacy.FromTargets(read(t, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, []notify.Channel{
		{ID: "1", Kind: notify.KindWebhook, Name: "Phone", Enabled: true, On: notify.OnAlways, Events: []string{"task.done", "package.done"},
			Webhook: &notify.Webhook{URL: "https://ntfy.example.org/downloads?auth=QmFzaWMgYWJj", Method: "POST",
				Headers: map[string]string{"Title": "%%task.name%%", "Priority": "4"}, Body: "%%task.name%% is done"}},
		{ID: "2", Kind: notify.KindDiscord, Name: "Discord", Enabled: true, On: notify.OnAlways, Events: []string{"task.failed"},
			Attempts: 5, TimeoutSeconds: 30, Discord: &notify.Discord{URL: "https://discord.com/api/webhooks/123456789/abcdefTOKENabcdef"}},
		{ID: "3", Kind: notify.KindWebhook, Name: "Matrix", Enabled: false, On: notify.OnAlways, Events: []string{"task.failed", "extract.done"},
			Attempts: 2, TimeoutSeconds: 10, Webhook: &notify.Webhook{
				URL: "https://matrix.example.org/_matrix/client/v3/rooms/!r:example.org/send/m.room.message/%%time%%", Method: "PUT",
				Headers: map[string]string{"Authorization": "Bearer syt_x", "Content-Type": "application/json"},
				Body:    `{"msgtype":"m.text","body":"%%task.name%% failed"}`}},
		{ID: "4", Kind: notify.KindWebhook, Name: "Draft", Enabled: false, On: notify.OnAlways, Events: []string{"task.done"},
			Webhook: &notify.Webhook{Method: "POST"}},
		{ID: "5", Kind: notify.KindWebhook, Name: "No events yet", Enabled: true, On: notify.OnNever,
			Webhook: &notify.Webhook{URL: "https://hooks.example.org/in", Method: "POST"}},
	})
}

func TestFromTargets_KeepsADiscordRowWithHeadersAsWebhook(t *testing.T) {
	got, err := legacy.FromTargets([]byte(`[{"id":"1","enabled":true,"url":"https://discord.com/api/webhooks/1/tok","headers":{"X-Audit":"yes"},"triggers":["task.done"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != notify.KindWebhook || got[0].Webhook.Headers["X-Audit"] != "yes" {
		t.Errorf("got %s", dump(got))
	}
}

func TestFromTargets_Empty(t *testing.T) {
	for _, blob := range []string{`null`, `[]`, ``} {
		got, err := legacy.FromTargets([]byte(blob))
		if err != nil || len(got) != 0 {
			t.Errorf("%q: %s, %v", blob, dump(got), err)
		}
	}
}

func TestFromEnv(t *testing.T) {
	got := legacy.FromEnv(map[string]string{
		"MATRIX_HOMESERVER": "https://matrix.example.org",
		"MATRIX_TOKEN":      "syt_YWxwaGE_token",
		"MATRIX_ROOM":       "#updates:example.org",
		"APPRISE_URL":       "http://apprise:8000/notify/alpha",
		"UNRAID_NOTIFY":     "true",
		"POLL_INTERVAL":     "6h",
	})
	same(t, got, []notify.Channel{
		{ID: "matrix", Kind: notify.KindMatrix, Enabled: true, On: notify.OnAlways,
			Matrix: &notify.Matrix{Homeserver: "https://matrix.example.org", Room: "#updates:example.org", Token: "syt_YWxwaGE_token"}},
		{ID: "apprise", Kind: notify.KindApprise, Enabled: true, On: notify.OnAlways, Apprise: &notify.Apprise{URL: "http://apprise:8000/notify/alpha"}},
		{ID: "unraid", Kind: notify.KindUnraid, Enabled: true, On: notify.OnAlways},
	})
}

func TestFromEnv_KeepsWhatCouldNotSendOff(t *testing.T) {
	got := legacy.FromEnv(map[string]string{
		"MATRIX_HOMESERVER": "https://matrix.example.org",
		"APPRISE_URL":       "apprise:8000/notify/alpha",
		"UNRAID_NOTIFY":     "false",
	})
	if len(got) != 2 || got[0].Enabled || got[1].Enabled {
		t.Errorf("got %s", dump(got))
	}
	same(t, got, got)
	for _, v := range []string{"yes", "1", "on", " TRUE "} {
		if got := legacy.FromEnv(map[string]string{"UNRAID_NOTIFY": v}); len(got) != 1 {
			t.Errorf("%q: %s", v, dump(got))
		}
	}
}

func TestFromUnraidWebhook(t *testing.T) {
	got, err := legacy.FromUnraidWebhook(read(t, "unraid-webhook.json"))
	if err != nil {
		t.Fatal(err)
	}
	same(t, got, []notify.Channel{
		{ID: "unraid", Kind: notify.KindUnraid, Enabled: true, On: notify.OnAlways},
		{ID: "webhook", Kind: notify.KindWebhook, Enabled: true, On: notify.OnAlways, TimeoutSeconds: 10,
			Webhook: &notify.Webhook{URL: "https://hooks.example.org/alerts", Method: "POST", Headers: map[string]string{"Content-Type": jsonType},
				Body: `{"event":"%%title%%","detail":"%%body%%","importance":"%%importance%%"}`}},
	})
}

func TestFromUnraidWebhook_Empty(t *testing.T) {
	got, err := legacy.FromUnraidWebhook([]byte(`{"unraid":false}`))
	if err != nil || len(got) != 0 {
		t.Errorf("%s, %v", dump(got), err)
	}
}
