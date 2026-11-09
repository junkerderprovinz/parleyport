package legacy

import (
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

type flat struct {
	On                    string            `json:"on"`
	WebhookEnabled        *bool             `json:"webhookEnabled"`
	WebhookURL            string            `json:"webhookUrl"`
	WebhookFormat         string            `json:"webhookFormat"`
	MatrixEnabled         *bool             `json:"matrixEnabled"`
	MatrixHomeserver      string            `json:"matrixHomeserver"`
	MatrixToken           string            `json:"matrixToken"`
	MatrixRoom            string            `json:"matrixRoom"`
	GotifyEnabled         *bool             `json:"gotifyEnabled"`
	GotifyURL             string            `json:"gotifyUrl"`
	GotifyToken           string            `json:"gotifyToken"`
	GotifyPriorityFailure *int              `json:"gotifyPriorityFailure"`
	GotifyPrioritySuccess *int              `json:"gotifyPrioritySuccess"`
	HealthchecksURL       string            `json:"healthchecksUrl"`
	HealthchecksByDomain  map[string]string `json:"healthchecksByDomain"`
	Unraid                bool              `json:"unraid"`
	SMTPEnabled           bool              `json:"smtpEnabled"`
	SMTPHost              string            `json:"smtpHost"`
	SMTPPort              int               `json:"smtpPort"`
	SMTPUsername          string            `json:"smtpUsername"`
	SMTPPassword          string            `json:"smtpPassword"`
	SMTPFrom              string            `json:"smtpFrom"`
	SMTPTo                string            `json:"smtpTo"`
	SMTPTLS               string            `json:"smtpTls"`
	AppriseEnabled        *bool             `json:"appriseEnabled"`
	AppriseURL            string            `json:"appriseUrl"`
	AppriseTags           string            `json:"appriseTags"`
}

// FromFlat reads the flat field list, one key per setting such as webhookUrl,
// matrixToken and smtpHost, with one policy "on" for every channel.
//
// A switch key that is missing means the channel is on when its fields are
// filled in, as the format was read. The Healthchecks checks are pinged
// whatever "on" says, and a 0 SMTP port is 587 in every TLS mode. A generic
// webhook keeps its JSON document through a template; Discord and Slack get
// the message notify writes for them.
func FromFlat(data []byte) ([]notify.Channel, error) {
	var f flat
	if err := decode(data, &f); err != nil {
		return nil, err
	}
	policy := notify.OnFailure
	switch f.On {
	case "", "failure":
	case "always":
		policy = notify.OnAlways
	default:
		// The format sent nothing for a value it did not know.
		policy = notify.OnNever
	}
	gate := func(set *bool, ready bool) bool { return (set == nil || *set) && ready }

	var out []notify.Channel
	if filled(f.WebhookURL) {
		out = append(out, webhookChannel("webhook", f.WebhookURL, f.WebhookFormat, gate(f.WebhookEnabled, true), policy,
			`{"title":"%%title%%","message":"%%body%%","ok":%%ok%%}`))
	}
	if filled(f.MatrixHomeserver, f.MatrixToken, f.MatrixRoom) {
		out = append(out, notify.Channel{ID: "matrix", Kind: notify.KindMatrix, On: policy,
			Enabled: gate(f.MatrixEnabled, all(f.MatrixHomeserver, f.MatrixToken, f.MatrixRoom)),
			Matrix:  &notify.Matrix{Homeserver: f.MatrixHomeserver, Room: f.MatrixRoom, Token: f.MatrixToken}})
	}
	if filled(f.GotifyURL, f.GotifyToken) {
		failure, success := notify.DefaultGotifyFailure, notify.DefaultGotifySuccess
		if f.GotifyPriorityFailure != nil {
			failure = *f.GotifyPriorityFailure
		}
		if f.GotifyPrioritySuccess != nil {
			success = *f.GotifyPrioritySuccess
		}
		out = append(out, notify.Channel{ID: "gotify", Kind: notify.KindGotify, On: policy,
			Enabled: gate(f.GotifyEnabled, all(f.GotifyURL, f.GotifyToken)),
			Gotify:  &notify.Gotify{URL: f.GotifyURL, Token: f.GotifyToken, PriorityFailure: &failure, PrioritySuccess: &success}})
	}
	if filled(f.SMTPHost, f.SMTPUsername, f.SMTPPassword, f.SMTPFrom, f.SMTPTo) {
		port := f.SMTPPort
		if port == 0 {
			port = 587
		}
		tls := strings.ToLower(f.SMTPTLS)
		if tls == "" {
			tls = "starttls"
		}
		out = append(out, notify.Channel{ID: "smtp", Kind: notify.KindSMTP, On: policy,
			Enabled: f.SMTPEnabled && all(f.SMTPHost, f.SMTPFrom, f.SMTPTo),
			SMTP: &notify.SMTP{Host: f.SMTPHost, Port: port, Username: f.SMTPUsername, Password: f.SMTPPassword,
				From: f.SMTPFrom, To: f.SMTPTo, TLS: tls}})
	}
	if filled(f.AppriseURL) {
		out = append(out, notify.Channel{ID: "apprise", Kind: notify.KindApprise, On: policy,
			Enabled: gate(f.AppriseEnabled, true),
			Apprise: &notify.Apprise{URL: f.AppriseURL, Tags: f.AppriseTags}})
	}
	if byKey := keys(f.HealthchecksByDomain); filled(f.HealthchecksURL) || byKey != nil {
		out = append(out, notify.Channel{ID: "healthchecks", Kind: notify.KindHealthchecks, Enabled: true, On: notify.OnAlways,
			Healthchecks: &notify.Healthchecks{URL: f.HealthchecksURL, ByKey: byKey}})
	}
	if f.Unraid {
		out = append(out, notify.Channel{ID: "unraid", Kind: notify.KindUnraid, Enabled: true, On: policy})
	}
	return settled(out), nil
}
