package legacy

import (
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

type nested struct {
	On             string `json:"on"`
	OnSuccess      bool   `json:"onSuccess"`
	Webhook        string `json:"webhook"`
	WebhookFormat  string `json:"webhookFormat"`
	WebhookEnabled *bool  `json:"webhookEnabled"`
	Matrix         *struct {
		Enabled    *bool  `json:"enabled"`
		Homeserver string `json:"homeserver"`
		Room       string `json:"room"`
		Token      string `json:"token"`
	} `json:"matrix"`
	SMTP *struct {
		Enabled  *bool  `json:"enabled"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		From     string `json:"from"`
		To       string `json:"to"`
		TLS      string `json:"tls"`
	} `json:"smtp"`
	Apprise *struct {
		Enabled *bool  `json:"enabled"`
		URL     string `json:"url"`
		Tags    string `json:"tags"`
	} `json:"apprise"`
	Healthchecks *struct {
		Enabled *bool             `json:"enabled"`
		URL     string            `json:"url"`
		Jobs    map[string]string `json:"jobs"`
	} `json:"healthchecks"`
}

// FromNested reads the nested object with one block per service, each with
// its own optional "enabled", and the policy in "on" or in the older
// "onSuccess".
//
// A missing "enabled" means on. Healthchecks pings every run unless the policy
// is never, and a job's own check becomes a check by key, the job's name. A
// generic webhook keeps its JSON document through a template.
func FromNested(data []byte) ([]notify.Channel, error) {
	var n nested
	if err := decode(data, &n); err != nil {
		return nil, err
	}
	policy := on(n.On)
	if n.On == "" && n.OnSuccess {
		policy = notify.OnAlways
	}
	switchedOn := func(set *bool) bool { return set == nil || *set }

	var out []notify.Channel
	if m := n.Matrix; m != nil && filled(m.Homeserver, m.Room, m.Token) {
		out = append(out, notify.Channel{ID: "matrix", Kind: notify.KindMatrix, On: policy,
			Enabled: switchedOn(m.Enabled) && all(m.Homeserver, m.Room, m.Token),
			Matrix:  &notify.Matrix{Homeserver: m.Homeserver, Room: m.Room, Token: m.Token}})
	}
	if filled(n.Webhook) {
		out = append(out, webhookChannel("webhook", n.Webhook, n.WebhookFormat, switchedOn(n.WebhookEnabled), policy,
			`{"subject":"%%title%%","body":"%%body%%","ok":%%ok%%}`))
	}
	if s := n.SMTP; s != nil && filled(s.Host, s.Username, s.Password, s.From, s.To) {
		out = append(out, notify.Channel{ID: "smtp", Kind: notify.KindSMTP, On: policy,
			Enabled: switchedOn(s.Enabled) && all(s.Host, s.From, s.To),
			SMTP: &notify.SMTP{Host: s.Host, Port: s.Port, Username: s.Username, Password: s.Password,
				From: s.From, To: s.To, TLS: strings.ToLower(s.TLS)}})
	}
	if a := n.Apprise; a != nil && filled(a.URL) {
		out = append(out, notify.Channel{ID: "apprise", Kind: notify.KindApprise, On: policy,
			Enabled: switchedOn(a.Enabled),
			Apprise: &notify.Apprise{URL: a.URL, Tags: a.Tags}})
	}
	if h := n.Healthchecks; h != nil {
		if byKey := keys(h.Jobs); filled(h.URL) || byKey != nil {
			checks := notify.OnAlways
			if policy == notify.OnNever {
				checks = notify.OnNever
			}
			out = append(out, notify.Channel{ID: "healthchecks", Kind: notify.KindHealthchecks, On: checks,
				Enabled:      switchedOn(h.Enabled),
				Healthchecks: &notify.Healthchecks{URL: h.URL, ByKey: byKey}})
		}
	}
	return settled(out), nil
}
