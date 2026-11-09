// Package legacy turns notification settings of the formats apps stored
// before notify into notify channels. Nothing a user had set up is dropped: a
// channel that was filled in comes over, and one that could not send comes
// over switched off. Settings that decide what an app sends, rather than where
// to, stay with the app.
package legacy

import (
	"encoding/json"
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

// webhookChannel is an old webhook with the body format it named.
func webhookChannel(id, url, format string, enabled bool, on notify.On, generic string) notify.Channel {
	c := notify.Channel{ID: id, Enabled: enabled, On: on}
	switch format {
	case "discord":
		c.Kind, c.Discord = notify.KindDiscord, &notify.Discord{URL: url}
	case "slack":
		c.Kind, c.Slack = notify.KindSlack, &notify.Slack{URL: url}
	case "gotify":
		c.Kind, c.Gotify = notify.KindGotify, &notify.Gotify{URL: url}
	case "ntfy":
		c.Kind, c.Ntfy = notify.KindNtfy, &notify.Ntfy{URL: url}
	default:
		c.Kind, c.Webhook = notify.KindWebhook, jsonWebhook(url, generic)
	}
	return c
}

// jsonWebhook posts body, a JSON template that rebuilds the document an old
// generic webhook sent.
func jsonWebhook(url, body string) *notify.Webhook {
	return &notify.Webhook{URL: url, Method: "POST", Headers: map[string]string{"Content-Type": "application/json"}, Body: body}
}

// filled reports whether any of the values was set.
func filled(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func all(values ...string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			return false
		}
	}
	return true
}

func on(v string) notify.On {
	switch notify.On(v) {
	case notify.OnNever, notify.OnAlways:
		return notify.On(v)
	default:
		return notify.OnFailure
	}
}

// keys copies the entries of m that have a value.
func keys(m map[string]string) map[string]string {
	var out map[string]string
	for k, v := range m {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out
}

func decode(data []byte, v any) error {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// settled switches off every channel that would not pass notify.Validate, so
// one address that never worked keeps the rest sending instead of failing the
// whole set.
func settled(out []notify.Channel) []notify.Channel {
	for i := range out {
		if out[i].Enabled && notify.Validate(out[i:i+1]) != nil {
			out[i].Enabled = false
		}
	}
	return out
}
