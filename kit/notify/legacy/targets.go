package legacy

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/junkerderprovinz/parleyport/kit/notify"
)

type target struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Enabled        bool              `json:"enabled"`
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers"`
	Body           string            `json:"body"`
	Triggers       []string          `json:"triggers"`
	Attempts       int               `json:"attempts"`
	TimeoutSeconds int               `json:"timeoutSeconds"`
}

// FromTargets reads a list of free HTTP targets, each with its own method,
// headers, body template, triggers, attempts and timeout.
//
// Every target becomes a webhook channel as it was, its triggers the
// channel's events. The templates are kept as written, so the app has to
// fill the same %%names%% through Event.Fields. A target with no trigger sent
// nothing and gets On never. A target that sent a Discord webhook an empty
// body, and carries no header, becomes a Discord channel, which writes the
// same kind of embed. A row with neither address nor name is the leftover of
// an Add button and is dropped.
func FromTargets(data []byte) ([]notify.Channel, error) {
	var ts []target
	if err := decode(data, &ts); err != nil {
		return nil, err
	}
	var out []notify.Channel
	for _, t := range ts {
		t.URL, t.Name = strings.TrimSpace(t.URL), strings.TrimSpace(t.Name)
		if t.URL == "" && t.Name == "" {
			continue
		}
		c := notify.Channel{
			ID:             strings.TrimSpace(t.ID),
			Name:           t.Name,
			Enabled:        t.Enabled && t.URL != "",
			On:             notify.OnAlways,
			Events:         t.Triggers,
			Attempts:       min(max(t.Attempts, 0), notify.MaxAttempts),
			TimeoutSeconds: min(max(t.TimeoutSeconds, 0), notify.MaxTimeoutSeconds),
		}
		if len(t.Triggers) == 0 {
			c.On, c.Events = notify.OnNever, nil
		}
		method := strings.ToUpper(strings.TrimSpace(t.Method))
		if method != "GET" && method != "PUT" {
			method = "POST"
		}
		if t.Body == "" && method != "GET" && len(t.Headers) == 0 && discordWebhook(t.URL) {
			c.Kind, c.Discord = notify.KindDiscord, &notify.Discord{URL: t.URL}
		} else {
			c.Kind = notify.KindWebhook
			c.Webhook = &notify.Webhook{URL: t.URL, Method: method, Headers: t.Headers, Body: t.Body}
		}
		out = append(out, c)
	}
	identify(out)
	return settled(out), nil
}

func discordWebhook(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com", "ptb.discordapp.com", "canary.discordapp.com":
		return strings.HasPrefix(u.Path, "/api/webhooks/") || strings.HasPrefix(u.Path, "/api/v")
	}
	return false
}

// identify gives each channel without an id, or with one taken earlier in the
// list, the lowest free number.
func identify(out []notify.Channel) {
	taken := map[string]bool{}
	keep := make([]bool, len(out))
	for i, c := range out {
		if c.ID != "" && !taken[c.ID] {
			taken[c.ID], keep[i] = true, true
		}
	}
	next := 1
	for i := range out {
		if keep[i] {
			continue
		}
		for taken[strconv.Itoa(next)] {
			next++
		}
		out[i].ID = strconv.Itoa(next)
		taken[out[i].ID] = true
	}
}
