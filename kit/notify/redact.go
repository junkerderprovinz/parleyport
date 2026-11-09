package notify

import (
	"cmp"
	"encoding/base64"
	"errors"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// RedactedValue stands in for a secret in Redacted, and Merge reads it back as
// a secret the user did not retype.
const RedactedValue = "********"

var (
	addressPattern  = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)
	userinfoPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]*@`)
)

// Redact cuts every address in err's text down to its scheme and host, since
// webhook, Apprise and Healthchecks addresses carry their key in the path or
// the query.
func Redact(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(shortenAddresses(err.Error()))
}

func shortenAddresses(s string) string {
	return addressPattern.ReplaceAllStringFunc(s, func(raw string) string {
		scheme, rest, _ := strings.Cut(raw, "://")
		host, _, _ := strings.Cut(rest, "/")
		host, _, _ = strings.Cut(host, "?")
		host, _, _ = strings.Cut(host, "#")
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		return scheme + "://" + host
	})
}

// redactChannel takes every secret of c out of s, in the spellings an error
// or an echoing server may use, and then shortens the addresses.
func redactChannel(c Channel, s string) string {
	secrets := c.secrets()
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	for _, secret := range secrets {
		for _, form := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
			s = strings.ReplaceAll(s, form, RedactedValue)
		}
	}
	return shortenAddresses(s)
}

// minSecret is the length below which a value is left alone, since masking
// "5" would garble every status code in the message.
const minSecret = 4

func (c Channel) secrets() []string {
	var out []string
	add := func(vs ...string) {
		for _, v := range vs {
			if len(v) >= minSecret {
				out = append(out, v)
			}
		}
	}
	addURL := func(raw string) { add(urlSecrets(raw)...) }
	if c.Webhook != nil {
		addURL(c.Webhook.URL)
		for _, v := range c.Webhook.Headers {
			add(v)
			for _, word := range strings.Fields(v) {
				if len(word) >= 8 {
					add(word)
				}
			}
		}
	}
	if c.Discord != nil {
		addURL(c.Discord.URL)
	}
	if c.Slack != nil {
		addURL(c.Slack.URL)
	}
	if c.Gotify != nil {
		addURL(c.Gotify.URL)
		add(c.Gotify.Token)
	}
	if c.Ntfy != nil {
		addURL(c.Ntfy.URL)
		add(c.Ntfy.Token)
	}
	if c.Matrix != nil {
		addURL(c.Matrix.Homeserver)
		add(c.Matrix.Token)
	}
	if c.SMTP != nil {
		add(c.SMTP.Password, base64.StdEncoding.EncodeToString([]byte("\x00"+c.SMTP.Username+"\x00"+c.SMTP.Password)))
	}
	if c.Apprise != nil {
		addURL(c.Apprise.URL)
		for _, u := range c.Apprise.URLs {
			add(u)
			addURL(u)
		}
	}
	if c.Healthchecks != nil {
		for _, u := range checkURLs(c.Healthchecks) {
			addURL(u)
		}
	}
	return out
}

// urlSecrets are the parts of an address that may be a key: the login, the
// query values, long path segments and a Discord webhook's token.
func urlSecrets(raw string) []string {
	raw = strings.TrimSpace(raw)
	out := []string{discordToken(raw)}
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return out
	}
	authority, path, _ := strings.Cut(rest, "/")
	path, query, _ := strings.Cut(path, "?")
	query, _, _ = strings.Cut(query, "#")
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo := authority[:at]
		user, pass, _ := strings.Cut(userinfo, ":")
		out = append(out, userinfo, pass, base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		if unescaped, err := url.PathUnescape(pass); err == nil {
			out = append(out, unescaped)
		}
	}
	// A service address such as tgram://<bot token>/<chat> keeps its key
	// where the host would be.
	if scheme != "http" && scheme != "https" {
		out = append(out, authority)
	}
	for _, seg := range strings.Split(path, "/") {
		if len(seg) >= 12 && !strings.Contains(seg, marker) {
			out = append(out, seg)
		}
	}
	for _, pair := range strings.Split(query, "&") {
		_, v, _ := strings.Cut(pair, "=")
		if strings.Contains(v, marker) {
			continue
		}
		out = append(out, v)
		if unescaped, err := url.QueryUnescape(v); err == nil {
			out = append(out, unescaped)
		}
	}
	return out
}

// scrubbed masks the login of every address in the texts of e, since a name
// can hold a password somebody typed into it.
func scrubbed(e Event) Event {
	mask := func(s string) string { return userinfoPattern.ReplaceAllString(s, "${1}"+RedactedValue+"@") }
	e.Title, e.Body, e.HTML = mask(e.Title), mask(e.Body), mask(e.HTML)
	if e.Fields != nil {
		fields := make(map[string]string, len(e.Fields))
		for k, v := range e.Fields {
			fields[k] = mask(v)
		}
		e.Fields = fields
	}
	if e.Facts != nil {
		facts := make([]Fact, len(e.Facts))
		for i, f := range e.Facts {
			facts[i] = Fact{Name: f.Name, Value: mask(f.Value)}
		}
		e.Facts = facts
	}
	return e
}

// Redacted returns a copy of channels fit for a browser, with every token,
// password and header value replaced by RedactedValue. Addresses stay, since
// the user edits them.
func Redacted(channels []Channel) []Channel {
	out := clone(channels)
	for i := range out {
		c := &out[i]
		if c.Webhook != nil {
			for name, v := range c.Webhook.Headers {
				c.Webhook.Headers[name] = mask(v)
			}
		}
		if c.Gotify != nil {
			c.Gotify.Token = mask(c.Gotify.Token)
		}
		if c.Ntfy != nil {
			c.Ntfy.Token = mask(c.Ntfy.Token)
		}
		if c.Matrix != nil {
			c.Matrix.Token = mask(c.Matrix.Token)
		}
		if c.SMTP != nil {
			c.SMTP.Password = mask(c.SMTP.Password)
		}
	}
	return out
}

func mask(v string) string {
	if v == "" {
		return ""
	}
	return RedactedValue
}

// Merge puts the secrets Redacted took out of next back from prev. A secret
// comes back only to the channel with the same id and kind whose destination
// is unchanged, so a client that never saw a token cannot point the channel
// at its own server and have the token sent there. A RedactedValue that
// cannot come back becomes empty.
func Merge(next, prev []Channel) []Channel {
	old := make(map[string]Channel, len(prev))
	for _, c := range prev {
		old[c.ID] = c
	}
	out := clone(next)
	for i := range out {
		c := &out[i]
		p, ok := old[c.ID]
		ok = ok && p.Kind == c.Kind
		if c.Webhook != nil {
			same := ok && p.Webhook != nil && strings.TrimSpace(p.Webhook.URL) == strings.TrimSpace(c.Webhook.URL)
			for name, v := range c.Webhook.Headers {
				if v == RedactedValue {
					c.Webhook.Headers[name] = keep(same, func() string { return p.Webhook.Headers[name] })
				}
			}
		}
		if c.Gotify != nil && c.Gotify.Token == RedactedValue {
			c.Gotify.Token = keep(ok && p.Gotify != nil && p.Gotify.URL == c.Gotify.URL, func() string { return p.Gotify.Token })
		}
		if c.Ntfy != nil && c.Ntfy.Token == RedactedValue {
			c.Ntfy.Token = keep(ok && p.Ntfy != nil && p.Ntfy.URL == c.Ntfy.URL, func() string { return p.Ntfy.Token })
		}
		if c.Matrix != nil && c.Matrix.Token == RedactedValue {
			c.Matrix.Token = keep(ok && p.Matrix != nil && p.Matrix.Homeserver == c.Matrix.Homeserver, func() string { return p.Matrix.Token })
		}
		if c.SMTP != nil && c.SMTP.Password == RedactedValue {
			same := ok && p.SMTP != nil && p.SMTP.Host == c.SMTP.Host && p.SMTP.port() == c.SMTP.port() && p.SMTP.Username == c.SMTP.Username
			c.SMTP.Password = keep(same, func() string { return p.SMTP.Password })
		}
	}
	return out
}

func keep(same bool, stored func() string) string {
	if !same {
		return ""
	}
	return stored()
}

// clone copies channels deep enough that editing a block or a map of the copy
// leaves the original alone.
func clone(channels []Channel) []Channel {
	if channels == nil {
		return nil
	}
	out := make([]Channel, len(channels))
	for i, c := range channels {
		c.Events = slices.Clone(c.Events)
		if c.Webhook != nil {
			w := *c.Webhook
			w.Headers = maps.Clone(w.Headers)
			c.Webhook = &w
		}
		c.Discord = clonePtr(c.Discord)
		c.Slack = clonePtr(c.Slack)
		if c.Gotify != nil {
			g := *c.Gotify
			g.PriorityFailure, g.PrioritySuccess = clonePtr(g.PriorityFailure), clonePtr(g.PrioritySuccess)
			c.Gotify = &g
		}
		c.Ntfy = clonePtr(c.Ntfy)
		c.Matrix = clonePtr(c.Matrix)
		c.SMTP = clonePtr(c.SMTP)
		if c.Apprise != nil {
			a := *c.Apprise
			a.URLs = slices.Clone(a.URLs)
			c.Apprise = &a
		}
		if c.Healthchecks != nil {
			h := *c.Healthchecks
			h.ByKey = maps.Clone(h.ByKey)
			c.Healthchecks = &h
		}
		out[i] = c
	}
	return out
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
