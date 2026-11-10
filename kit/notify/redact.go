package notify

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
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
		add(bodySecrets(c.Webhook.Body)...)
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
// password and header value replaced by RedactedValue. Addresses keep their
// host and shape for the user who edits them, with every part that may be a
// key masked, and a webhook body keeps its text with the values under key
// names masked.
func Redacted(channels []Channel) []Channel {
	out := clone(channels)
	for i := range out {
		c := &out[i]
		if c.Webhook != nil {
			c.Webhook.URL = maskURL(c.Webhook.URL)
			c.Webhook.Body = maskBody(c.Webhook.Body)
			for name, v := range c.Webhook.Headers {
				c.Webhook.Headers[name] = mask(v)
			}
		}
		if c.Discord != nil {
			c.Discord.URL = maskURL(c.Discord.URL)
		}
		if c.Slack != nil {
			c.Slack.URL = maskURL(c.Slack.URL)
		}
		if c.Gotify != nil {
			c.Gotify.URL = maskURL(c.Gotify.URL)
			c.Gotify.Token = mask(c.Gotify.Token)
		}
		if c.Ntfy != nil {
			c.Ntfy.URL = maskNtfy(c.Ntfy.URL)
			c.Ntfy.Token = mask(c.Ntfy.Token)
		}
		if c.Matrix != nil {
			c.Matrix.Homeserver = maskURL(c.Matrix.Homeserver)
			c.Matrix.Token = mask(c.Matrix.Token)
		}
		if c.SMTP != nil {
			c.SMTP.Password = mask(c.SMTP.Password)
		}
		if c.Apprise != nil {
			c.Apprise.URL = maskApprise(c.Apprise.URL)
			for j, u := range c.Apprise.URLs {
				c.Apprise.URLs[j] = maskURL(u)
			}
		}
		if c.Healthchecks != nil {
			c.Healthchecks.URL = maskURL(c.Healthchecks.URL)
			for key, u := range c.Healthchecks.ByKey {
				c.Healthchecks.ByKey[key] = maskURL(u)
			}
		}
	}
	return out
}

// maskAddress masks what may be a key in an address: the login, every query
// value, path segments long enough to be a token, the segments isKey picks
// and, outside http, the host, where a service address such as
// tgram://<bot token>/<chat> keeps its key.
func maskAddress(raw string, isKey func(segs []string, i int) bool) string {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return raw
	}
	rest, fragment, hasFragment := strings.Cut(rest, "#")
	rest, query, hasQuery := strings.Cut(rest, "?")
	authority, path, hasPath := strings.Cut(rest, "/")
	if s := strings.ToLower(strings.TrimSpace(scheme)); s != "http" && s != "https" && authority != "" {
		authority = RedactedValue
	} else if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = RedactedValue + authority[at:]
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if seg != "" && !strings.Contains(seg, marker) && (len(seg) >= 12 || isKey != nil && isKey(segs, i)) {
			segs[i] = RedactedValue
		}
	}
	pairs := strings.Split(query, "&")
	for i, pair := range pairs {
		if name, v, ok := strings.Cut(pair, "="); ok && v != "" && !strings.Contains(v, marker) {
			pairs[i] = name + "=" + RedactedValue
		}
	}
	out := scheme + "://" + authority
	if hasPath {
		out += "/" + strings.Join(segs, "/")
	}
	if hasQuery {
		out += "?" + strings.Join(pairs, "&")
	}
	if hasFragment {
		out += "#" + fragment
	}
	return out
}

func maskURL(raw string) string { return maskAddress(raw, nil) }

// maskNtfy also masks the topic, since on a public server whoever knows it
// can read and post.
func maskNtfy(raw string) string {
	return maskAddress(raw, func(segs []string, i int) bool { return i == len(segs)-1 })
}

// maskApprise also masks the key of a /notify/<key> endpoint, which the user
// picks and may keep short.
func maskApprise(raw string) string {
	return maskAddress(raw, func(segs []string, i int) bool { return i > 0 && segs[i-1] == "notify" })
}

// keyNames end the names a webhook body keeps a key under, such as token,
// api_key, accessToken, client_secret or password.
var keyNames = []string{"token", "key", "secret", "password", "passwd", "auth", "authorization"}

func keyName(name string) bool {
	name = strings.ToLower(name)
	return slices.ContainsFunc(keyNames, func(k string) bool { return strings.HasSuffix(name, k) })
}

// span is where a value sits in a text.
type span struct{ start, end int }

// bodyKeys finds the values a webhook body keeps under a key name: string
// values at any depth of a JSON document, else the values of a form. A value
// that is empty or holds a placeholder carries no key.
func bodyKeys(body string) []span {
	var found []span
	if t := strings.TrimSpace(body); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		found = jsonKeys(body)
	} else {
		found = formKeys(body)
	}
	return slices.DeleteFunc(found, func(sp span) bool {
		v := body[sp.start:sp.end]
		return v == "" || strings.Contains(v, marker)
	})
}

// jsonKeys scans the text rather than parsing it, since a body is a template
// that need not be JSON before its placeholders are filled, and the user's
// layout has to survive the mask.
func jsonKeys(s string) []span {
	var found []span
	for i := 0; i < len(s); {
		if s[i] != '"' {
			i++
			continue
		}
		end, ok := stringEnd(s, i)
		if !ok {
			break
		}
		var name string
		if json.Unmarshal([]byte(s[i:end]), &name) != nil {
			name = s[i+1 : end-1]
		}
		i = end
		j := skipSpace(s, end)
		if j == len(s) || s[j] != ':' {
			continue
		}
		j = skipSpace(s, j+1)
		if j == len(s) || s[j] != '"' {
			continue
		}
		vend, ok := stringEnd(s, j)
		if !ok {
			break
		}
		if keyName(name) {
			found = append(found, span{j + 1, vend - 1})
		}
		i = vend
	}
	return found
}

// stringEnd is the index just past the JSON string that starts at s[i].
func stringEnd(s string, i int) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true
		}
	}
	return 0, false
}

func skipSpace(s string, i int) int {
	for i < len(s) && strings.IndexByte(" \t\r\n", s[i]) >= 0 {
		i++
	}
	return i
}

func formKeys(s string) []span {
	var found []span
	at := 0
	for pair := range strings.SplitSeq(s, "&") {
		raw, v, ok := strings.Cut(pair, "=")
		name := raw
		if unescaped, err := url.QueryUnescape(raw); err == nil {
			name = unescaped
		}
		if ok && keyName(strings.TrimSpace(name)) {
			start := at + len(raw) + 1
			found = append(found, span{start, start + len(strings.TrimRight(v, " \t\r\n"))})
		}
		at += len(pair) + 1
	}
	return found
}

// maskBody masks the values a webhook body keeps under a key name and leaves
// the rest readable.
func maskBody(body string) string {
	var b strings.Builder
	last := 0
	for _, sp := range bodyKeys(body) {
		b.WriteString(body[last:sp.start])
		b.WriteString(RedactedValue)
		last = sp.end
	}
	b.WriteString(body[last:])
	return b.String()
}

// bodySecrets are the keys in a webhook body as written and as they go out
// once unescaped.
func bodySecrets(body string) []string {
	var out []string
	for _, sp := range bodyKeys(body) {
		v := body[sp.start:sp.end]
		out = append(out, v)
		var s string
		if json.Unmarshal([]byte(`"`+v+`"`), &s) == nil {
			out = append(out, s)
		}
		if s, err := url.QueryUnescape(v); err == nil {
			out = append(out, s)
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
// at its own server and have the token sent there. A masked address or body
// comes back only as Redacted left it. A RedactedValue that cannot come back
// empties its field.
func Merge(next, prev []Channel) []Channel {
	old := make(map[string]Channel, len(prev))
	for _, c := range prev {
		old[c.ID] = c
	}
	out := clone(next)
	for i := range out {
		c := &out[i]
		p, ok := old[c.ID]
		if !ok || p.Kind != c.Kind {
			p = Channel{}
		}
		p = p.withEveryBlock()
		if c.Webhook != nil {
			c.Webhook.URL = unmask(c.Webhook.URL, p.Webhook.URL, maskURL)
			same := strings.TrimSpace(p.Webhook.URL) == strings.TrimSpace(c.Webhook.URL)
			c.Webhook.Body = unmask(c.Webhook.Body, keep(same, func() string { return p.Webhook.Body }), maskBody)
			for name, v := range c.Webhook.Headers {
				if v == RedactedValue {
					c.Webhook.Headers[name] = keep(same, func() string { return p.Webhook.Headers[name] })
				}
			}
		}
		if c.Discord != nil {
			c.Discord.URL = unmask(c.Discord.URL, p.Discord.URL, maskURL)
		}
		if c.Slack != nil {
			c.Slack.URL = unmask(c.Slack.URL, p.Slack.URL, maskURL)
		}
		if c.Gotify != nil {
			c.Gotify.URL = unmask(c.Gotify.URL, p.Gotify.URL, maskURL)
			if c.Gotify.Token == RedactedValue {
				c.Gotify.Token = keep(p.Gotify.URL == c.Gotify.URL, func() string { return p.Gotify.Token })
			}
		}
		if c.Ntfy != nil {
			c.Ntfy.URL = unmask(c.Ntfy.URL, p.Ntfy.URL, maskNtfy)
			if c.Ntfy.Token == RedactedValue {
				c.Ntfy.Token = keep(p.Ntfy.URL == c.Ntfy.URL, func() string { return p.Ntfy.Token })
			}
		}
		if c.Matrix != nil {
			c.Matrix.Homeserver = unmask(c.Matrix.Homeserver, p.Matrix.Homeserver, maskURL)
			if c.Matrix.Token == RedactedValue {
				c.Matrix.Token = keep(p.Matrix.Homeserver == c.Matrix.Homeserver, func() string { return p.Matrix.Token })
			}
		}
		if c.SMTP != nil && c.SMTP.Password == RedactedValue {
			same := p.SMTP.Host == c.SMTP.Host && p.SMTP.port() == c.SMTP.port() && p.SMTP.Username == c.SMTP.Username
			c.SMTP.Password = keep(same, func() string { return p.SMTP.Password })
		}
		if c.Apprise != nil {
			c.Apprise.URL = unmask(c.Apprise.URL, p.Apprise.URL, maskApprise)
			var stored []string
			if p.Apprise.URL == c.Apprise.URL {
				stored = p.Apprise.URLs
			}
			c.Apprise.URLs = unmaskAll(c.Apprise.URLs, stored)
		}
		if c.Healthchecks != nil {
			c.Healthchecks.URL = unmask(c.Healthchecks.URL, p.Healthchecks.URL, maskURL)
			for key, u := range c.Healthchecks.ByKey {
				c.Healthchecks.ByKey[key] = unmask(u, p.Healthchecks.ByKey[key], maskURL)
			}
		}
	}
	return out
}

// withEveryBlock fills the settings blocks c lacks with empty ones, so Merge
// can compare against a channel that had none.
func (c Channel) withEveryBlock() Channel {
	c.Webhook = cmp.Or(c.Webhook, &Webhook{})
	c.Discord = cmp.Or(c.Discord, &Discord{})
	c.Slack = cmp.Or(c.Slack, &Slack{})
	c.Gotify = cmp.Or(c.Gotify, &Gotify{})
	c.Ntfy = cmp.Or(c.Ntfy, &Ntfy{})
	c.Matrix = cmp.Or(c.Matrix, &Matrix{})
	c.SMTP = cmp.Or(c.SMTP, &SMTP{})
	c.Apprise = cmp.Or(c.Apprise, &Apprise{})
	c.Healthchecks = cmp.Or(c.Healthchecks, &Healthchecks{})
	return c
}

// unmask returns stored when next is its masked form, and empty when next
// carries a mask it cannot take back.
func unmask(next, stored string, masked func(string) string) string {
	switch {
	case next == masked(stored):
		return stored
	case strings.Contains(next, RedactedValue):
		return ""
	default:
		return next
	}
}

// unmaskAll is unmask for a list. Stored addresses that mask alike come back
// in their stored order.
func unmaskAll(next, stored []string) []string {
	byMask := make(map[string][]string, len(stored))
	for _, u := range stored {
		m := maskURL(u)
		byMask[m] = append(byMask[m], u)
	}
	for i, u := range next {
		if q := byMask[u]; len(q) > 0 {
			next[i], byMask[u] = q[0], q[1:]
		} else if strings.Contains(u, RedactedValue) {
			next[i] = ""
		}
	}
	return next
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
