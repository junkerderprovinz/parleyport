package notify

import (
	"encoding/json"
	"net/url"
	"strings"
)

const marker = "%%"

// stripPlaceholders replaces every closed %%name%% with one letter, so an
// address whose host is a placeholder still parses, and reports whether every
// placeholder was closed.
func stripPlaceholders(s string) (string, bool) {
	if !strings.Contains(s, marker) {
		return s, true
	}
	var b strings.Builder
	for {
		before, rest, found := strings.Cut(s, marker)
		if !found {
			b.WriteString(s)
			return b.String(), true
		}
		_, after, closed := strings.Cut(rest, marker)
		if !closed {
			return "", false
		}
		b.WriteString(before)
		b.WriteByte('x')
		s = after
	}
}

// slot is where a value goes, which decides how it is escaped.
type slot int

const (
	slotPlain slot = iota
	slotURL
	slotHeader
	slotJSON
	slotForm
)

// expand replaces every closed %%name%% with its value from vars, escaped for
// the slot. An unknown name stays as written, so a typo shows in the message
// instead of quietly leaving a gap. Only the values are escaped, never the
// text around them, which is the user's own document.
func expand(s string, sl slot, vars map[string]string) string {
	if !strings.Contains(s, marker) {
		return s
	}
	var b strings.Builder
	for {
		before, rest, found := strings.Cut(s, marker)
		if !found {
			b.WriteString(s)
			return b.String()
		}
		name, after, closed := strings.Cut(rest, marker)
		if !closed {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(before)
		if v, ok := vars[strings.ToLower(strings.TrimSpace(name))]; ok {
			b.WriteString(escape(v, sl))
		} else {
			b.WriteString(marker + name + marker)
		}
		s = after
	}
}

func escape(v string, sl slot) string {
	switch sl {
	case slotURL, slotForm:
		return url.QueryEscape(v)
	case slotHeader:
		return stripControl(v)
	case slotJSON:
		b, _ := json.Marshal(v)
		return string(b[1 : len(b)-1])
	default:
		return v
	}
}

// stripControl removes what net/http refuses in a header value, so a line
// break in a title cannot start a header of its own.
func stripControl(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
}

// bodySlot reads how a body is escaped from its Content-Type header, the one
// the far end believes.
func bodySlot(headers map[string]string) slot {
	for name, value := range headers {
		if !strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			continue
		}
		ct := strings.ToLower(value)
		switch {
		case strings.Contains(ct, "json"):
			return slotJSON
		case strings.Contains(ct, "x-www-form-urlencoded"):
			return slotForm
		}
	}
	return slotPlain
}
