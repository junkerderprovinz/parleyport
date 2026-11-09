package notify

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

var discordHosts = map[string]bool{
	"discord.com":           true,
	"discordapp.com":        true,
	"ptb.discord.com":       true,
	"canary.discord.com":    true,
	"ptb.discordapp.com":    true,
	"canary.discordapp.com": true,
}

// discordToken is the token of a Discord webhook address, its last path
// segment, or "" for any other address.
func discordToken(addr string) string {
	u, err := url.Parse(addr)
	if err != nil || !discordHosts[strings.ToLower(u.Hostname())] {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 5 && strings.HasPrefix(parts[1], "v") {
		parts = append(parts[:1], parts[2:]...)
	}
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "webhooks" || parts[2] == "" || parts[3] == "" {
		return ""
	}
	return parts[3]
}

const (
	discordSuccess = 0x57F287
	discordWarning = 0xFEE75C
	discordFailure = 0xED4245
	discordInfo    = 0x5865F2
)

// Discord's limits, counted in UTF-16 units as Discord counts them.
const (
	discordTitleMax       = 256
	discordDescriptionMax = 4096
	discordFieldNameMax   = 256
	discordFieldValueMax  = 1024
	discordFooterMax      = 2048
	discordFieldsMax      = 25
)

type discordMessage struct {
	Embeds []discordEmbed `json:"embeds"`
	// An empty list rather than none, so an @everyone in a file name pings
	// nobody.
	AllowedMentions struct {
		Parse []string `json:"parse"`
	} `json:"allowed_mentions"`
}

type discordEmbed struct {
	Title       string         `json:"title,omitempty"`
	URL         string         `json:"url,omitempty"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
	Footer      *discordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (d *Dispatcher) discordBody(e Event) string {
	em := discordEmbed{
		Title:       discordText(e.Title, discordTitleMax),
		Description: discordText(e.Body, discordDescriptionMax),
		Color:       discordInfo,
		Timestamp:   e.at().UTC().Format(time.RFC3339),
	}
	switch e.Severity {
	case SeveritySuccess:
		em.Color = discordSuccess
	case SeverityWarning:
		em.Color = discordWarning
	case SeverityFailure, SeverityCritical:
		em.Color = discordFailure
	}
	if httpURL(e.Link) {
		em.URL = e.Link
	}
	for _, f := range e.Facts {
		name, value := discordText(f.Name, discordFieldNameMax), discordText(f.Value, discordFieldValueMax)
		if name == "" || value == "" || len(em.Fields) == discordFieldsMax {
			continue
		}
		em.Fields = append(em.Fields, discordField{Name: name, Value: value, Inline: len([]rune(value)) <= 40})
	}
	if footer := discordText(d.source, discordFooterMax); footer != "" {
		em.Footer = &discordFooter{Text: footer}
	}
	msg := discordMessage{Embeds: []discordEmbed{em}}
	msg.AllowedMentions.Parse = []string{}
	b, _ := json.Marshal(msg)
	return string(b)
}

const discordMarkup = "\\*_~`|<>[]#-"

// discordText escapes Discord's markdown, so a name like "a_b_c" stays as it
// is, and shortens the text to limit with an ellipsis.
func discordText(v string, limit int) string {
	v = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' || r == 0x7f {
			return ' '
		}
		return r
	}, v))
	if v == "" {
		return ""
	}
	runes := []rune(v)
	var pieces []string
	total := 0
	for i, r := range runes {
		p := string(r)
		if strings.ContainsRune(discordMarkup, r) || r == '.' && listNumber(runes, i) {
			p = `\` + p
		}
		pieces = append(pieces, p)
		total += utf16Len(p)
	}
	if total <= limit {
		return strings.Join(pieces, "")
	}
	var b strings.Builder
	used := 0
	for _, p := range pieces {
		n := utf16Len(p)
		if used+n > limit-1 {
			break
		}
		b.WriteString(p)
		used += n
	}
	b.WriteString("…")
	return b.String()
}

// listNumber reports whether the dot at i ends a leading number followed by a
// space, which Discord would render as a numbered list.
func listNumber(runes []rune, i int) bool {
	if i == 0 || i+1 >= len(runes) || runes[i+1] != ' ' {
		return false
	}
	for _, r := range runes[:i] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}
