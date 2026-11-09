package notify

import (
	"strings"
	"time"
)

// Severity is how good or bad the news is. Empty means SeverityInfo.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeveritySuccess  Severity = "success"
	SeverityWarning  Severity = "warning"
	SeverityFailure  Severity = "failure"
	SeverityCritical Severity = "critical"
)

// bad reports whether a channel with On "failure" carries the event.
func (s Severity) bad() bool {
	return s == SeverityWarning || s == SeverityFailure || s == SeverityCritical
}

func (s Severity) failed() bool {
	return s == SeverityFailure || s == SeverityCritical
}

func (s Severity) or() Severity {
	if s == "" {
		return SeverityInfo
	}
	return s
}

// importance is Unraid's level for the severity.
func (s Severity) importance() string {
	switch s {
	case SeverityCritical:
		return "alert"
	case SeverityWarning, SeverityFailure:
		return "warning"
	default:
		return "normal"
	}
}

// Ping is a Healthchecks phase.
type Ping string

const (
	PingStart   Ping = "start"
	PingSuccess Ping = "success"
	PingFail    Ping = "fail"
	PingLog     Ping = "log"
)

// Fact is a named value a service shows beside the message, such as a field
// of a Discord embed.
type Fact struct {
	Name  string
	Value string
}

// Event is one thing worth telling. The app writes every text in the reader's
// language, the module adds none of its own.
//
// Webhook templates may use %%event%%, %%severity%%, %%ok%%, %%title%%,
// %%body%%, %%link%%, %%key%%, %%time%%, %%source%% and %%importance%%, and
// every name in Fields, which wins over these. Names are matched without
// regard to case, and an unknown name is left as written.
type Event struct {
	// Kind is the app's name for what happened, such as "run.failed". A
	// channel's Events list matches it.
	Kind     string
	Severity Severity
	Title    string
	Body     string
	// HTML is the body as HTML for Matrix, which shows it in place of Body.
	HTML string
	Link string
	// Key picks a Healthchecks check from ByKey, such as a job or a domain.
	Key string
	// At is when it happened. Zero means now.
	At time.Time
	// Ping is the Healthchecks phase this event reports. Empty pings no check.
	Ping   Ping
	Fields map[string]string
	Facts  []Fact
}

func (e Event) at() time.Time {
	if e.At.IsZero() {
		return time.Now()
	}
	return e.At
}

// vars are the names a webhook template may use.
func (e Event) vars(source string) map[string]string {
	ok := "true"
	if e.Severity.failed() {
		ok = "false"
	}
	v := map[string]string{
		"event":      e.Kind,
		"severity":   string(e.Severity.or()),
		"ok":         ok,
		"title":      e.Title,
		"body":       e.Body,
		"link":       e.Link,
		"key":        e.Key,
		"time":       e.at().UTC().Format(time.RFC3339),
		"source":     source,
		"importance": e.Severity.importance(),
	}
	for name, value := range e.Fields {
		v[strings.ToLower(strings.TrimSpace(name))] = value
	}
	return v
}

// lines joins the parts that are not empty, one per line.
func lines(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}
