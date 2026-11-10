// Package events describes what happened in an app in a form other members of
// a fortress can react to: the types, their schema and the Log an app keeps
// them in. The fortress carries them to other members and runs the rules.
package events

import (
	_ "embed"
	"regexp"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/status"
)

// Schema is the JSON Schema of an event.
//
//go:embed schema/v1.json
var Schema string

// Kind names what happened as dot-separated lower-case words, the thing
// first and the outcome last. Apps may add their own kinds in that form.
type Kind string

const (
	// BackupFailed means a backup ended without a usable copy.
	BackupFailed Kind = "backup.failed"
	// DownloadDone means a download finished and its files are in place.
	DownloadDone Kind = "download.done"
	// RunDone means a run of a job ended, whatever its outcome.
	RunDone Kind = "run.done"
	// FileReceived means someone sent a file and it was stored.
	FileReceived Kind = "file.received"
)

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Valid reports whether k has the form of a kind.
func (k Kind) Valid() bool {
	return kindPattern.MatchString(string(k))
}

// Event is one thing that happened in an app. Subject is what it happened to,
// such as a container, a package or a file name. Fields carries details for
// rules and webhook templates. Depth counts the events that led to this one
// through rules, so a chain of rules can be cut off.
type Event struct {
	ID       string            `json:"id"`
	Kind     Kind              `json:"kind"`
	At       time.Time         `json:"at"`
	Severity status.Severity   `json:"severity"`
	Source   Source            `json:"source"`
	Subject  string            `json:"subject,omitempty"`
	Link     string            `json:"link,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	Depth    int               `json:"depth,omitempty"`
}

// Source names the app and the instance an event comes from, with the ids of
// their status report.
type Source struct {
	App      string `json:"app"`
	Instance string `json:"instance"`
}
