// Package status is the contract every app of a fortress answers: one JSON
// report of how the app is doing and a log to page through, both behind the
// same check, so a member that may see one may see the other.
package status

import (
	_ "embed"
	"time"
)

// Contract is the version of the report format this package writes.
const Contract = 1

const (
	// StatusPath is where an app serves its report.
	StatusPath = "/api/fortress/v1/status"
	// LogPath is where an app serves its log.
	LogPath = "/api/fortress/v1/log"
)

// ReportSchema is the JSON Schema of a report.
//
//go:embed schema/v1.json
var ReportSchema string

// LogSchema is the JSON Schema of a log page.
//
//go:embed schema/log-v1.json
var LogSchema string

// Report is what an app says about itself. Contract and Counts are filled in
// by Handler, which also lifts State to match the worst item in NeedsYou.
type Report struct {
	Contract     int         `json:"contract"`
	App          App         `json:"app"`
	Instance     Instance    `json:"instance"`
	State        State       `json:"state"`
	Counts       Counts      `json:"counts"`
	NeedsYou     []Need      `json:"needsYou"`
	Work         []Task      `json:"work"`
	Next         []Scheduled `json:"next"`
	Capabilities []string    `json:"capabilities"`
	SampledAt    time.Time   `json:"sampledAt"`
}

// App names the app. ID is a lower-case slug that stays the same across
// versions and instances. Color and Icon are optional and let readers show the
// app in its own colour and with its logo: Color is #rrggbb, Icon an SVG data
// URI written by IconFromSVG.
type App struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	UI      string `json:"ui,omitempty"`
	Color   string `json:"color,omitempty"`
	Icon    string `json:"icon,omitempty"`
}

// Instance names the running copy of the app. Container and Mounts let other
// members match it to the container it runs in and translate its paths.
type Instance struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Container string  `json:"container,omitempty"`
	Mounts    []Mount `json:"mounts,omitempty"`
}

// Mount is one path the container sees and where it lives on the host.
type Mount struct {
	Container string `json:"container"`
	Host      string `json:"host"`
}

// Counts carries the lengths of NeedsYou and Work for dashboards that cannot
// map lists.
type Counts struct {
	NeedsYou int `json:"needsYou"`
	Work     int `json:"work"`
}

// Need is something the user should look at. ID stays the same for as long as
// the need lasts, so readers can tell an old item from a new one. Code is
// stable for machines, Text is in the language that was asked for.
type Need struct {
	ID       string    `json:"id"`
	Severity Severity  `json:"severity"`
	Code     string    `json:"code"`
	Text     string    `json:"text"`
	Since    time.Time `json:"since,omitzero"`
	Link     string    `json:"link,omitempty"`
}

// Task is work that is running. Progress runs from 0 to 1 and is nil when
// the app cannot tell. BlocksRestart says the host should not restart while it
// runs.
type Task struct {
	ID            string    `json:"id"`
	Kind          WorkKind  `json:"kind"`
	Title         string    `json:"title"`
	Progress      *float64  `json:"progress,omitempty"`
	StartedAt     time.Time `json:"startedAt"`
	BlocksRestart bool      `json:"blocksRestart"`
}

// Scheduled is work the app will start on its own at a set time.
type Scheduled struct {
	Kind  WorkKind  `json:"kind"`
	Title string    `json:"title"`
	At    time.Time `json:"at"`
}

// WorkKind sorts tasks for readers that show them by kind.
type WorkKind string

const (
	KindBackup   WorkKind = "backup"
	KindRestore  WorkKind = "restore"
	KindDownload WorkKind = "download"
	KindExtract  WorkKind = "extract"
	KindSync     WorkKind = "sync"
	KindUpdate   WorkKind = "update"
	KindCheck    WorkKind = "check"
	KindTransfer WorkKind = "transfer"
	KindOther    WorkKind = "other"
)

// LogQuery asks for the entries after a cursor. An empty After starts at the
// oldest entry the app still keeps.
type LogQuery struct {
	After string
	Limit int
	Lang  string
}

// LogPage is one page of the log, oldest entry first. Next is the cursor for
// the following call; when nothing newer exists, it repeats the cursor that
// was asked for, so a reader can poll with it.
type LogPage struct {
	Entries []LogEntry `json:"entries"`
	Next    string     `json:"next"`
}

// LogEntry is one line of the log.
type LogEntry struct {
	ID    string    `json:"id"`
	At    time.Time `json:"at"`
	Level Severity  `json:"level"`
	Code  string    `json:"code"`
	Text  string    `json:"text"`
	Link  string    `json:"link,omitempty"`
}
