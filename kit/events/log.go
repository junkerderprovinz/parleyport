package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/notify"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

const (
	// DefaultSize is how many events a log keeps when LogConfig.Size is 0.
	DefaultSize = 500
	// MaxPageBytes bounds a page as JSON, so a page fits any answer between
	// members whatever the limit asked for. A page holds at least one event.
	MaxPageBytes = 1 << 20
	// The bounds of the schema, which Add holds every event to.
	maxID      = 200
	maxSubject = 1000
	maxLink    = 2048
	maxFields  = 50
	maxField   = 2000
	// notifyTimeout bounds one event's way out through notify, retries
	// included.
	notifyTimeout = 2 * time.Minute
)

// Notifier sends an event to the services a user set up. *notify.Dispatcher
// is one; an app whose channels change passes one that sends through its
// current Dispatcher.
type Notifier interface {
	Send(ctx context.Context, e notify.Event) []notify.Result
}

// LogConfig is what a Log runs on.
type LogConfig struct {
	// Source is the app and instance every event comes from.
	Source Source
	// Size is how many events the log keeps; the oldest go first.
	Size int
	// Notify, if set, gets every event as it is added. Its webhook templates
	// find the whole event as JSON under %%json%%.
	Notify Notifier
}

// Log keeps an app's newest events for the members that read them with a
// cursor. It lives in memory: a reader whose cursor comes from before a
// restart reads the new log from its oldest event, so it misses only what
// happened before the restart and was not read yet.
type Log struct {
	source Source
	size   int
	notify Notifier
	// epoch tells the cursors of this log from those of an earlier one.
	epoch string
	wg    sync.WaitGroup

	mu   sync.Mutex
	seq  uint64
	kept []kept
}

type kept struct {
	seq   uint64
	event Event
	size  int
}

// Page is a part of a log, oldest event first. Next is the cursor for the
// following read; when nothing newer exists, it repeats the cursor that was
// read after, so a reader can poll with it.
type Page struct {
	Events []Event `json:"events"`
	Next   string  `json:"next"`
}

// NewLog returns an empty log.
func NewLog(cfg LogConfig) *Log {
	if cfg.Size <= 0 {
		cfg.Size = DefaultSize
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return &Log{source: cfg.Source, size: cfg.Size, notify: cfg.Notify, epoch: hex.EncodeToString(b)}
}

// Add keeps e and returns it as readers see it: from the log's source, with
// an ID and a time if it had none, and at least the depth of a rule action
// that ctx carries. An action that adds its event later, after its context
// is gone, carries Depth(ctx) into the event itself.
func (l *Log) Add(ctx context.Context, e Event) (Event, error) {
	if e.Severity == "" {
		e.Severity = status.SeverityInfo
	}
	if err := e.check(); err != nil {
		return Event{}, err
	}
	e.Source = l.source
	e.Depth = max(e.Depth, Depth(ctx))
	e.Fields = maps.Clone(e.Fields)
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	l.mu.Lock()
	l.seq++
	if e.ID == "" {
		e.ID = l.cursor(l.seq)
	}
	body, err := json.Marshal(e)
	if err != nil {
		l.seq--
		l.mu.Unlock()
		return Event{}, err
	}
	if len(l.kept) == l.size {
		copy(l.kept, l.kept[1:])
		l.kept = l.kept[:len(l.kept)-1]
	}
	l.kept = append(l.kept, kept{seq: l.seq, event: e, size: len(body)})
	l.mu.Unlock()

	if l.notify != nil {
		out := notification(e, body)
		l.wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
			defer cancel()
			for _, r := range l.notify.Send(ctx, out) {
				if !r.OK() {
					slog.WarnContext(ctx, "events: a notification failed", "channel", r.Channel, "kind", e.Kind, "err", r.Err)
				}
			}
		})
	}
	return clone(e), nil
}

// Read returns up to limit events after the cursor after, the oldest first.
// An empty cursor, or one this log did not hand out, reads from the oldest
// event kept. A limit below 1 reads none and gives the cursor after the
// newest event, for a reader that wants only what comes from now on.
func (l *Log) Read(after string, limit int) Page {
	l.mu.Lock()
	defer l.mu.Unlock()
	seq, ours := l.parse(after)
	end := ""
	if l.seq > 0 {
		end = l.cursor(l.seq)
	}
	if limit < 1 {
		return Page{Events: []Event{}, Next: end}
	}
	start := 0
	if ours {
		start = sort.Search(len(l.kept), func(i int) bool { return l.kept[i].seq > seq })
	}
	p := Page{Events: []Event{}, Next: end}
	bytes := len(`{"events":[],"next":""}`) + len(end)
	for _, k := range l.kept[start:] {
		bytes += k.size + 1
		if len(p.Events) == limit || len(p.Events) > 0 && bytes > MaxPageBytes {
			break
		}
		p.Events = append(p.Events, clone(k.event))
		p.Next = l.cursor(k.seq)
	}
	return p
}

// Close waits for the events still on their way out through notify.
func (l *Log) Close() {
	l.wg.Wait()
}

func (l *Log) cursor(seq uint64) string {
	return l.epoch + "-" + strconv.FormatUint(seq, 10)
}

// parse reads a cursor this log handed out.
func (l *Log) parse(cursor string) (uint64, bool) {
	epoch, n, ok := strings.Cut(cursor, "-")
	if !ok || epoch != l.epoch {
		return 0, false
	}
	seq, err := strconv.ParseUint(n, 10, 64)
	if err != nil || seq > l.seq {
		return 0, false
	}
	return seq, true
}

func (e Event) check() error {
	switch {
	case !e.Kind.Valid() || len(e.Kind) > 100:
		return fmt.Errorf("events: %q is no kind", e.Kind)
	case e.Severity != status.SeverityInfo && e.Severity != status.SeverityWarn && e.Severity != status.SeverityError:
		return fmt.Errorf("events: %q is no severity", e.Severity)
	case len(e.ID) > maxID || len(e.Subject) > maxSubject || len(e.Link) > maxLink:
		return errors.New("events: id, subject or link too long")
	case len(e.Fields) > maxFields:
		return fmt.Errorf("events: more than %d fields", maxFields)
	case e.Depth < 0:
		return errors.New("events: negative depth")
	}
	for _, v := range e.Fields {
		if len(v) > maxField {
			return fmt.Errorf("events: a field longer than %d bytes", maxField)
		}
	}
	return nil
}

func clone(e Event) Event {
	e.Fields = maps.Clone(e.Fields)
	return e
}

// notification is e as notify sends it, with the event as JSON in the field
// json for webhook templates.
func notification(e Event, body []byte) notify.Event {
	severity := notify.SeverityInfo
	switch e.Severity {
	case status.SeverityWarn:
		severity = notify.SeverityWarning
	case status.SeverityError:
		severity = notify.SeverityFailure
	}
	title := e.Subject
	if title == "" {
		title = string(e.Kind)
	}
	fields := maps.Clone(e.Fields)
	if fields == nil {
		fields = map[string]string{}
	}
	fields["json"] = string(body)
	return notify.Event{Kind: string(e.Kind), Severity: severity, Title: title, Link: e.Link, At: e.At, Fields: fields}
}

type depthKey struct{}

// MaxDepth is where a chain of rules ends: an event at this depth or deeper
// sets off no rule.
const MaxDepth = 3

// WithDepth returns ctx for an action a rule runs at depth n, so the events
// the action adds carry it.
func WithDepth(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, depthKey{}, n)
}

// Depth is the depth of the rule action ctx belongs to, 0 outside one.
func Depth(ctx context.Context) int {
	n, _ := ctx.Value(depthKey{}).(int)
	return n
}
