package events_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/events"
	"github.com/junkerderprovinz/parleyport/kit/notify"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

var source = events.Source{App: "example-app", Instance: "3f9c40"}

func add(t *testing.T, l *events.Log, kind events.Kind, subject string) events.Event {
	t.Helper()
	e, err := l.Add(context.Background(), events.Event{Kind: kind, Severity: status.SeverityInfo, Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func subjects(es []events.Event) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Subject)
	}
	return out
}

func TestAddFillsWhatTheLogOwns(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	before := time.Now()
	e := add(t, l, events.RunDone, "nightly")
	if e.ID == "" || e.Source != source || e.At.Before(before) || e.Depth != 0 {
		t.Errorf("added %+v", e)
	}
	other := add(t, l, events.RunDone, "nightly")
	if other.ID == e.ID {
		t.Errorf("two events share the id %q", e.ID)
	}
}

func TestAddRefusesWhatTheSchemaRefuses(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	fields := map[string]string{}
	for i := range 51 {
		fields[fmt.Sprint("f", i)] = "x"
	}
	for name, e := range map[string]events.Event{
		"bad kind":       {Kind: "Backup"},
		"bad severity":   {Kind: events.RunDone, Severity: "fatal"},
		"long subject":   {Kind: events.RunDone, Subject: strings.Repeat("s", 1001)},
		"long field":     {Kind: events.RunDone, Fields: map[string]string{"log": strings.Repeat("l", 2001)}},
		"too many field": {Kind: events.RunDone, Fields: fields},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := l.Add(context.Background(), e); err == nil {
				t.Error("added")
			}
		})
	}
	if p := l.Read("", 10); len(p.Events) != 0 {
		t.Errorf("the log keeps %d refused events", len(p.Events))
	}
}

func TestACursorReadsEveryEventOnceWhileEventsArrive(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source, Size: 1000})
	const total = 500
	var wg sync.WaitGroup
	for w := range 5 {
		wg.Go(func() {
			for i := range total / 5 {
				if _, err := l.Add(context.Background(), events.Event{Kind: events.RunDone, Subject: fmt.Sprintf("%d-%d", w, i)}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	seen := map[string]int{}
	var order []string
	cursor := ""
	read := func() {
		p := l.Read(cursor, 7)
		for _, e := range p.Events {
			seen[e.Subject]++
			order = append(order, e.ID)
		}
		cursor = p.Next
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			read()
		}
	}
	for range total {
		read()
	}
	if len(seen) != total {
		t.Errorf("read %d events of %d", len(seen), total)
	}
	for s, n := range seen {
		if n != 1 {
			t.Errorf("read %s %d times", s, n)
		}
	}
	all := l.Read("", total)
	for i, e := range all.Events {
		if i < len(order) && order[i] != e.ID {
			t.Fatalf("event %d came as %s, the log holds %s there", i, order[i], e.ID)
		}
	}
}

func TestNextRepeatsTheCursorWhenNothingIsNew(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	add(t, l, events.RunDone, "a")
	p := l.Read("", 10)
	again := l.Read(p.Next, 10)
	if len(again.Events) != 0 || again.Next != p.Next {
		t.Errorf("read %v with next %q after %q", subjects(again.Events), again.Next, p.Next)
	}
	add(t, l, events.RunDone, "b")
	if got := subjects(l.Read(p.Next, 10).Events); len(got) != 1 || got[0] != "b" {
		t.Errorf("read %v", got)
	}
}

func TestAnEmptyLogHasNoCursorToSkip(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	p := l.Read("", 10)
	add(t, l, events.RunDone, "first")
	if got := subjects(l.Read(p.Next, 10).Events); len(got) != 1 {
		t.Errorf("after the cursor of an empty log, read %v", got)
	}
}

func TestALimitOfZeroGivesTheEndOfTheLog(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	add(t, l, events.RunDone, "old")
	end := l.Read("", 0)
	if len(end.Events) != 0 {
		t.Errorf("read %v", subjects(end.Events))
	}
	add(t, l, events.RunDone, "new")
	if got := subjects(l.Read(end.Next, 10).Events); len(got) != 1 || got[0] != "new" {
		t.Errorf("after the end, read %v", got)
	}
}

func TestTheLogKeepsTheNewestEvents(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source, Size: 3})
	first := l.Read("", 0).Next
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		add(t, l, events.RunDone, s)
	}
	if got := strings.Join(subjects(l.Read(first, 10).Events), ""); got != "cde" {
		t.Errorf("read %q", got)
	}
}

func TestACursorOfAnotherLogStartsAtTheOldest(t *testing.T) {
	before := events.NewLog(events.LogConfig{Source: source})
	add(t, before, events.RunDone, "a")
	add(t, before, events.RunDone, "b")
	cursor := before.Read("", 10).Next

	restarted := events.NewLog(events.LogConfig{Source: source})
	add(t, restarted, events.RunDone, "c")
	if got := subjects(restarted.Read(cursor, 10).Events); len(got) != 1 || got[0] != "c" {
		t.Errorf("a cursor from before a restart read %v", got)
	}
	ahead := restarted.Read("", 10).Next + "0"
	for _, c := range []string{"garbage", "-1", cursor + "0", ahead} {
		if got := subjects(restarted.Read(c, 10).Events); len(got) != 1 {
			t.Errorf("cursor %q read %v", c, got)
		}
	}
}

func TestAPageStaysSmallWhateverTheLimit(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	fields := map[string]string{}
	for i := range 50 {
		fields[fmt.Sprint("f", i)] = strings.Repeat("x", 2000)
	}
	for range 20 {
		if _, err := l.Add(context.Background(), events.Event{Kind: events.RunDone, Fields: fields}); err != nil {
			t.Fatal(err)
		}
	}
	p := l.Read("", 20)
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > events.MaxPageBytes || len(p.Events) == 0 {
		t.Errorf("a page of %d events takes %d bytes", len(p.Events), len(body))
	}
	rest := l.Read(p.Next, 20)
	if len(p.Events)+len(rest.Events) > 20 || len(rest.Events) == 0 {
		t.Errorf("read %d and then %d", len(p.Events), len(rest.Events))
	}
}

func TestTheReaderCannotChangeTheLog(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	fields := map[string]string{"run": "1"}
	if _, err := l.Add(context.Background(), events.Event{Kind: events.RunDone, Fields: fields}); err != nil {
		t.Fatal(err)
	}
	fields["run"] = "2"
	l.Read("", 1).Events[0].Fields["run"] = "3"
	if got := l.Read("", 1).Events[0].Fields["run"]; got != "1" {
		t.Errorf("the log holds run %s", got)
	}
}

func TestAnEventCarriesTheDepthOfTheRuleThatCausedIt(t *testing.T) {
	l := events.NewLog(events.LogConfig{Source: source})
	ctx := events.WithDepth(context.Background(), 2)
	if events.Depth(ctx) != 2 || events.Depth(context.Background()) != 0 {
		t.Fatalf("depth %d in a context with 2", events.Depth(ctx))
	}
	e, err := l.Add(ctx, events.Event{Kind: events.RunDone})
	if err != nil {
		t.Fatal(err)
	}
	if e.Depth != 2 {
		t.Errorf("depth %d", e.Depth)
	}
	later, err := l.Add(context.Background(), events.Event{Kind: events.RunDone, Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if later.Depth != 1 {
		t.Errorf("an event the app carried its depth into has depth %d", later.Depth)
	}
}

type notifier struct {
	mu   sync.Mutex
	sent []notify.Event
}

func (n *notifier) Send(_ context.Context, e notify.Event) []notify.Result {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, e)
	return nil
}

func TestEveryEventGoesOutThroughNotify(t *testing.T) {
	n := &notifier{}
	l := events.NewLog(events.LogConfig{Source: source, Notify: n})
	e, err := l.Add(context.Background(), events.Event{
		Kind: events.BackupFailed, Severity: status.SeverityError, Subject: "web", Link: "/runs/1",
		Fields: map[string]string{"run": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if len(n.sent) != 1 {
		t.Fatalf("sent %d", len(n.sent))
	}
	got := n.sent[0]
	if got.Kind != string(events.BackupFailed) || got.Severity != notify.SeverityFailure || got.Title != "web" ||
		got.Link != "/runs/1" || !got.At.Equal(e.At) || got.Fields["run"] != "1" {
		t.Errorf("sent %+v", got)
	}
	var back events.Event
	if err := json.Unmarshal([]byte(got.Fields["json"]), &back); err != nil || back.ID != e.ID || back.Source != source {
		t.Errorf("the event as JSON is %q: %v", got.Fields["json"], err)
	}
}

func TestSeveritiesMapOntoNotify(t *testing.T) {
	n := &notifier{}
	l := events.NewLog(events.LogConfig{Source: source, Notify: n})
	for _, s := range []status.Severity{"", status.SeverityInfo, status.SeverityWarn, status.SeverityError} {
		if _, err := l.Add(context.Background(), events.Event{Kind: events.RunDone, Severity: s}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	want := map[notify.Severity]int{notify.SeverityInfo: 2, notify.SeverityWarning: 1, notify.SeverityFailure: 1}
	got := map[notify.Severity]int{}
	for _, e := range n.sent {
		got[e.Severity]++
		if e.Title != string(events.RunDone) {
			t.Errorf("an event without a subject has the title %q", e.Title)
		}
	}
	for s, c := range want {
		if got[s] != c {
			t.Errorf("%s: %d, want %d", s, got[s], c)
		}
	}
}
