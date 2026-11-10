package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/events"
)

// runs records what a rule hands an action.
type runs struct {
	mu    sync.Mutex
	got   []events.Event
	froms []Caller
}

func (r *runs) action(name string, then func(ctx context.Context)) Action {
	return Action{Name: name, Run: func(ctx context.Context, from Caller, body []byte) ([]byte, error) {
		var e events.Event
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.got = append(r.got, e)
		r.froms = append(r.froms, from)
		r.mu.Unlock()
		if then != nil {
			then(ctx)
		}
		return nil, nil
	}}
}

func (r *runs) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *runs) events() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got)
}

func newLog(app, instance string) *events.Log {
	return events.NewLog(events.LogConfig{Source: events.Source{App: app, Instance: instance}})
}

func emit(t *testing.T, l *events.Log, kind events.Kind, subject string) {
	t.Helper()
	if _, err := l.Add(context.Background(), events.Event{Kind: kind, Subject: subject}); err != nil {
		t.Fatal(err)
	}
}

// watching reports whether f has a cursor for member id, which it takes on
// first contact.
func (f *Fortress) watching(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.book.Cursors[id]
	return ok
}

// settle gives the rules a few rounds to act on anything still pending.
func settle() { time.Sleep(3 * watchEvery) }

func TestAMemberReadsAnotherAppsEventsByCursor(t *testing.T) {
	url := relayServer(t)
	log := newLog("alpha", "alpha-1")
	a := open(t, "alpha", "alpha-1", setup{relay: url, log: log})
	b := open(t, "bravo", "bravo-1", setup{relay: url, uses: []string{EventsAction}})
	meet(t, a, b)

	for _, s := range []string{"one", "two", "three"} {
		emit(t, log, events.RunDone, s)
	}
	p, err := b.f.Events(ctx(t), a.id, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Events) != 3 || p.Events[2].Subject != "three" || p.Events[0].Source.App != "alpha" {
		t.Fatalf("read %+v", p.Events)
	}
	again, err := b.f.Events(ctx(t), a.id, p.Next)
	if err != nil || len(again.Events) != 0 || again.Next != p.Next {
		t.Fatalf("read %+v with next %q after %q: %v", again.Events, again.Next, p.Next, err)
	}
	emit(t, log, events.RunDone, "four")
	more, err := b.f.Events(ctx(t), a.id, p.Next)
	if err != nil || len(more.Events) != 1 || more.Events[0].Subject != "four" {
		t.Fatalf("read %+v: %v", more.Events, err)
	}
}

func TestNoEventsWithoutPermission(t *testing.T) {
	url := relayServer(t)
	log := newLog("alpha", "alpha-1")
	a := open(t, "alpha", "alpha-1", setup{relay: url, log: log})
	notes := &runs{}
	b := open(t, "bravo", "bravo-1", setup{relay: url, uses: []string{EventsAction}, actions: []Action{notes.action("notes.add", nil)}})
	c := open(t, "charlie", "charlie-1", setup{relay: url})
	meet(t, a, b)
	meet(t, a, c)

	if _, err := c.f.Events(ctx(t), a.id, ""); err == nil {
		t.Error("an app that does not use events.read read events")
	}
	if _, err := c.f.Act(ctx(t), a.id, EventsAction, nil); !errors.Is(err, ErrPermissionOff) {
		t.Errorf("an app that does not use events.read asked for them and got %v", err)
	}
	if _, err := b.f.Events(ctx(t), c.id, ""); !errors.Is(err, ErrNoSuchAction) {
		t.Errorf("events of an app that keeps none: %v", err)
	}
	listed := false
	for _, p := range a.f.Permissions() {
		if p.Action == EventsAction && p.To == "alpha" {
			listed = listed || p.From == "bravo"
			if p.From == "charlie" {
				t.Errorf("listed %+v", p)
			}
		}
	}
	if !listed {
		t.Errorf("no switch for bravo reading alpha's events in %+v", a.f.Permissions())
	}

	if err := a.f.SetPermission("bravo", "alpha", EventsAction, false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.f.Events(ctx(t), a.id, ""); !errors.Is(err, ErrPermissionOff) {
		t.Errorf("read with the permission off: %v", err)
	}
	if err := b.f.SetRules([]Rule{{Member: a.id, Kind: events.BackupFailed, Action: "notes.add"}}); err != nil {
		t.Fatal(err)
	}
	emit(t, log, events.BackupFailed, "while off")
	settle()
	if n := notes.count(); n != 0 {
		t.Fatalf("a rule ran %d times with the permission off", n)
	}

	if err := a.f.SetPermission("bravo", "alpha", EventsAction, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to read alpha's events", func() bool { return b.f.watching(a.id) })
	emit(t, log, events.BackupFailed, "back on")
	waitFor(t, "the rule to run", func() bool { return notes.count() > 0 })
	settle()
	if got := notes.events(); len(got) != 1 || got[0].Subject != "back on" {
		t.Errorf("the rule ran for %+v", got)
	}
}

func TestARuleRunsItsActionOnceForEachEvent(t *testing.T) {
	url := relayServer(t)
	log := newLog("alpha", "alpha-1")
	a := open(t, "alpha", "alpha-1", setup{relay: url, log: log})
	notes := &runs{}
	s := setup{relay: url, uses: []string{EventsAction}, actions: []Action{notes.action("notes.add", nil)}}
	b := open(t, "bravo", "bravo-1", s)
	meet(t, a, b)

	emit(t, log, events.BackupFailed, "before the rule")
	rules := []Rule{{Member: a.id, Kind: events.BackupFailed, Action: "notes.add"}}
	if err := b.f.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to read alpha's events", func() bool { return b.f.watching(a.id) })
	emit(t, log, events.RunDone, "other kind")
	emit(t, log, events.BackupFailed, "web")
	waitFor(t, "the rule to run", func() bool { return notes.count() > 0 })
	settle()
	got := notes.events()
	if len(got) != 1 || got[0].Subject != "web" || got[0].Depth != 0 {
		t.Fatalf("the rule ran for %+v", got)
	}
	if from := notes.froms[0]; from.ID != a.id || from.App != "alpha" || from.Device != "alpha-1" {
		t.Errorf("the action ran for %+v", from)
	}

	_ = b.f.Close()
	b.f = reopen(t, b, s)
	if got := b.f.Rules(); !slices.Equal(got, rules) {
		t.Errorf("after a restart the rules are %+v", got)
	}
	settle()
	if n := notes.count(); n != 1 {
		t.Fatalf("after a restart the rule ran %d times", n)
	}
	emit(t, log, events.BackupFailed, "db")
	waitFor(t, "the rule to run again", func() bool { return notes.count() == 2 })
	settle()
	if n := notes.count(); n != 2 {
		t.Errorf("the rule ran %d times for two events", n)
	}
}

func TestARuleAddedAgainSkipsWhatHappenedMeanwhile(t *testing.T) {
	url := relayServer(t)
	log := newLog("alpha", "alpha-1")
	a := open(t, "alpha", "alpha-1", setup{relay: url, log: log})
	notes := &runs{}
	b := open(t, "bravo", "bravo-1", setup{relay: url, uses: []string{EventsAction}, actions: []Action{notes.action("notes.add", nil)}})
	meet(t, a, b)

	rules := []Rule{{Member: a.id, Kind: events.BackupFailed, Action: "notes.add"}}
	if err := b.f.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to read alpha's events", func() bool { return b.f.watching(a.id) })
	if err := b.f.SetRules(nil); err != nil {
		t.Fatal(err)
	}
	emit(t, log, events.BackupFailed, "without a rule")
	if err := b.f.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bravo to read alpha's events again", func() bool { return b.f.watching(a.id) })
	settle()
	if n := notes.count(); n != 0 {
		t.Errorf("the rule ran %d times for an event from before it", n)
	}
}

func TestAChainOfRulesEndsAtDepthThree(t *testing.T) {
	url := relayServer(t)
	logA, logB := newLog("alpha", "alpha-1"), newLog("bravo", "bravo-1")
	stepsA, stepsB := &runs{}, &runs{}
	step := func(r *runs, l *events.Log) Action {
		return r.action("chain.step", func(ctx context.Context) {
			if _, err := l.Add(ctx, events.Event{Kind: "chain.stepped"}); err != nil {
				t.Error(err)
			}
		})
	}
	a := open(t, "alpha", "alpha-1", setup{relay: url, log: logA, uses: []string{EventsAction}, actions: []Action{step(stepsA, logA)}})
	b := open(t, "bravo", "bravo-1", setup{relay: url, log: logB, uses: []string{EventsAction}, actions: []Action{step(stepsB, logB)}})
	meet(t, a, b)
	if err := a.f.SetRules([]Rule{{Member: b.id, Kind: "chain.stepped", Action: "chain.step"}}); err != nil {
		t.Fatal(err)
	}
	if err := b.f.SetRules([]Rule{{Member: a.id, Kind: "chain.stepped", Action: "chain.step"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both to read each other's events", func() bool { return a.f.watching(b.id) && b.f.watching(a.id) })

	emit(t, logA, "chain.stepped", "start")
	depths := func(l *events.Log) []int {
		var out []int
		for _, e := range l.Read("", 100).Events {
			out = append(out, e.Depth)
		}
		return out
	}
	waitFor(t, "the chain to reach depth three", func() bool { return slices.Contains(depths(logB), events.MaxDepth) })
	settle()
	if got := depths(logA); !slices.Equal(got, []int{0, 2}) {
		t.Errorf("alpha added events at depths %v", got)
	}
	if got := depths(logB); !slices.Equal(got, []int{1, 3}) {
		t.Errorf("bravo added events at depths %v", got)
	}
	if stepsA.count() != 1 || stepsB.count() != 2 {
		t.Errorf("alpha stepped %d times, bravo %d", stepsA.count(), stepsB.count())
	}
}

func TestAnActionCarriesTheDepthOfItsRule(t *testing.T) {
	show := Action{Name: "depth.show", Run: func(ctx context.Context, _ Caller, _ []byte) ([]byte, error) {
		return []byte(strconv.Itoa(events.Depth(ctx))), nil
	}}
	url := relayServer(t)
	a := open(t, "alpha", "alpha-1", setup{relay: url, actions: []Action{show}})
	b := open(t, "bravo", "bravo-1", setup{relay: url, uses: []string{"depth.show"}})
	meet(t, a, b)
	for _, tt := range []struct{ depth, want int }{{0, 0}, {2, 2}, {9, events.MaxDepth}} {
		out, err := b.f.Act(events.WithDepth(ctx(t), tt.depth), a.id, "depth.show", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := strconv.Atoi(string(out)); got != tt.want {
			t.Errorf("an action called at depth %d ran at %s", tt.depth, out)
		}
	}
}

func TestSetRulesRefusesRulesThatCannotRun(t *testing.T) {
	notes := &runs{}
	url := relayServer(t)
	b := open(t, "bravo", "bravo-1", setup{relay: url, uses: []string{EventsAction}, actions: []Action{notes.action("notes.add", nil)}})
	c := open(t, "charlie", "charlie-1", setup{relay: url, actions: []Action{notes.action("notes.add", nil)}})
	good := Rule{Member: "m1", Kind: events.BackupFailed, Action: "notes.add"}
	if err := b.f.SetRules([]Rule{good}); err != nil {
		t.Fatal(err)
	}
	many := make([]Rule, maxRules+1)
	for i := range many {
		many[i] = Rule{Member: strconv.Itoa(i), Kind: events.RunDone, Action: "notes.add"}
	}
	for name, rules := range map[string][]Rule{
		"unknown action":    {{Member: "m1", Kind: events.RunDone, Action: "notes.drop"}},
		"reading as action": {{Member: "m1", Kind: events.RunDone, Action: EventsAction}},
		"bad kind":          {{Member: "m1", Kind: "Run", Action: "notes.add"}},
		"no member":         {{Kind: events.RunDone, Action: "notes.add"}},
		"twice":             {good, good},
		"too many":          many,
	} {
		t.Run(name, func(t *testing.T) {
			if err := b.f.SetRules(rules); err == nil {
				t.Error("took them")
			}
			if got := b.f.Rules(); !slices.Equal(got, []Rule{good}) {
				t.Errorf("the rules became %+v", got)
			}
		})
	}
	if err := c.f.SetRules([]Rule{good}); err == nil {
		t.Error("an app that does not use events.read took a rule")
	}
}
