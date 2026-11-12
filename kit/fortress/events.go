package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/events"
	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/status"
)

// EventsAction is the permission behind Events: an app that reads the events
// of others lists it in Config.Uses, and switching it off keeps that app from
// reading them here.
const EventsAction = "events.read"

const (
	// watchEvery is how often the fortress reads the events of a member that
	// a rule waits on.
	watchEvery = 2 * time.Second
	maxRules   = 64
	maxMember  = 128
)

// Rule runs this app's Action whenever the member Member adds an event of
// Kind. The action gets the event as JSON and that member as its Caller.
type Rule struct {
	Member string      `json:"member"`
	Kind   events.Kind `json:"kind"`
	Action string      `json:"action"`
}

// eventsQuery is what a member asks of another's events. Tail asks for the
// cursor after the newest event alone.
type eventsQuery struct {
	After string `json:"after,omitempty"`
	Limit int    `json:"limit,omitempty"`
	Tail  bool   `json:"tail,omitempty"`
}

// Events reads the events member id added after the cursor after, at most
// status.MaxLogLimit of them. An empty cursor starts at the oldest event the
// member keeps; the page's Next is the cursor for the following read. It
// needs EventsAction in Config.Uses and the permission at the member's app.
func (f *Fortress) Events(ctx context.Context, id, after string) (events.Page, error) {
	if !slices.Contains(f.about.Uses, EventsAction) {
		return events.Page{}, fmt.Errorf("fortress: reading events needs %s in Config.Uses", EventsAction)
	}
	return f.readEvents(ctx, id, eventsQuery{After: after, Limit: status.MaxLogLimit})
}

func (f *Fortress) readEvents(ctx context.Context, id string, q eventsQuery) (events.Page, error) {
	body, err := json.Marshal(q)
	if err != nil {
		return events.Page{}, err
	}
	out, err := f.Act(ctx, id, EventsAction, body)
	if err != nil {
		return events.Page{}, err
	}
	var p events.Page
	err = json.Unmarshal(out, &p)
	return p, err
}

// serveEvents answers EventsAction from Config.Events.
func (f *Fortress) serveEvents(_ context.Context, _ Caller, body []byte) ([]byte, error) {
	var q eventsQuery
	if len(body) > 0 && json.Unmarshal(body, &q) != nil {
		return nil, &Refusal{Code: "bad_request"}
	}
	limit := min(q.Limit, status.MaxLogLimit)
	switch {
	case q.Tail:
		limit = 0
	case limit < 1:
		limit = status.DefaultLogLimit
	}
	return json.Marshal(f.events.Read(q.After, limit))
}

// Rules lists the rules this instance runs.
func (f *Fortress) Rules() []Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.book.Rules)
}

// SetRules replaces the rules this instance runs and keeps them in the store.
// A rule reads its member's events from the moment it first reaches it, so it
// never runs for what happened before.
func (f *Fortress) SetRules(rules []Rule) error {
	if err := f.checkRules(rules); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	before, cursors := f.book.Rules, f.book.Cursors
	f.book.Rules = slices.Clone(rules)
	f.book.Cursors = map[string]string{}
	for id, c := range cursors {
		if watched(rules, id) {
			f.book.Cursors[id] = c
		}
	}
	if err := f.saveLocked(); err != nil {
		f.book.Rules, f.book.Cursors = before, cursors
		return err
	}
	return nil
}

func (f *Fortress) checkRules(rules []Rule) error {
	if !slices.Contains(f.about.Uses, EventsAction) {
		return fmt.Errorf("fortress: rules need %s in Config.Uses", EventsAction)
	}
	if len(rules) > maxRules {
		return fmt.Errorf("fortress: more than %d rules", maxRules)
	}
	for i, r := range rules {
		_, ok := f.actions[r.Action]
		switch {
		case r.Member == "" || len(r.Member) > maxMember:
			return fmt.Errorf("fortress: rule %d names no member", i)
		case !r.Kind.Valid():
			return fmt.Errorf("fortress: rule %d: %q is no kind", i, r.Kind)
		case !ok || r.Action == EventsAction:
			return fmt.Errorf("fortress: rule %d: the app offers no action %q", i, r.Action)
		case slices.Contains(rules[:i], r):
			return fmt.Errorf("fortress: rule %d comes twice", i)
		}
	}
	return nil
}

func watched(rules []Rule, id string) bool {
	return slices.ContainsFunc(rules, func(r Rule) bool { return r.Member == id })
}

// watch reads the events of every member a rule waits on whose turn has come.
func (f *Fortress) watch(now time.Time) {
	f.mu.Lock()
	rules := slices.Clone(f.book.Rules)
	f.mu.Unlock()
	if len(rules) == 0 {
		return
	}
	for _, m := range f.group.Members() {
		if m.Kind != member.KindInstance || !m.Online() || !watched(rules, m.ID) || !f.due(f.watched, m.ID, now) {
			continue
		}
		f.again(f.watched, m.ID, now.Add(watchEvery))
		if f.react(m.ID, m.Name, rules) {
			f.again(f.watched, m.ID, now)
		}
	}
}

// react reads member id's new events and runs the rules they match. The
// cursor is saved before any action runs, so an action runs at most once for
// an event, even when the instance stops halfway. On first contact it only
// takes the cursor. It reports whether more events are waiting.
func (f *Fortress) react(id, device string, rules []Rule) bool {
	f.mu.Lock()
	cursor, known := f.book.Cursors[id]
	f.mu.Unlock()
	q := eventsQuery{After: cursor, Limit: status.MaxLogLimit, Tail: !known}
	ctx, cancel := context.WithTimeout(f.ctx, callTimeout)
	defer cancel()
	page, err := f.readEvents(ctx, id, q)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.DebugContext(ctx, "fortress: reading a member's events failed", "member", id, "err", err)
		}
		return false
	}

	f.mu.Lock()
	if !watched(f.book.Rules, id) || f.book.Cursors[id] != cursor {
		f.mu.Unlock()
		return false
	}
	if f.book.Cursors == nil {
		f.book.Cursors = map[string]string{}
	}
	f.book.Cursors[id] = page.Next
	if err := f.saveLocked(); err != nil {
		if known {
			f.book.Cursors[id] = cursor
		} else {
			delete(f.book.Cursors, id)
		}
		f.mu.Unlock()
		slog.WarnContext(ctx, "fortress: keeping the event cursor failed", "err", err)
		return false
	}
	f.mu.Unlock()

	from := Caller{ID: id, App: f.appOf(id), Device: device}
	for _, e := range page.Events {
		if e.Depth >= events.MaxDepth {
			continue
		}
		for _, r := range rules {
			if r.Member == id && r.Kind == e.Kind {
				f.fire(r.Action, from, e)
			}
		}
	}
	return len(page.Events) == status.MaxLogLimit
}

// fire runs action for the event e on its own goroutine, one step deeper in
// the chain than e.
func (f *Fortress) fire(action string, from Caller, e events.Event) {
	a := f.actions[action]
	body, err := json.Marshal(e)
	if err != nil || !f.enter() {
		return
	}
	go func() {
		defer f.wg.Done()
		ctx := events.WithDepth(f.ctx, e.Depth+1)
		if _, err := a.Run(ctx, from, body); err != nil {
			slog.WarnContext(ctx, "fortress: a rule's action failed", "action", action, "member", from.ID, "kind", e.Kind, "err", err)
		}
	}()
}
