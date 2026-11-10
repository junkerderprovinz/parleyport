package fortress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/member"
	"github.com/junkerderprovinz/parleyport/kit/relay"
)

// maxPermissions bounds the switches a fortress keeps, which any member can
// add to.
const maxPermissions = 1024

// Permission is whether the app From may run Action at the app To. Changed is
// when somebody last switched it, zero while nobody did and it is on.
type Permission struct {
	From    string
	To      string
	Action  string
	On      bool
	Changed time.Time
}

type permissionKey struct {
	From, To, Action string
}

func (k permissionKey) valid() bool {
	return validApp(k.From) && validApp(k.To) && validAction(k.Action)
}

func (k permissionKey) MarshalText() ([]byte, error) {
	return []byte(k.From + " " + k.To + " " + k.Action), nil
}

func (k *permissionKey) UnmarshalText(b []byte) error {
	parts := strings.Split(string(b), " ")
	if len(parts) != 3 {
		return fmt.Errorf("fortress: %q is no permission", b)
	}
	*k = permissionKey{From: parts[0], To: parts[1], Action: parts[2]}
	if !k.valid() {
		return fmt.Errorf("fortress: %q is no permission", b)
	}
	return nil
}

// switchState is the last switch of one permission: the instance By set it
// to On at At.
type switchState struct {
	On bool      `json:"on"`
	At time.Time `json:"at"`
	By string    `json:"by"`
}

// later reports whether s replaces t. Two switches at the same time are
// ordered by who made them, so every instance keeps the same one.
func (s switchState) later(t switchState) bool {
	if !s.At.Equal(t.At) {
		return s.At.After(t.At)
	}
	return s.By > t.By
}

type permissionTable map[permissionKey]switchState

// merge takes s for k if it is later than the switch held, and reports
// whether it did. A switch from beyond the clock skew would win over every
// real one until its time came, so it is refused.
func (t permissionTable) merge(k permissionKey, s switchState, now time.Time) bool {
	if s.At.IsZero() || s.At.After(now.Add(relay.ClockSkew)) {
		return false
	}
	old, ok := t[k]
	if ok && !s.later(old) || !ok && len(t) >= maxPermissions {
		return false
	}
	t[k] = s
	return true
}

// switchEntry is a switch as members pass it on.
type switchEntry struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Action string    `json:"action"`
	On     bool      `json:"on"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
}

func (e switchEntry) split() (permissionKey, switchState) {
	return permissionKey{From: e.From, To: e.To, Action: e.Action}, switchState{On: e.On, At: e.At, By: e.By}
}

// Permissions lists, for every action an app in the fortress uses and an app
// offers, whether the one may run it at the other.
func (f *Fortress) Permissions() []Permission {
	uses := map[string]map[string]bool{}
	offers := map[string]map[string]bool{}
	note := func(m map[string]map[string]bool, app string, names []string) {
		if m[app] == nil {
			m[app] = map[string]bool{}
		}
		for _, n := range names {
			m[app][n] = true
		}
	}
	note(uses, f.app.ID, f.about.Uses)
	note(offers, f.app.ID, f.about.Actions)
	for _, m := range f.Members() {
		if m.App.ID != "" {
			note(uses, m.App.ID, m.Uses)
			note(offers, m.App.ID, m.Actions)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Permission
	for from, used := range uses {
		for action := range used {
			for to, offered := range offers {
				if !offered[action] {
					continue
				}
				p := Permission{From: from, To: to, Action: action, On: true}
				if s, ok := f.book.Permissions[permissionKey{From: from, To: to, Action: action}]; ok {
					p.On, p.Changed = s.On, s.At
				}
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Action < b.Action
	})
	return out
}

// permitted reports whether app may run action here.
func (f *Fortress) permitted(app, action string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.book.Permissions[permissionKey{From: app, To: f.app.ID, Action: action}]
	return !ok || s.On
}

// SetPermission switches whether the app from may run action at the app to,
// here and on every instance reachable now. The others fetch it later.
func (f *Fortress) SetPermission(from, to, action string, on bool) error {
	k := permissionKey{From: from, To: to, Action: action}
	if !k.valid() {
		return fmt.Errorf("fortress: %s may %s at %s is no permission", from, action, to)
	}
	now := time.Now().UTC()
	f.mu.Lock()
	if f.book.Permissions == nil {
		f.book.Permissions = permissionTable{}
	}
	s := switchState{On: on, At: now, By: f.self}
	if old, ok := f.book.Permissions[k]; ok && !s.later(old) {
		s.At = old.At.Add(time.Millisecond)
	}
	before, had := f.book.Permissions[k]
	if !f.book.Permissions.merge(k, s, now) {
		f.mu.Unlock()
		return errors.New("fortress: no room for another permission")
	}
	if err := f.saveLocked(); err != nil {
		if had {
			f.book.Permissions[k] = before
		} else {
			delete(f.book.Permissions, k)
		}
		f.mu.Unlock()
		return err
	}
	f.mu.Unlock()

	body, err := json.Marshal(switchEntry{From: from, To: to, Action: action, On: s.On, At: s.At, By: s.By})
	if err != nil {
		return err
	}
	for _, m := range f.group.Members() {
		if m.Kind != member.KindInstance || !m.Online() || !f.enter() {
			continue
		}
		go func() {
			defer f.wg.Done()
			ctx, cancel := context.WithTimeout(f.ctx, callTimeout)
			defer cancel()
			_, _, _ = f.group.Call(ctx, m.ID, http.MethodPost, permissionsPath, body)
		}()
	}
	return nil
}

// takeSwitch merges a switch an instance made and passed on.
func (f *Fortress) takeSwitch(w http.ResponseWriter, r *http.Request, caller string) {
	var e switchEntry
	raw, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(raw, &e) != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	k, s := e.split()
	if !k.valid() || s.By != caller {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	f.mu.Lock()
	if f.book.Permissions == nil {
		f.book.Permissions = permissionTable{}
	}
	if f.book.Permissions.merge(k, s, time.Now()) {
		f.dirty = true
	}
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *Fortress) permissionList() []switchEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]switchEntry, 0, len(f.book.Permissions))
	for k, s := range f.book.Permissions {
		out = append(out, switchEntry{From: k.From, To: k.To, Action: k.Action, On: s.On, At: s.At, By: s.By})
	}
	return out
}

// pull fetches the switches member id knows and keeps the later ones.
func (f *Fortress) pull(ctx context.Context, id string, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	body, err := f.get(ctx, id, permissionsPath)
	var entries []switchEntry
	if err != nil || json.Unmarshal(body, &entries) != nil {
		f.again(f.synced, id, now.Add(retryAfter))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced[id] = now.Add(syncEvery)
	if f.book.Permissions == nil {
		f.book.Permissions = permissionTable{}
	}
	for _, e := range entries {
		if k, s := e.split(); k.valid() && f.book.Permissions.merge(k, s, now) {
			f.dirty = true
		}
	}
}

// enter counts one more call Close has to wait for, or reports false once
// the fortress is closing.
func (f *Fortress) enter() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.wg.Add(1)
	return true
}
