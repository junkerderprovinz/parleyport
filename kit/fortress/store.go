package fortress

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/group"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// about is what a member says it is.
type about struct {
	App     App      `json:"app"`
	Actions []string `json:"actions,omitempty"`
	Uses    []string `json:"uses,omitempty"`
	// Moved says the member answers on a phrase the fortress has left, and
	// hands the members from before the new keys at movedPath.
	Moved bool `json:"moved,omitempty"`
}

func (a about) valid() bool {
	if !validApp(a.App.ID) || len(a.App.Name) > maxText || len(a.App.Version) > maxText ||
		len(a.Actions) > maxNames || len(a.Uses) > maxNames {
		return false
	}
	for _, names := range [][]string{a.Actions, a.Uses} {
		for _, n := range names {
			if !validAction(n) {
				return false
			}
		}
	}
	return true
}

// book is what the fortress keeps beside its group.
type book struct {
	// Group is the fortress's group key, so a store written under another
	// phrase starts over.
	Group string `json:"group"`
	// Changed is when the book moved here from the phrase before.
	Changed     time.Time        `json:"changed,omitzero"`
	Members     map[string]about `json:"members,omitempty"`
	Permissions permissionTable  `json:"permissions,omitempty"`
	Rules       []Rule           `json:"rules,omitempty"`
	// Cursors are where the rules stand in each member's events.
	Cursors map[string]string `json:"cursors,omitempty"`
	// Behind are the members the app's own pairing let in that had not
	// followed it when Settle closed it.
	Behind map[string]straggler `json:"behind,omitempty"`
}

type straggler struct {
	Kind       member.Kind `json:"kind"`
	Name       string      `json:"name,omitempty"`
	Deployment string      `json:"deployment,omitempty"`
}

// loadBook reads the book kept under groupKey, or under previous, the group
// key of the phrase the fortress changed from.
func loadBook(raw []byte, groupKey, previous string) (book, error) {
	fresh := book{Group: groupKey}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fresh, nil
	}
	var b book
	if err := json.Unmarshal(raw, &b); err != nil {
		return book{}, fmt.Errorf("fortress: the store is damaged: %w", err)
	}
	switch {
	case b.Group == groupKey:
		return b, nil
	case previous != "" && b.Group == previous:
		b.Group, b.Changed = groupKey, time.Now().Round(0)
		return b, nil
	}
	return fresh, nil
}

func (f *Fortress) saveLocked() error {
	raw, err := json.Marshal(f.book)
	if err != nil {
		return err
	}
	if err := f.store.saveFortress(raw); err != nil {
		return err
	}
	f.dirty = false
	return nil
}

// memory keeps a group's state for as long as the fortress runs.
type memory struct {
	mu  sync.Mutex
	raw []byte
}

func (m *memory) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return bytes.Clone(m.raw), nil
}

func (m *memory) Save(raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.raw = bytes.Clone(raw)
	return nil
}

// splitStore keeps the fortress's group and its book in the one store the app
// gives. As a group.Store it is the group's part.
type splitStore struct {
	store group.Store

	mu  sync.Mutex
	doc stored
}

type stored struct {
	Group    json.RawMessage `json:"group,omitempty"`
	Fortress json.RawMessage `json:"fortress,omitempty"`
}

var _ group.Store = (*splitStore)(nil)

func (s *splitStore) load() error {
	raw, err := s.store.Load()
	if err != nil {
		return fmt.Errorf("fortress: reading the store: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &s.doc); err != nil {
		return fmt.Errorf("fortress: the store is damaged: %w", err)
	}
	return nil
}

func (s *splitStore) fortress() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.doc.Fortress)
}

func (s *splitStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.doc.Group), nil
}

func (s *splitStore) Save(raw []byte) error {
	return s.save(func(d *stored) { d.Group = bytes.Clone(raw) })
}

func (s *splitStore) saveFortress(raw []byte) error {
	return s.save(func(d *stored) { d.Fortress = bytes.Clone(raw) })
}

// save writes the document with change made, and keeps the change only once
// the write went through.
func (s *splitStore) save(change func(*stored)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.doc
	change(&next)
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.store.Save(raw); err != nil {
		return err
	}
	s.doc = next
	return nil
}
