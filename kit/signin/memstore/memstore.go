// Package memstore keeps the sign-in documents in memory, for tests and for
// apps that start fresh on every run.
package memstore

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// Store is a signin.Store in memory. The zero value is not ready, use New.
type Store struct {
	mu   sync.RWMutex
	docs map[string][]byte
	// fail, when set, is what every call returns, so a test can see what the
	// package does with a store that breaks.
	fail error
}

// New returns an empty store.
func New() *Store { return &Store{docs: map[string][]byte{}} }

// Break makes every later call return err, or work again with nil.
func (s *Store) Break(err error) {
	s.mu.Lock()
	s.fail = err
	s.mu.Unlock()
}

func key(kind, id string) string { return kind + "\x00" + id }

// Get implements signin.Store.
func (s *Store) Get(_ context.Context, kind, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.fail != nil {
		return nil, s.fail
	}
	b, ok := s.docs[key(kind, id)]
	if !ok {
		return nil, fmt.Errorf("%s %q: %w", kind, id, signin.ErrNotFound)
	}
	return slices.Clone(b), nil
}

// List implements signin.Store.
func (s *Store) List(_ context.Context, kind string) ([]signin.Doc, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.fail != nil {
		return nil, s.fail
	}
	var out []signin.Doc
	prefix := kind + "\x00"
	for k, b := range s.docs {
		if id, ok := strings.CutPrefix(k, prefix); ok {
			out = append(out, signin.Doc{Kind: kind, ID: id, Data: slices.Clone(b)})
		}
	}
	slices.SortFunc(out, func(a, b signin.Doc) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Apply implements signin.Store.
func (s *Store) Apply(_ context.Context, docs ...signin.Doc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	for _, d := range docs {
		if len(d.Data) == 0 {
			delete(s.docs, key(d.Kind, d.ID))
			continue
		}
		s.docs[key(d.Kind, d.ID)] = slices.Clone(d.Data)
	}
	return nil
}
