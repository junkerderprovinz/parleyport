// Package filestore keeps the sign-in documents in one sealed JSON file, for
// apps without a database. The whole file is read at Open and written anew on
// every Apply, through a temporary file and a rename, so a crash leaves the
// old file or the new one.
package filestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

const (
	domain   = "signin/filestore/v1"
	maxBytes = 16 << 20
)

// Store is a signin.Store in one file.
type Store struct {
	path string
	seal signin.Sealer
	mu   sync.RWMutex
	docs map[string]map[string][]byte
}

// Open reads the store at path, sealed with seal. A missing file is an empty
// store. A file that does not open is an error, never an empty store, so a
// changed key cannot make the app look as if nobody had set a password.
func Open(path string, seal signin.Sealer) (*Store, error) {
	s := &Store{path: path, seal: seal, docs: map[string]map[string][]byte{}}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	defer func() { _ = f.Close() }()
	sealed, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("filestore: %w", err)
	}
	if len(sealed) > maxBytes {
		return nil, fmt.Errorf("filestore: %s is larger than %d bytes", path, maxBytes)
	}
	plain, err := seal.Open(domain, sealed)
	if err != nil {
		return nil, fmt.Errorf("filestore: %s does not open with this key: %w", path, err)
	}
	if err := json.Unmarshal(plain, &s.docs); err != nil {
		return nil, fmt.Errorf("filestore: %s: %w", path, err)
	}
	return s, nil
}

// Get implements signin.Store.
func (s *Store) Get(_ context.Context, kind, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.docs[kind][id]
	if !ok {
		return nil, fmt.Errorf("%s %q: %w", kind, id, signin.ErrNotFound)
	}
	return slices.Clone(b), nil
}

// List implements signin.Store.
func (s *Store) List(_ context.Context, kind string) ([]signin.Doc, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]signin.Doc, 0, len(s.docs[kind]))
	for id, b := range s.docs[kind] {
		out = append(out, signin.Doc{Kind: kind, ID: id, Data: slices.Clone(b)})
	}
	slices.SortFunc(out, func(a, b signin.Doc) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Apply implements signin.Store. The documents in memory change only once
// the file is written.
func (s *Store) Apply(_ context.Context, docs ...signin.Doc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]map[string][]byte, len(s.docs))
	for kind, ids := range s.docs {
		next[kind] = make(map[string][]byte, len(ids))
		for id, b := range ids {
			next[kind][id] = b
		}
	}
	for _, d := range docs {
		if len(d.Data) == 0 {
			delete(next[d.Kind], d.ID)
			continue
		}
		if next[d.Kind] == nil {
			next[d.Kind] = map[string][]byte{}
		}
		next[d.Kind][d.ID] = slices.Clone(d.Data)
	}
	if err := s.write(next); err != nil {
		return err
	}
	s.docs = next
	return nil
}

func (s *Store) write(docs map[string]map[string][]byte) error {
	plain, err := json.Marshal(docs)
	if err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	sealed, err := s.seal.Seal(domain, plain)
	if err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	if len(sealed) > maxBytes {
		return fmt.Errorf("filestore: the store would grow past %d bytes", maxBytes)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".signin-*")
	if err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return fmt.Errorf("filestore: %w", err)
	}
	if _, err := tmp.Write(sealed); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("filestore: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("filestore: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("filestore: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename itself durable. Some systems cannot sync a
// directory, and the file is already in place then.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
