package signin

import (
	"context"
	"errors"
)

// ErrNotFound is what Store.Get returns for a document that is not there.
var ErrNotFound = errors.New("signin: not found")

// Store keeps the package's documents for the app. Every document has a kind
// and an id, and Data is opaque JSON. One store belongs to one process: the
// package serialises its own writes, so an adapter only has to be safe for
// concurrent use and apply a batch all or nothing.
//
// The adapters in sqlstore, filestore and memstore pass signintest.Store.
type Store interface {
	// Get returns the data of one document, or an error wrapping
	// ErrNotFound.
	Get(ctx context.Context, kind, id string) ([]byte, error)
	// List returns every document of kind, ordered by id.
	List(ctx context.Context, kind string) ([]Doc, error)
	// Apply writes docs in order and all or nothing. A doc without Data is
	// deleted, and deleting one that is not there is no error.
	Apply(ctx context.Context, docs ...Doc) error
}

// Doc is one document in a Store.
type Doc struct {
	Kind string
	ID   string
	Data []byte
}
