// Package sqlstore keeps the sign-in documents in one table of the app's own
// SQLite database. It uses database/sql and brings no driver, so the app
// keeps the one it has.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

var tableRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Store is a signin.Store on one table.
type Store struct {
	db    *sql.DB
	table string
	// Writes from this process wait for each other here instead of in
	// SQLite's busy handler.
	mu sync.Mutex
}

// Schema is the statement that creates table, for an app that keeps its
// schema in numbered migrations of its own.
func Schema(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
	kind TEXT NOT NULL,
	id   TEXT NOT NULL,
	data BLOB NOT NULL,
	PRIMARY KEY (kind, id)
)`
}

// New returns a store on table in db and creates the table when it is
// missing. table must be a lower-case SQL identifier, because it goes into
// the statements as it is. The app sets the busy timeout on db.
func New(ctx context.Context, db *sql.DB, table string) (*Store, error) {
	if !tableRE.MatchString(table) {
		return nil, fmt.Errorf("sqlstore: table %q is not a lower-case identifier", table)
	}
	if _, err := db.ExecContext(ctx, Schema(table)); err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}
	return &Store{db: db, table: table}, nil
}

// Get implements signin.Store.
func (s *Store) Get(ctx context.Context, kind, id string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT data FROM `+s.table+` WHERE kind = ? AND id = ?`, kind, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s %q: %w", kind, id, signin.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}
	return b, nil
}

// List implements signin.Store.
func (s *Store) List(ctx context.Context, kind string) ([]signin.Doc, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, data FROM `+s.table+` WHERE kind = ? ORDER BY id`, kind)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []signin.Doc
	for rows.Next() {
		d := signin.Doc{Kind: kind}
		if err := rows.Scan(&d.ID, &d.Data); err != nil {
			return nil, fmt.Errorf("sqlstore: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: %w", err)
	}
	return out, nil
}

// Apply implements signin.Store in one transaction.
func (s *Store) Apply(ctx context.Context, docs ...signin.Doc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, d := range docs {
		if len(d.Data) == 0 {
			_, err = tx.ExecContext(ctx, `DELETE FROM `+s.table+` WHERE kind = ? AND id = ?`, d.Kind, d.ID)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO `+s.table+` (kind, id, data) VALUES (?, ?, ?)
				ON CONFLICT (kind, id) DO UPDATE SET data = excluded.data`, d.Kind, d.ID, d.Data)
		}
		if err != nil {
			return fmt.Errorf("sqlstore: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: %w", err)
	}
	return nil
}
