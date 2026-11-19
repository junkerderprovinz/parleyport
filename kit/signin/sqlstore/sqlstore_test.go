package sqlstore_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
	"github.com/junkerderprovinz/parleyport/kit/signin/sqlstore"
)

func openDB(t testing.TB, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStoreContract(t *testing.T) {
	signintest.Store(t, func(t testing.TB) func() signin.Store {
		path := filepath.Join(t.TempDir(), "app.sqlite")
		return func() signin.Store {
			s, err := sqlstore.New(context.Background(), openDB(t, path), "signin_docs")
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	})
}

func TestNewRefusesATableNameThatIsNotAnIdentifier(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "app.sqlite"))
	for _, name := range []string{"", "x;drop table users", "Docs", "1docs", "a-b", "docs\"", string(make([]byte, 70))} {
		if _, err := sqlstore.New(context.Background(), db, name); err == nil {
			t.Errorf("table %q accepted", name)
		}
	}
}

func TestApplyIsAllOrNothing(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "app.sqlite"))
	s, err := sqlstore.New(context.Background(), db, "signin_docs")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Apply(ctx, signin.Doc{Kind: "k", ID: "1", Data: []byte(`1`)}); err != nil {
		t.Fatal(err)
	}
	// A trigger that refuses one id stands in for a write that fails half
	// way through a batch.
	if _, err := db.Exec(`CREATE TRIGGER refuse BEFORE INSERT ON signin_docs WHEN NEW.id = 'bad' BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	err = s.Apply(ctx,
		signin.Doc{Kind: "k", ID: "1"},
		signin.Doc{Kind: "k", ID: "2", Data: []byte(`2`)},
		signin.Doc{Kind: "k", ID: "bad", Data: []byte(`3`)},
	)
	if err == nil {
		t.Fatal("the batch went through")
	}
	if b, err := s.Get(ctx, "k", "1"); err != nil || string(b) != "1" {
		t.Fatalf("the delete before the failure stayed: %s, %v", b, err)
	}
	if _, err := s.Get(ctx, "k", "2"); err == nil {
		t.Fatal("the put before the failure stayed")
	}
}

func TestSchemaMatchesWhatNewCreates(t *testing.T) {
	db := openDB(t, filepath.Join(t.TempDir(), "app.sqlite"))
	if _, err := db.Exec(sqlstore.Schema("signin_docs")); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlstore.New(context.Background(), db, "signin_docs"); err != nil {
		t.Fatalf("New on a table made from Schema: %v", err)
	}
}
