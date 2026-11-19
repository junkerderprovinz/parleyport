// Package signintest checks an app and the store adapters against the
// sign-in contract, and brings what such tests need: a sign-in service that
// runs in the test process and an authenticator that makes passkeys in
// software.
package signintest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// Store checks an adapter against the Store contract. fresh is called once
// per check and returns an opener over new, empty data. Every call of the
// opener must return a store over that same data, as after a restart, so
// adapters that persist prove it.
func Store(t *testing.T, fresh func(t testing.TB) (open func() signin.Store)) {
	t.Helper()
	checks := []struct {
		name string
		run  func(t *testing.T, open func() signin.Store)
	}{
		{"get of a missing document is ErrNotFound", storeMissing},
		{"apply writes and get reads it back", storeRoundTrip},
		{"apply keeps its own copy of the data", storeCopies},
		{"a doc without data deletes", storeDelete},
		{"list returns one kind ordered by id", storeList},
		{"one apply runs in order", storeOrder},
		{"ids keep every character", storeOddIDs},
		{"concurrent applies all land", storeConcurrent},
		{"data survives reopening", storeReopen},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) { c.run(t, fresh(t)) })
	}
}

func put(t *testing.T, s signin.Store, docs ...signin.Doc) {
	t.Helper()
	if err := s.Apply(context.Background(), docs...); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func get(t *testing.T, s signin.Store, kind, id string) []byte {
	t.Helper()
	b, err := s.Get(context.Background(), kind, id)
	if err != nil {
		t.Fatalf("Get(%s, %s): %v", kind, id, err)
	}
	return b
}

func storeMissing(t *testing.T, open func() signin.Store) {
	_, err := open().Get(context.Background(), "account", "nobody")
	if !errors.Is(err, signin.ErrNotFound) {
		t.Fatalf("Get of a missing document = %v, want ErrNotFound", err)
	}
}

func storeRoundTrip(t *testing.T, open func() signin.Store) {
	s := open()
	put(t, s, signin.Doc{Kind: "account", ID: "1", Data: []byte(`{"a":1}`)})
	if got := get(t, s, "account", "1"); string(got) != `{"a":1}` {
		t.Fatalf("Get = %s", got)
	}
	put(t, s, signin.Doc{Kind: "account", ID: "1", Data: []byte(`{"a":2}`)})
	if got := get(t, s, "account", "1"); string(got) != `{"a":2}` {
		t.Fatalf("Get after overwrite = %s", got)
	}
	if _, err := s.Get(context.Background(), "session", "1"); !errors.Is(err, signin.ErrNotFound) {
		t.Fatalf("the same id under another kind = %v", err)
	}
}

func storeCopies(t *testing.T, open func() signin.Store) {
	s := open()
	data := []byte(`{"a":1}`)
	put(t, s, signin.Doc{Kind: "k", ID: "1", Data: data})
	data[2] = 'b'
	got := get(t, s, "k", "1")
	if string(got) != `{"a":1}` {
		t.Fatalf("a change to the caller's slice reached the store: %s", got)
	}
	got[2] = 'c'
	if again := get(t, s, "k", "1"); string(again) != `{"a":1}` {
		t.Fatalf("a change to a returned slice reached the store: %s", again)
	}
}

func storeDelete(t *testing.T, open func() signin.Store) {
	s := open()
	put(t, s, signin.Doc{Kind: "k", ID: "1", Data: []byte(`1`)})
	put(t, s, signin.Doc{Kind: "k", ID: "1"})
	if _, err := s.Get(context.Background(), "k", "1"); !errors.Is(err, signin.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	put(t, s, signin.Doc{Kind: "k", ID: "never"})
}

func storeList(t *testing.T, open func() signin.Store) {
	s := open()
	put(t, s,
		signin.Doc{Kind: "k", ID: "b", Data: []byte(`2`)},
		signin.Doc{Kind: "k", ID: "a", Data: []byte(`1`)},
		signin.Doc{Kind: "other", ID: "c", Data: []byte(`3`)},
	)
	docs, err := s.List(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range docs {
		got = append(got, d.Kind+"/"+d.ID+"="+string(d.Data))
	}
	if strings.Join(got, " ") != "k/a=1 k/b=2" {
		t.Fatalf("List = %v", got)
	}
	empty, err := s.List(context.Background(), "none")
	if err != nil || len(empty) != 0 {
		t.Fatalf("List of an empty kind = %v, %v", empty, err)
	}
}

func storeOrder(t *testing.T, open func() signin.Store) {
	s := open()
	put(t, s,
		signin.Doc{Kind: "k", ID: "1", Data: []byte(`1`)},
		signin.Doc{Kind: "k", ID: "1"},
		signin.Doc{Kind: "k", ID: "2", Data: []byte(`a`)},
		signin.Doc{Kind: "k", ID: "2", Data: []byte(`b`)},
	)
	if _, err := s.Get(context.Background(), "k", "1"); !errors.Is(err, signin.ErrNotFound) {
		t.Fatalf("a put followed by a delete left %v", err)
	}
	if got := get(t, s, "k", "2"); string(got) != "b" {
		t.Fatalf("the later of two puts lost: %s", got)
	}
}

func storeOddIDs(t *testing.T, open func() signin.Store) {
	s := open()
	ids := []string{"a/b", "ü-ö", "x y", `quote'"`, strings.Repeat("z", 200), "%2F"}
	for i, id := range ids {
		put(t, s, signin.Doc{Kind: "k", ID: id, Data: []byte(fmt.Sprint(i))})
	}
	for i, id := range ids {
		if got := get(t, s, "k", id); string(got) != fmt.Sprint(i) {
			t.Errorf("id %q read back %s", id, got)
		}
	}
}

func storeConcurrent(t *testing.T, open func() signin.Store) {
	s := open()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Go(func() {
			errs <- s.Apply(context.Background(), signin.Doc{Kind: "k", ID: fmt.Sprintf("%02d", i), Data: []byte(`1`)})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	docs, err := s.List(context.Background(), "k")
	if err != nil || len(docs) != 20 {
		t.Fatalf("List after 20 concurrent applies = %d docs, %v", len(docs), err)
	}
}

func storeReopen(t *testing.T, open func() signin.Store) {
	data := bytes.Repeat([]byte("x"), 100_000)
	put(t, open(), signin.Doc{Kind: "k", ID: "big", Data: data}, signin.Doc{Kind: "k", ID: "gone", Data: []byte(`1`)})
	put(t, open(), signin.Doc{Kind: "k", ID: "gone"})
	s := open()
	if got := get(t, s, "k", "big"); !bytes.Equal(got, data) {
		t.Fatalf("a document of %d bytes read back as %d", len(data), len(got))
	}
	if _, err := s.Get(context.Background(), "k", "gone"); !errors.Is(err, signin.ErrNotFound) {
		t.Fatalf("a deleted document came back after reopening: %v", err)
	}
}
