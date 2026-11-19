package memstore_test

import (
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin"
	"github.com/junkerderprovinz/parleyport/kit/signin/memstore"
	"github.com/junkerderprovinz/parleyport/kit/signin/signintest"
)

func TestStoreContract(t *testing.T) {
	signintest.Store(t, func(testing.TB) func() signin.Store {
		s := memstore.New()
		return func() signin.Store { return s }
	})
}
