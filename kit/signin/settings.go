package signin

import (
	"context"
	"errors"
	"net/http"
)

const settingsID = "settings"

// settings are the app-wide choices an admin makes about sign-in. Each field
// reads false for a store that never saved them, so the defaults are the
// zero values.
type settings struct {
	// NoQuestion turns off the password question before a change that wants
	// a fresh sign-in. Without the question, the visitor signs in anew.
	NoQuestion bool `json:"noQuestion,omitempty"`
}

func (a *Auth) settings(ctx context.Context) (settings, error) {
	var s settings
	if err := a.load(ctx, kindMeta, settingsID, &s); err != nil && !errors.Is(err, ErrNotFound) {
		return settings{}, err
	}
	return s, nil
}

// asks reports whether the app may ask f's visitor for the password to make
// a stale sign-in fresh again, which only an account with a password can
// answer.
func (a *Auth) asks(ctx context.Context, f *found) bool {
	s, err := a.settings(ctx)
	if err != nil || s.NoQuestion || f.v.Account == "" {
		return false
	}
	acc, err := a.account(ctx, f.v.Account)
	return err == nil && acc.hasPassword()
}

// notFresh answers a change that wants a sign-in from moments ago, and says
// whether the app may ask for the password instead of a new sign-in.
func (a *Auth) notFresh(w http.ResponseWriter, r *http.Request, f *found) {
	fail(w, http.StatusForbidden, "signInAgain", "askPassword", a.asks(r.Context(), f))
}

func (a *Auth) getSettings(w http.ResponseWriter, r *http.Request, _ *found) {
	s, err := a.settings(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]bool{"askPassword": !s.NoQuestion})
}

func (a *Auth) patchSettings(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		AskPassword *bool `json:"askPassword"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	ctx := r.Context()
	a.mu.Lock()
	if _, err := a.stillValid(ctx, f); err != nil {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	s, err := a.settings(ctx)
	if err == nil && in.AskPassword != nil {
		s.NoQuestion = !*in.AskPassword
		err = a.cfg.Store.Apply(ctx, a.doc(kindMeta, settingsID, s))
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, map[string]bool{"askPassword": !s.NoQuestion})
}
