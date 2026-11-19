package signin

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

type accountView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Role     string    `json:"role"`
	Owner    bool      `json:"owner"`
	Via      Via       `json:"via"`
	Service  string    `json:"service,omitempty"`
	Created  time.Time `json:"created"`
	Seen     time.Time `json:"seen,omitzero"`
	Blocked  bool      `json:"blocked"`
	Password bool      `json:"password"`
	Groups   []string  `json:"groups,omitempty"`
}

func (a *Auth) viewOf(acc *account) accountView {
	v := a.visitorOf(acc, acc.Via, acc.Service)
	return accountView{
		ID: acc.ID, Name: acc.Name, Role: v.Role, Owner: acc.Owner, Via: acc.Via, Service: acc.Service,
		Created: acc.Created, Seen: acc.Seen, Blocked: acc.Blocked, Password: acc.hasPassword(), Groups: acc.Groups,
	}
}

func (a *Auth) getAccounts(w http.ResponseWriter, r *http.Request, _ *found) {
	all, err := a.accounts(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out := make([]accountView, 0, len(all))
	for _, acc := range all {
		out = append(out, a.viewOf(acc))
	}
	slices.SortStableFunc(out, func(x, y accountView) int {
		if x.Owner != y.Owner {
			if x.Owner {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	ok(w, map[string]any{"accounts": out})
}

func (a *Auth) getRoles(w http.ResponseWriter, _ *http.Request, _ *found) {
	ok(w, map[string]any{"roles": a.roles})
}

// validName reports whether name can name an account: 1 to 64 characters,
// none of them a control character or a comma, which would split a list of
// names.
func validName(name string) bool {
	if name == "" || len([]rune(name)) > maxNameLen {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) || c == ',' {
			return false
		}
	}
	return true
}

func (a *Auth) postAccount(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if a.cfg.Owner {
		fail(w, http.StatusConflict, "oneOwner")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !validName(in.Name) {
		fail(w, http.StatusBadRequest, "nameInvalid")
		return
	}
	if !slices.Contains(a.roles, in.Role) {
		fail(w, http.StatusBadRequest, "roleUnknown")
		return
	}
	if !a.checkNew(w, in.Password) {
		return
	}
	hash, err := a.hashPassword(in.Password)
	if err != nil {
		a.internal(w, err)
		return
	}
	acc := &account{ID: newID(), Name: in.Name, Role: in.Role, Via: ViaPassword, Created: a.now(), Password: hash}
	taken := false
	err = a.Mint(r, func() error {
		if _, err := a.byName(r.Context(), in.Name); err == nil {
			taken = true
			return nil
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		return a.cfg.Store.Apply(r.Context(), a.doc(kindAccount, acc.ID, acc))
	})
	switch {
	case errors.Is(err, ErrNotFresh):
		a.notFresh(w, r, f)
	case err != nil:
		a.internal(w, err)
	case taken:
		fail(w, http.StatusConflict, "nameTaken")
	default:
		a.note(r.Context(), r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "newAccount"})
		ok(w, map[string]any{"account": a.viewOf(acc)})
	}
}

func (a *Auth) patchAccount(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Blocked *bool   `json:"blocked"`
		Role    *string `json:"role"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	if in.Role != nil && !slices.Contains(a.roles, *in.Role) {
		fail(w, http.StatusBadRequest, "roleUnknown")
		return
	}
	ctx := r.Context()
	a.mu.Lock()
	if _, err := a.stillValid(ctx, f); err != nil {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	acc, err := a.account(ctx, r.PathValue("id"))
	if err != nil {
		a.mu.Unlock()
		a.missing(w, err)
		return
	}
	if acc.Owner {
		a.mu.Unlock()
		fail(w, http.StatusForbidden, "accountOwner")
		return
	}
	var why Ending
	if in.Blocked != nil && *in.Blocked && !acc.Blocked {
		why = EndBlocked
	}
	if in.Blocked != nil {
		acc.Blocked = *in.Blocked
	}
	if in.Role != nil {
		if slices.Index(a.roles, *in.Role) > slices.Index(a.roles, acc.Role) && why == "" {
			why = EndRole
		}
		acc.Role = *in.Role
	}
	docs := []Doc{a.doc(kindAccount, acc.ID, acc)}
	if why != "" {
		acc.Epoch++
		docs[0] = a.doc(kindAccount, acc.ID, acc)
		ended, err := a.endAll(r, acc.ID)
		if err != nil {
			a.mu.Unlock()
			a.internal(w, err)
			return
		}
		docs = append(docs, ended...)
		docs = append(docs, a.ending(acc.ID, why))
	}
	err = a.cfg.Store.Apply(ctx, docs...)
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	ok(w, map[string]any{"account": a.viewOf(acc)})
}

func (a *Auth) deleteAccount(w http.ResponseWriter, r *http.Request, f *found) {
	ctx := r.Context()
	a.mu.Lock()
	if _, err := a.stillValid(ctx, f); err != nil {
		a.mu.Unlock()
		fail(w, http.StatusUnauthorized, "signInFirst")
		return
	}
	acc, err := a.account(ctx, r.PathValue("id"))
	if err != nil {
		a.mu.Unlock()
		a.missing(w, err)
		return
	}
	if acc.Owner {
		a.mu.Unlock()
		fail(w, http.StatusForbidden, "accountOwner")
		return
	}
	docs, err := a.endAll(r, acc.ID)
	if err == nil {
		var more []Doc
		for _, kind := range []string{kindPasskey, kindIdentity} {
			if more, err = a.wipe(ctx, kind, owned(acc.ID)); err != nil {
				break
			}
			docs = append(docs, more...)
		}
	}
	if err == nil {
		docs = append(docs, gone(kindAccount, acc.ID), a.ending(acc.ID, EndRemoved))
		err = a.cfg.Store.Apply(ctx, docs...)
	}
	a.mu.Unlock()
	if err != nil {
		a.internal(w, err)
		return
	}
	a.runEndings(ctx)
	ok(w, nil)
}

func (a *Auth) missing(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		fail(w, http.StatusNotFound, "notFound")
		return
	}
	a.internal(w, err)
}
