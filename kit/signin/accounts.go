package signin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Account is an account as the app and the contract see it. Epoch rises
// with everything that ends all of the account's sessions, so the app can
// tie what it remembers about a sign-in to it.
type Account struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Owner     bool      `json:"owner"`
	Via       Via       `json:"via"`
	Service   string    `json:"service,omitempty"`
	Created   time.Time `json:"created"`
	Seen      time.Time `json:"seen,omitzero"`
	Blocked   bool      `json:"blocked"`
	Password  bool      `json:"password"`
	TwoFactor bool      `json:"twoFactor"`
	Groups    []string  `json:"groups,omitempty"`
	Epoch     int       `json:"-"`
}

// ChangeKind is what Hooks.Changing hears is about to change.
type ChangeKind string

const (
	ChangeCreate ChangeKind = "create"
	ChangeRename ChangeKind = "rename"
	ChangeRole   ChangeKind = "role"
	ChangeBlock  ChangeKind = "block"
	ChangeRemove ChangeKind = "remove"
)

// Change is a change to an account the package is about to write. Name,
// Role and Blocked are what the account is after it. Via says how a new
// account signs in: ViaPassword, or ViaService with Service and the
// person's Issuer and Subject there.
type Change struct {
	Kind            ChangeKind
	Account         string
	Name            string
	Role            string
	Blocked         bool
	Via             Via
	Service         string
	Issuer, Subject string
}

func (a *Auth) viewOf(acc *account) Account {
	v := a.visitorOf(acc, acc.Via, acc.Service)
	return Account{
		ID: acc.ID, Name: acc.Name, Role: v.Role, Owner: acc.Owner, Via: acc.Via, Service: acc.Service,
		Created: acc.Created, Seen: acc.Seen, Blocked: acc.Blocked, Password: acc.hasPassword(),
		TwoFactor: acc.twoFactor(), Groups: acc.Groups, Epoch: acc.Epoch,
	}
}

func (a *Auth) getAccounts(w http.ResponseWriter, r *http.Request, _ *found) {
	all, err := a.accounts(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	out := make([]Account, 0, len(all))
	for _, acc := range all {
		out = append(out, a.viewOf(acc))
	}
	slices.SortStableFunc(out, func(x, y Account) int {
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

// removed keeps the name and id of a removed account until the app took
// its removal, so nobody new inherits what the app still keeps under them.
type removed struct {
	Name string    `json:"name"`
	At   time.Time `json:"at"`
}

// nameFree reports whether name, in any case, belongs to no account but
// except and to no removed account the app has not cleaned up yet. The
// caller holds mu.
func (a *Auth) nameFree(ctx context.Context, name, except string) (bool, error) {
	acc, err := a.byName(ctx, name)
	if err == nil {
		return acc.ID == except, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	gone, _, err := listOf[removed](ctx, a, kindRemoved)
	if err != nil {
		return false, err
	}
	for _, g := range gone {
		if strings.EqualFold(g.Name, name) {
			return false, nil
		}
	}
	return true, nil
}

// newAccountID returns an id that no account and no removed account holds,
// from Config.NewID when the app makes its own. The caller holds mu.
func (a *Auth) newAccountID(ctx context.Context) (string, error) {
	for range 5 {
		id := newID()
		if a.cfg.NewID != nil {
			var err error
			if id, err = a.cfg.NewID(); err != nil {
				return "", err
			}
		}
		if id == "" {
			continue
		}
		_, inUse := a.cfg.Store.Get(ctx, kindAccount, id)
		_, gone := a.cfg.Store.Get(ctx, kindRemoved, id)
		switch {
		case inUse != nil && !errors.Is(inUse, ErrNotFound):
			return "", inUse
		case gone != nil && !errors.Is(gone, ErrNotFound):
			return "", gone
		case inUse != nil && gone != nil:
			return id, nil
		}
	}
	return "", errors.New("signin: the app gave no free account id")
}

// changing tells the app about a change before it is written. The caller
// holds mu.
func (a *Auth) changing(ctx context.Context, c Change) error {
	if a.cfg.Hooks.Changing == nil {
		return nil
	}
	return a.cfg.Hooks.Changing(ctx, c)
}

func changeOf(kind ChangeKind, acc *account) Change {
	return Change{Kind: kind, Account: acc.ID, Name: acc.Name, Role: acc.Role, Blocked: acc.Blocked, Via: acc.Via, Service: acc.Service}
}

func (a *Auth) postAccount(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, smallBody, &in) || !a.checkNew(w, in.Password) {
		return
	}
	acc, err := a.createAccount(r, in.Name, in.Password, in.Role)
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	ok(w, map[string]any{"account": a.viewOf(acc)})
}

// createAccount adds a local account with a password, as the admin of r.
func (a *Auth) createAccount(r *http.Request, name, pw, role string) (*account, error) {
	if a.cfg.Owner {
		return nil, refuse(http.StatusConflict, "oneOwner")
	}
	name = strings.TrimSpace(name)
	if !validName(name) {
		return nil, refuse(http.StatusBadRequest, "nameInvalid")
	}
	if !slices.Contains(a.roles, role) {
		return nil, refuse(http.StatusBadRequest, "roleUnknown")
	}
	if err := a.newPassword(pw); err != nil {
		return nil, err
	}
	hash, err := a.hashPassword(pw)
	if err != nil {
		return nil, err
	}
	ctx := r.Context()
	acc := &account{Name: name, Role: role, Via: ViaPassword, Created: a.now(), Password: hash}
	err = a.Mint(r, func() error {
		free, err := a.nameFree(ctx, name, "")
		if err != nil {
			return err
		}
		if !free {
			return refuse(http.StatusConflict, "nameTaken")
		}
		if acc.ID, err = a.newAccountID(ctx); err != nil {
			return err
		}
		if err := a.changing(ctx, changeOf(ChangeCreate, acc)); err != nil {
			return err
		}
		return a.cfg.Store.Apply(ctx, a.doc(kindAccount, acc.ID, acc))
	})
	if err != nil {
		return nil, err
	}
	a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPassword, Result: "newAccount"})
	return acc, nil
}

// accountChange is what an admin changes about another account. Absent
// fields stay as they are.
type accountChange struct {
	Name    *string `json:"name"`
	Role    *string `json:"role"`
	Blocked *bool   `json:"blocked"`
}

func (a *Auth) patchAccount(w http.ResponseWriter, r *http.Request, f *found) {
	var in accountChange
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	acc, err := a.changeAccount(r, f, r.PathValue("id"), in)
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	ok(w, map[string]any{"account": a.viewOf(acc)})
}

// changeAccount renames, blocks or gives another role to the account id as
// the admin f. The owner stays the way out: nobody blocks it or changes its
// role, and only the owner renames it. Blocking or a lower role ends the
// account's sessions and tokens.
func (a *Auth) changeAccount(r *http.Request, f *found, id string, in accountChange) (*account, error) {
	if in.Role != nil && !slices.Contains(a.roles, *in.Role) {
		return nil, refuse(http.StatusBadRequest, "roleUnknown")
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if !validName(name) {
			return nil, refuse(http.StatusBadRequest, "nameInvalid")
		}
		in.Name = &name
	}
	ctx := r.Context()
	a.mu.Lock()
	acc, err := a.changeLocked(r, f, id, in)
	a.mu.Unlock()
	if err == nil {
		a.runEndings(ctx)
	}
	return acc, err
}

func (a *Auth) changeLocked(r *http.Request, f *found, id string, in accountChange) (*account, error) {
	ctx := r.Context()
	if _, err := a.stillValid(ctx, f); err != nil {
		return nil, refuse(http.StatusUnauthorized, "signInFirst")
	}
	acc, err := a.account(ctx, id)
	if err != nil {
		return nil, err
	}
	if acc.Owner && (in.Role != nil || in.Blocked != nil || (in.Name != nil && f.v.Account != acc.ID)) {
		return nil, refuse(http.StatusForbidden, "accountOwner")
	}
	var why Ending
	if in.Name != nil && *in.Name != acc.Name {
		free, err := a.nameFree(ctx, *in.Name, acc.ID)
		if err != nil {
			return nil, err
		}
		if !free {
			return nil, refuse(http.StatusConflict, "nameTaken")
		}
		acc.Name = *in.Name
		if err := a.changing(ctx, changeOf(ChangeRename, acc)); err != nil {
			return nil, err
		}
	}
	if in.Role != nil && *in.Role != acc.Role {
		if slices.Index(a.roles, *in.Role) > slices.Index(a.roles, acc.Role) {
			why = EndRole
		}
		acc.Role = *in.Role
		if err := a.changing(ctx, changeOf(ChangeRole, acc)); err != nil {
			return nil, err
		}
	}
	if in.Blocked != nil && *in.Blocked != acc.Blocked {
		if *in.Blocked {
			why = EndBlocked
		}
		acc.Blocked = *in.Blocked
		if err := a.changing(ctx, changeOf(ChangeBlock, acc)); err != nil {
			return nil, err
		}
	}
	var docs []Doc
	if why != "" {
		acc.Epoch++
		if docs, err = a.endAll(ctx, acc.ID); err != nil {
			return nil, err
		}
		docs = append(docs, a.endingsOf(acc, why)...)
	}
	docs = append(docs, a.doc(kindAccount, acc.ID, acc))
	return acc, a.cfg.Store.Apply(ctx, docs...)
}

func (a *Auth) deleteAccount(w http.ResponseWriter, r *http.Request, f *found) {
	if err := a.removeAccount(r, f, r.PathValue("id")); err != nil {
		a.answer(w, r, f, err)
		return
	}
	ok(w, nil)
}

// removeAccount removes the account id and every way in it had, as the
// admin f. Its name and id stay taken until the app took the removal.
func (a *Auth) removeAccount(r *http.Request, f *found, id string) error {
	a.mu.Lock()
	err := a.removeLocked(r, f, id)
	a.mu.Unlock()
	if err == nil {
		a.runEndings(r.Context())
	}
	return err
}

func (a *Auth) removeLocked(r *http.Request, f *found, id string) error {
	ctx := r.Context()
	if _, err := a.stillValid(ctx, f); err != nil {
		return refuse(http.StatusUnauthorized, "signInFirst")
	}
	acc, err := a.account(ctx, id)
	if err != nil {
		return err
	}
	if acc.Owner {
		return refuse(http.StatusForbidden, "accountOwner")
	}
	docs, err := a.endAll(ctx, acc.ID)
	if err != nil {
		return err
	}
	for _, kind := range []string{kindPasskey, kindIdentity, kindClaim} {
		more, err := a.wipe(ctx, kind, owned(acc.ID))
		if err != nil {
			return err
		}
		docs = append(docs, more...)
	}
	if err := a.changing(ctx, changeOf(ChangeRemove, acc)); err != nil {
		return err
	}
	docs = append(docs, gone(kindAccount, acc.ID), a.doc(kindRemoved, acc.ID, removed{Name: acc.Name, At: a.now()}), a.ending(acc.ID, EndRemoved, false))
	return a.cfg.Store.Apply(ctx, docs...)
}

func (a *Auth) missing(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		fail(w, http.StatusNotFound, "notFound")
		return
	}
	a.internal(w, err)
}
