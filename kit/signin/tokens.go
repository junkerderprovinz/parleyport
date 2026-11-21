package signin

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

const (
	tokenLife    = 90 * 24 * time.Hour
	maxTokenDays = 3650
	maxNameLen   = 64
)

type tokenView struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Scopes  []string  `json:"scopes"`
	Created time.Time `json:"created"`
	Used    time.Time `json:"used,omitzero"`
	Expires time.Time `json:"expires,omitzero"`
}

func (a *Auth) getTokens(w http.ResponseWriter, r *http.Request, f *found) {
	all, ids, err := listOf[apiToken](r.Context(), a, kindToken)
	if err != nil {
		a.internal(w, err)
		return
	}
	out := []tokenView{}
	for _, id := range ids {
		if t := all[id]; t.Account == f.v.Account {
			out = append(out, tokenView{ID: id, Name: t.Name, Scopes: t.Scopes, Created: t.Created, Used: t.Used, Expires: t.Expires})
		}
	}
	slices.SortFunc(out, func(x, y tokenView) int { return x.Created.Compare(y.Created) })
	ok(w, map[string]any{"tokens": out})
}

func (a *Auth) postToken(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		Days   *int     `json:"days"`
		Never  bool     `json:"never"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > maxNameLen {
		fail(w, http.StatusBadRequest, "tokenNameMissing")
		return
	}
	if len(in.Scopes) == 0 {
		fail(w, http.StatusBadRequest, "scopeUnknown")
		return
	}
	for _, s := range in.Scopes {
		if !slices.Contains(a.scopes, s) {
			fail(w, http.StatusBadRequest, "scopeUnknown", "scope", s)
			return
		}
	}
	now := a.now()
	t := apiToken{Account: f.v.Account, Name: in.Name, Scopes: slices.Compact(slices.Sorted(slices.Values(in.Scopes))), Created: now}
	switch {
	case in.Never:
	case in.Days == nil:
		t.Expires = now.Add(tokenLife)
	case *in.Days < 1 || *in.Days > maxTokenDays:
		fail(w, http.StatusBadRequest, "badRequest")
		return
	default:
		t.Expires = now.Add(time.Duration(*in.Days) * 24 * time.Hour)
	}
	tok, err := token.New(a.cfg.TokenPrefix)
	if err != nil {
		a.internal(w, err)
		return
	}
	t.Digest = a.macHex("token", tok.Secret)
	err = a.Mint(r, func() error { return a.cfg.Store.Apply(r.Context(), a.doc(kindToken, tok.ID, t)) })
	if err == ErrNotFresh {
		a.notFresh(w, r, f)
		return
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	a.note(r.Context(), r, Entry{Account: f.v.Account, Name: f.v.Name, Via: ViaToken, Result: "tokenMade"})
	ok(w, map[string]any{"token": tokenView{ID: tok.ID, Name: t.Name, Scopes: t.Scopes, Created: t.Created, Expires: t.Expires}, "value": tok.Value})
}

func (a *Auth) deleteToken(w http.ResponseWriter, r *http.Request, f *found) {
	a.mu.Lock()
	err := a.removeToken(r.Context(), f.v.Account, r.PathValue("id"))
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	a.runEndings(r.Context())
	ok(w, nil)
}

// removeToken deletes the token id of account. The caller holds mu.
func (a *Auth) removeToken(ctx context.Context, account, id string) error {
	t := new(apiToken)
	if err := a.load(ctx, kindToken, id, t); err != nil || t.Account != account {
		return refuse(http.StatusNotFound, "notFound")
	}
	docs := []Doc{gone(kindToken, id)}
	if t.Legacy {
		more, err := a.wayGone(ctx, account)
		if err != nil {
			return err
		}
		docs = append(docs, more...)
	}
	return a.cfg.Store.Apply(ctx, docs...)
}

// byToken finds the visitor behind an API token: one in the kit's form by
// its id, an older one by the digest Legacy.Token works out.
func (a *Auth) byToken(ctx context.Context, value string) (Visitor, bool) {
	var id, digest string
	if tid, secret, ok := token.Parse(a.cfg.TokenPrefix, value); ok {
		id, digest = tid, a.macHex("token", secret)
	} else if a.cfg.Legacy.Token != nil {
		old, ok := a.cfg.Legacy.Token(value)
		if !ok {
			return Visitor{}, false
		}
		id, digest = legacyTokenID(old), old
	} else {
		return Visitor{}, false
	}
	t := new(apiToken)
	if err := a.load(ctx, kindToken, id, t); err != nil || !equal(t.Digest, digest) {
		return Visitor{}, false
	}
	now := a.now()
	if !t.Expires.IsZero() && !now.Before(t.Expires) {
		return Visitor{}, false
	}
	acc, err := a.account(ctx, t.Account)
	if err != nil || acc.Blocked {
		return Visitor{}, false
	}
	if !acc.hasPassword() && now.Sub(acc.Checked) > outsideRest {
		return Visitor{}, false
	}
	if now.Sub(t.Used) > seenEvery {
		a.touchToken(ctx, id)
	}
	v := a.visitorOf(acc, ViaToken, "")
	v.Scopes = t.Scopes
	return v, true
}

func (a *Auth) touchToken(ctx context.Context, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := new(apiToken)
	if err := a.load(ctx, kindToken, id, t); err != nil {
		return
	}
	t.Used = a.now()
	if err := a.cfg.Store.Apply(ctx, a.doc(kindToken, id, t)); err != nil {
		a.log.Warn("signin: noting a token's use", "err", err)
	}
}

func legacyTokenID(digest string) string { return "legacy-" + shortID("token", digest) }
