package signin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	challengeLife = 5 * time.Minute
	passkeyBody   = 64 << 10
	loginPasskey  = APIPrefix + "login/passkey"
	addPasskey    = APIPrefix + "me/passkeys"
	maxUsed       = 10_000
)

// relyingParty is the WebAuthn side of the app at its public address, or
// nil where passkeys cannot work: without a domain name, or over plain http
// anywhere but on localhost.
func (a *Auth) relyingParty() *webauthn.WebAuthn {
	u := a.public()
	if u == nil {
		return nil
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		return nil
	}
	if u.Scheme != "https" && (u.Scheme != "http" || host != "localhost") {
		return nil
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID: host, RPDisplayName: a.cfg.Name, RPOrigins: []string{u.Scheme + "://" + u.Host},
	})
	if err != nil {
		a.log.Warn("signin: passkeys at this address", "address", u.String(), "err", err)
		return nil
	}
	return w
}

func (a *Auth) public() *url.URL {
	if a.cfg.Public == nil {
		return nil
	}
	return a.cfg.Public()
}

type passkeyUser struct {
	acc   *account
	creds []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.acc.Handle }
func (u passkeyUser) WebAuthnName() string                       { return u.acc.Name }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.acc.Name }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (a *Auth) passkeysOf(r *http.Request, account string) (map[string]*passkeyDoc, []string, error) {
	all, ids, err := listOf[passkeyDoc](r.Context(), a, kindPasskey)
	if err != nil {
		return nil, nil, err
	}
	mine := ids[:0]
	for _, id := range ids {
		if all[id].Account == account {
			mine = append(mine, id)
		}
	}
	return all, mine, nil
}

// challenge is a WebAuthn ceremony the browser carries in a sealed cookie
// until it answers. The server keeps only the challenges already used.
type challenge struct {
	Data    webauthn.SessionData `json:"data"`
	Account string               `json:"account,omitempty"`
	Expires time.Time            `json:"expires"`
}

type usedChallenges struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// take marks a challenge used and reports whether it was not before.
func (u *usedChallenges) take(c string, until, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = map[string]time.Time{}
	}
	if len(u.m) >= maxUsed {
		for k, t := range u.m {
			if now.After(t) {
				delete(u.m, k)
			}
		}
	}
	if _, seen := u.m[c]; seen || len(u.m) >= maxUsed {
		return false
	}
	u.m[c] = until
	return true
}

func (a *Auth) sealChallenge(w http.ResponseWriter, r *http.Request, path, account string, data *webauthn.SessionData) error {
	c := challenge{Data: *data, Account: account, Expires: a.now().Add(challengeLife)}
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	sealed, err := a.sealFor("passkey-challenge", path, plain)
	if err != nil {
		return err
	}
	a.setCookie(w, r, "passkey", base64.RawURLEncoding.EncodeToString(sealed), path, challengeLife)
	return nil
}

// openChallenge reads the challenge of r once. A second answer to it, or
// one after five minutes, is refused.
func (a *Auth) openChallenge(w http.ResponseWriter, r *http.Request, path string) (*challenge, bool) {
	raw := a.readCookie(r, "passkey", path)
	a.clearCookie(w, r, "passkey", path)
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || raw == "" {
		return nil, false
	}
	plain, err := a.openFor("passkey-challenge", path, sealed)
	if err != nil {
		return nil, false
	}
	c := new(challenge)
	if json.Unmarshal(plain, c) != nil {
		return nil, false
	}
	now := a.now()
	if !now.Before(c.Expires) || !a.used.take(c.Data.Challenge, c.Expires, now) {
		return nil, false
	}
	return c, true
}

func (a *Auth) postPasskeyLoginOptions(w http.ResponseWriter, r *http.Request, _ *found) {
	if a.open.Load() {
		fail(w, http.StatusConflict, "setPasswordFirst")
		return
	}
	rp := a.relyingParty()
	if rp == nil {
		fail(w, http.StatusConflict, "passkeysUnavailable")
		return
	}
	assertion, data, err := rp.BeginDiscoverableMediatedLogin(protocol.MediationConditional, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err == nil {
		err = a.sealChallenge(w, r, loginPasskey, "", data)
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, assertion)
}

func (a *Auth) postPasskeyLogin(w http.ResponseWriter, r *http.Request, f *found) {
	body, good := readRaw(w, r, passkeyBody)
	if !good {
		return
	}
	ctx := r.Context()
	rp := a.relyingParty()
	if rp == nil {
		fail(w, http.StatusConflict, "passkeysUnavailable")
		return
	}
	c, good := a.openChallenge(w, r, loginPasskey)
	if !good {
		fail(w, http.StatusUnauthorized, "passkeyRefused")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		fail(w, http.StatusUnauthorized, "passkeyRefused")
		return
	}
	var doc *passkeyDoc
	var acc *account
	unknown := false
	find := func(rawID, handle []byte) (webauthn.User, error) {
		doc = new(passkeyDoc)
		if err := a.load(ctx, kindPasskey, passkeyID(rawID), doc); err != nil {
			unknown = true
			return nil, err
		}
		var err error
		if acc, err = a.account(ctx, doc.Account); err != nil || !bytes.Equal(acc.Handle, handle) {
			unknown = true
			return nil, errors.New("signin: passkey of another account")
		}
		return passkeyUser{acc: acc, creds: []webauthn.Credential{doc.Credential}}, nil
	}
	_, cred, err := rp.ValidatePasskeyLogin(find, c.Data, parsed)
	if unknown {
		a.note(ctx, r, Entry{Via: ViaPasskey, Result: "passkeyUnknown"})
		fail(w, http.StatusUnauthorized, "passkeyUnknown")
		return
	}
	if err != nil || acc == nil || !acc.hasPassword() {
		e := Entry{Via: ViaPasskey, Result: "passkeyRefused"}
		if acc != nil {
			e.Account, e.Name = acc.ID, acc.Name
		}
		a.note(ctx, r, e)
		fail(w, http.StatusUnauthorized, "passkeyRefused")
		return
	}
	if acc.Blocked {
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPasskey, Result: "blocked"})
		fail(w, http.StatusForbidden, "blocked")
		return
	}
	if cred.Authenticator.CloneWarning {
		a.note(ctx, r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPasskey, Result: "passkeyCounter"})
	}
	a.mu.Lock()
	if cur := new(passkeyDoc); a.load(ctx, kindPasskey, passkeyID(cred.ID), cur) == nil {
		cur.Credential.Authenticator.SignCount = cred.Authenticator.SignCount
		cur.Credential.Flags.BackupState = cred.Flags.BackupState
		cur.Used = a.now()
		err = a.cfg.Store.Apply(ctx, a.doc(kindPasskey, passkeyID(cred.ID), cur))
	}
	a.mu.Unlock()
	if err != nil {
		a.log.Warn("signin: noting a passkey's use", "err", err)
	}
	a.signedIn(w, r, f, acc.ID, acc.Epoch, ViaPasskey, "", nil)
}

type passkeyView struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Used    time.Time `json:"used,omitzero"`
	RPID    string    `json:"rpID"`
	Synced  bool      `json:"synced"`
	Here    bool      `json:"here"`
}

func (a *Auth) getPasskeys(w http.ResponseWriter, r *http.Request, f *found) {
	all, ids, err := a.passkeysOf(r, f.v.Account)
	if err != nil {
		a.internal(w, err)
		return
	}
	here := ""
	if u := a.public(); u != nil {
		here = u.Hostname()
	}
	out := []passkeyView{}
	for _, id := range ids {
		p := all[id]
		out = append(out, passkeyView{ID: id, Name: p.Name, Created: p.Created, Used: p.Used, RPID: p.RPID, Synced: p.Credential.Flags.BackupState, Here: p.RPID == here})
	}
	ok(w, map[string]any{"passkeys": out})
}

// passkeyAccount is the account a new passkey would be for, after the checks
// every step of adding one makes.
func (a *Auth) passkeyAccount(w http.ResponseWriter, r *http.Request, f *found) (*webauthn.WebAuthn, *account, bool) {
	rp := a.relyingParty()
	if rp == nil {
		fail(w, http.StatusConflict, "passkeysUnavailable")
		return nil, nil, false
	}
	if !a.fresh(f) {
		a.notFresh(w, r, f)
		return nil, nil, false
	}
	acc, good := a.localAccount(w, r, f)
	return rp, acc, good
}

func (a *Auth) postPasskeyOptions(w http.ResponseWriter, r *http.Request, f *found) {
	rp, acc, good := a.passkeyAccount(w, r, f)
	if !good {
		return
	}
	ctx := r.Context()
	if len(acc.Handle) == 0 {
		a.mu.Lock()
		cur, err := a.stillValid(ctx, f)
		if err == nil && len(cur.Handle) == 0 {
			handle := make([]byte, 32)
			rand.Read(handle)
			cur.Handle = handle
			err = a.cfg.Store.Apply(ctx, a.doc(kindAccount, cur.ID, cur))
		}
		a.mu.Unlock()
		if err != nil {
			a.internal(w, err)
			return
		}
		acc = cur
	}
	all, ids, err := a.passkeysOf(r, acc.ID)
	if err != nil {
		a.internal(w, err)
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, id := range ids {
		exclude = append(exclude, all[id].Credential.Descriptor())
	}
	creation, data, err := rp.BeginRegistration(passkeyUser{acc: acc},
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
	if err == nil {
		err = a.sealChallenge(w, r, addPasskey, acc.ID, data)
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	ok(w, creation)
}

func (a *Auth) postPasskey(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !readJSON(w, r, passkeyBody, &in) {
		return
	}
	rp, acc, good := a.passkeyAccount(w, r, f)
	if !good {
		return
	}
	c, good := a.openChallenge(w, r, addPasskey)
	if !good || c.Account != acc.ID {
		fail(w, http.StatusUnauthorized, "passkeyRefused")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Credential)
	if err != nil {
		fail(w, http.StatusBadRequest, "passkeyRefused")
		return
	}
	cred, err := rp.CreateCredential(passkeyUser{acc: acc}, c.Data, parsed)
	if err != nil {
		fail(w, http.StatusBadRequest, "passkeyRefused")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > maxNameLen {
		name = "Passkey"
	}
	doc := passkeyDoc{Account: acc.ID, Name: name, Created: a.now(), RPID: rp.Config.RPID, Credential: *cred}
	taken := false
	err = a.Mint(r, func() error {
		if a.load(r.Context(), kindPasskey, passkeyID(cred.ID), new(passkeyDoc)) == nil {
			taken = true
			return nil
		}
		return a.cfg.Store.Apply(r.Context(), a.doc(kindPasskey, passkeyID(cred.ID), doc))
	})
	if errors.Is(err, ErrNotFresh) {
		a.notFresh(w, r, f)
		return
	}
	if taken {
		fail(w, http.StatusConflict, "passkeyRefused")
		return
	}
	if err != nil {
		a.internal(w, err)
		return
	}
	a.note(r.Context(), r, Entry{Account: acc.ID, Name: acc.Name, Via: ViaPasskey, Result: "passkeyAdded"})
	ok(w, map[string]string{"id": passkeyID(cred.ID)})
}

func (a *Auth) patchPasskey(w http.ResponseWriter, r *http.Request, f *found) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, smallBody, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > maxNameLen {
		fail(w, http.StatusBadRequest, "nameInvalid")
		return
	}
	a.mu.Lock()
	err := a.ownPasskey(r.Context(), f.v.Account, r.PathValue("id"), func(id string, p *passkeyDoc) ([]Doc, error) {
		p.Name = name
		return []Doc{a.doc(kindPasskey, id, p)}, nil
	})
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	ok(w, nil)
}

func (a *Auth) deletePasskey(w http.ResponseWriter, r *http.Request, f *found) {
	a.mu.Lock()
	err := a.removePasskey(r.Context(), f.v.Account, r.PathValue("id"))
	a.mu.Unlock()
	if err != nil {
		a.answer(w, r, f, err)
		return
	}
	a.runEndings(r.Context())
	ok(w, nil)
}

// removePasskey deletes the passkey id of account. The caller holds mu.
func (a *Auth) removePasskey(ctx context.Context, account, id string) error {
	return a.ownPasskey(ctx, account, id, func(id string, _ *passkeyDoc) ([]Doc, error) {
		more, err := a.wayGone(ctx, account)
		return append(more, gone(kindPasskey, id)), err
	})
}

// ownPasskey writes what change makes of the passkey id of account. The
// caller holds mu.
func (a *Auth) ownPasskey(ctx context.Context, account, id string, change func(string, *passkeyDoc) ([]Doc, error)) error {
	p := new(passkeyDoc)
	if err := a.load(ctx, kindPasskey, id, p); err != nil || p.Account != account {
		return refuse(http.StatusNotFound, "notFound")
	}
	docs, err := change(id, p)
	if err != nil {
		return err
	}
	return a.cfg.Store.Apply(ctx, docs...)
}
