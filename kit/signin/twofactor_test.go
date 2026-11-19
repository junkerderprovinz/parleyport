package signin_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/totp"
)

// twoFactor turns two-factor on for b's account and returns the secret and
// the recovery codes.
func twoFactor(t *testing.T, a *app, b *browser) ([]byte, []string) {
	t.Helper()
	r := b.api("POST", "me/totp", map[string]any{})
	want(t, r, 200, "")
	m := r.json(t)
	if !strings.HasPrefix(m["uri"].(string), "otpauth://totp/") {
		t.Fatalf("setup %v", m)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m["secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	want(t, b.api("POST", "me/totp/confirm", map[string]string{"code": "000000"}), 401, "wrongCode")
	r = b.api("POST", "me/totp/confirm", map[string]string{"code": totp.Code(secret, a.clock.Now())})
	want(t, r, 200, "")
	var codes []string
	for _, c := range r.json(t)["codes"].([]any) {
		codes = append(codes, c.(string))
	}
	a.clock.Add(30 * time.Second)
	return secret, codes
}

func TestTwoFactorAsksForTheCodeAfterThePassword(t *testing.T) {
	a := newApp(t)
	secret, codes := twoFactor(t, a, a.owner())
	if len(codes) != 10 {
		t.Fatalf("%d recovery codes", len(codes))
	}
	b := a.browser()
	r := b.api("POST", "login", map[string]string{"password": ownerPassword})
	if r.Status != 200 || r.json(t)["step"] != "code" {
		t.Fatalf("login with two-factor = %d %s", r.Status, r.Body)
	}
	if b.visitor().Via != "" {
		t.Fatal("the password alone signed in")
	}
	want(t, b.api("POST", "login/totp", map[string]string{"code": "123456"}), 401, "wrongCode")
	want(t, b.api("POST", "login/totp", map[string]string{"code": totp.Code(secret, a.clock.Now())}), 200, "")
	if b.visitor().Via == "" {
		t.Fatal("password and code did not sign in")
	}
}

func TestACodeCountsOnce(t *testing.T) {
	a := newApp(t)
	secret, _ := twoFactor(t, a, a.owner())
	code := totp.Code(secret, a.clock.Now())
	first := a.browser()
	first.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, first.api("POST", "login/totp", map[string]string{"code": code}), 200, "")

	a.open()
	second := a.browser()
	second.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, second.api("POST", "login/totp", map[string]string{"code": code}), 401, "wrongCode")
}

func TestARecoveryCodeCountsOnce(t *testing.T) {
	a := newApp(t)
	_, codes := twoFactor(t, a, a.owner())
	b := a.browser()
	b.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, b.api("POST", "login/totp", map[string]string{"code": strings.ToUpper(codes[3])}), 200, "")
	c := a.browser()
	c.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, c.api("POST", "login/totp", map[string]string{"code": codes[3]}), 401, "wrongCode")
	me := b.api("GET", "me", nil).json(t)
	if me["recoveryLeft"] != float64(9) {
		t.Fatalf("recoveryLeft %v", me["recoveryLeft"])
	}
}

func TestWrongCodesCountPerAccountNotPerPassword(t *testing.T) {
	a := newApp(t)
	secret, _ := twoFactor(t, a, a.owner())
	for range 5 {
		b := a.browser()
		b.api("POST", "login", map[string]string{"password": ownerPassword})
		b.api("POST", "login/totp", map[string]string{"code": "000000"})
	}
	b := a.browser()
	b.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, b.api("POST", "login/totp", map[string]string{"code": totp.Code(secret, a.clock.Now())}), 429, "throttled")
}

func TestTheStepBelongsToTheBrowser(t *testing.T) {
	a := newApp(t)
	secret, _ := twoFactor(t, a, a.owner())
	a.browser().api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, a.browser().api("POST", "login/totp", map[string]string{"code": totp.Code(secret, a.clock.Now())}), 401, "stepExpired")
}

func TestTheStepEndsAfterFiveMinutes(t *testing.T) {
	a := newApp(t)
	secret, _ := twoFactor(t, a, a.owner())
	b := a.browser()
	b.api("POST", "login", map[string]string{"password": ownerPassword})
	a.clock.Add(6 * time.Minute)
	want(t, b.api("POST", "login/totp", map[string]string{"code": totp.Code(secret, a.clock.Now())}), 401, "stepExpired")
}

func TestTurningTwoFactorOnEndsTheOtherSessions(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	other := a.signIn()
	twoFactor(t, a, b)
	if other.visitor().Via != "" {
		t.Fatal("a session without the second factor survived")
	}
	if b.visitor().Via == "" {
		t.Fatal("the browser that turned it on was signed out")
	}
}

func TestTwoFactorWantsAFreshSignIn(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	a.clock.Add(11 * time.Minute)
	want(t, b.api("POST", "me/totp", map[string]any{}), 403, "signInAgain")
}

func TestTurningTwoFactorOffWantsACode(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	secret, _ := twoFactor(t, a, b)
	want(t, b.api("DELETE", "me/totp", map[string]string{"code": "000000"}), 401, "wrongCode")
	want(t, b.api("DELETE", "me/totp", map[string]string{"code": totp.Code(secret, a.clock.Now())}), 200, "")
	r := a.browser().api("POST", "login", map[string]string{"password": ownerPassword})
	if r.json(t)["step"] != nil {
		t.Fatal("still asks for a code")
	}
}

func TestNewRecoveryCodesReplaceTheOld(t *testing.T) {
	a := newApp(t)
	b := a.owner()
	_, old := twoFactor(t, a, b)
	r := b.api("POST", "me/totp/codes", map[string]any{})
	want(t, r, 200, "")
	if n := len(r.json(t)["codes"].([]any)); n != 10 {
		t.Fatalf("%d new codes", n)
	}
	c := a.browser()
	c.api("POST", "login", map[string]string{"password": ownerPassword})
	want(t, c.api("POST", "login/totp", map[string]string{"code": old[0]}), 401, "wrongCode")
}
