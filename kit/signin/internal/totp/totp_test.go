package totp_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/totp"
)

var rfcSecret = []byte("12345678901234567890")

func TestCodeMatchesRFC6238(t *testing.T) {
	tests := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tt := range tests {
		if got := totp.Code(rfcSecret, time.Unix(tt.unix, 0)); got != tt.want {
			t.Errorf("Code at %d = %s, want %s", tt.unix, got, tt.want)
		}
	}
}

func TestCheckAcceptsOneStepEitherSide(t *testing.T) {
	now := time.Unix(1111111109, 0)
	for _, off := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code := totp.Code(rfcSecret, now.Add(off))
		if _, ok := totp.Check(rfcSecret, code, now, 0); !ok {
			t.Errorf("code from %v away is refused", off)
		}
	}
	for _, off := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		code := totp.Code(rfcSecret, now.Add(off))
		if _, ok := totp.Check(rfcSecret, code, now, 0); ok {
			t.Errorf("code from %v away is accepted", off)
		}
	}
}

func TestCheckRefusesAStepAlreadyUsed(t *testing.T) {
	now := time.Unix(1111111109, 0)
	code := totp.Code(rfcSecret, now)
	step, ok := totp.Check(rfcSecret, code, now, 0)
	if !ok {
		t.Fatal("first use refused")
	}
	if _, ok := totp.Check(rfcSecret, code, now, step); ok {
		t.Fatal("the same code counts twice")
	}
	earlier := totp.Code(rfcSecret, now.Add(-30*time.Second))
	if _, ok := totp.Check(rfcSecret, earlier, now, step); ok {
		t.Fatal("a code older than the last one counts")
	}
}

func TestCheckRefusesMalformedCodes(t *testing.T) {
	now := time.Unix(59, 0)
	for _, code := range []string{"", "28708", "2870822", "abcdef", "287 082"} {
		if _, ok := totp.Check(rfcSecret, code, now, 0); ok {
			t.Errorf("code %q accepted", code)
		}
	}
}

func TestURICarriesTheSecretAndIssuer(t *testing.T) {
	u, err := url.Parse(totp.URI("Example Host", "owner", rfcSecret))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("uri %s", u)
	}
	if got := u.Query().Get("secret"); got != totp.Encode(rfcSecret) {
		t.Fatalf("secret %q", got)
	}
	if got := u.Query().Get("issuer"); got != "Example Host" {
		t.Fatalf("issuer %q", got)
	}
}

func TestNewSecretIsTwentyRandomBytes(t *testing.T) {
	a, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := totp.NewSecret()
	if len(a) != 20 || string(a) == string(b) {
		t.Fatalf("secrets %x and %x", a, b)
	}
}
