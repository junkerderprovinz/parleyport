package token_test

import (
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/signin/internal/token"
)

func TestNewParsesBack(t *testing.T) {
	tok, err := token.New("ab")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Value, "ab_") || len(tok.Value) != len("ab_")+22+43+6 {
		t.Fatalf("value %q", tok.Value)
	}
	id, secret, ok := token.Parse("ab", tok.Value)
	if !ok || id != tok.ID || secret != tok.Secret {
		t.Fatalf("Parse = %q, %q, %v", id, secret, ok)
	}
}

func TestParseRefusesABrokenChecksum(t *testing.T) {
	tok, _ := token.New("ab")
	b := []byte(tok.Value)
	i := len("ab_") + 5
	if b[i] == 'x' {
		b[i] = 'y'
	} else {
		b[i] = 'x'
	}
	if _, _, ok := token.Parse("ab", string(b)); ok {
		t.Fatal("a token with one changed character parses")
	}
}

func TestParseRefusesOtherShapes(t *testing.T) {
	tok, _ := token.New("ab")
	for name, v := range map[string]string{
		"other prefix": "cd" + tok.Value[2:],
		"no prefix":    tok.Value[3:],
		"short":        tok.Value[:len(tok.Value)-1],
		"long":         tok.Value + "a",
		"symbols":      tok.Value[:10] + "!" + tok.Value[11:],
		"empty":        "",
	} {
		if _, _, ok := token.Parse("ab", v); ok {
			t.Errorf("%s parses", name)
		}
	}
}

func TestValidPrefix(t *testing.T) {
	for p, want := range map[string]bool{"ab": true, "abcdefgh": true, "a": false, "abcdefghi": false, "Ab": false, "a1": false, "": false} {
		if got := token.ValidPrefix(p); got != want {
			t.Errorf("ValidPrefix(%q) = %v", p, got)
		}
	}
}

func TestRandomIsLongAndFresh(t *testing.T) {
	a, b := token.Random(32), token.Random(32)
	if len(a) != 43 || a == b {
		t.Fatalf("Random gave %q and %q", a, b)
	}
}
