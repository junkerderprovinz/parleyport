package phrase

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/internal/vectors"
)

func TestNewRoundTrips(t *testing.T) {
	for i := 0; i < 2000; i++ {
		secret, words, err := New()
		if err != nil {
			t.Fatalf("New() = %v", err)
		}
		if got := len(strings.Fields(words)); got != WordCount {
			t.Fatalf("phrase has %d words, want %d: %q", got, WordCount, words)
		}
		back, err := Decode(words)
		if err != nil {
			t.Fatalf("Decode(%q) = %v", words, err)
		}
		if !bytes.Equal(secret, back) {
			t.Fatalf("round trip changed the secret:\n in: %x\nout: %x\nphrase: %q", secret, back, words)
		}
	}
}

func TestEncodeIsStable(t *testing.T) {
	secret := make([]byte, SecretLen)
	for i := range secret {
		secret[i] = byte(i * 7)
	}
	first, err := Encode(secret)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		again, err := Encode(secret)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("Encode is not stable: %q then %q", first, again)
		}
	}
}

func TestEncodeMatchesTheVectors(t *testing.T) {
	v, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range v.Phrase {
		secret, err := hex.DecodeString(tc.Secret)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Encode(secret)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.Words {
			t.Errorf("Encode(%s) = %q, want %q", tc.Secret, got, tc.Words)
		}
		back, err := Decode(tc.Words)
		if err != nil || !bytes.Equal(back, secret) {
			t.Errorf("Decode(%q) = %x, %v; want %s", tc.Words, back, err, tc.Secret)
		}
	}
}

// Four checksum bits catch about fifteen of sixteen substitutions, so this
// walks every alternative first word against one fixed phrase rather than
// trying one substitution against a random phrase.
func TestChecksumCatchesASwappedWord(t *testing.T) {
	words, err := Encode(make([]byte, SecretLen))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(words)

	slipped := 0
	for _, w := range wordlist {
		if w == got[0] {
			continue
		}
		try := append([]string{w}, got[1:]...)
		_, err := Decode(strings.Join(try, " "))
		if err == nil {
			slipped++
			continue
		}
		if !errors.Is(err, ErrChecksum) {
			t.Fatalf("substituting %q: Decode error = %v, want ErrChecksum", w, err)
		}
	}

	// The band only has to catch a checksum that is never applied (2047 slip)
	// or one that rejects everything (none slip).
	const expect = 2047 / 16
	if slipped < expect-40 || slipped > expect+40 {
		t.Fatalf("%d of 2047 substitutions went undetected, expected about %d", slipped, expect)
	}
}

func TestAnUnknownWordIsNamedWithItsPosition(t *testing.T) {
	_, words, err := New()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(words)
	got[6] = "recieve"

	_, err = Decode(strings.Join(got, " "))
	var de *DecodeError
	if !errors.As(err, &de) {
		t.Fatalf("Decode error = %v, want a *DecodeError", err)
	}
	if de.Reason != ReasonUnknownWord || de.Word != "recieve" || de.Position != 7 {
		t.Errorf("got %+v, want the unknown word recieve at position 7", de)
	}
	if msg := err.Error(); !strings.Contains(msg, "recieve") || !strings.Contains(msg, "7") {
		t.Errorf("error %q does not name the word and its position", msg)
	}
}

func TestAWrongWordCountIsRefused(t *testing.T) {
	_, words, err := New()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(words)

	for _, tc := range []struct {
		name  string
		words []string
	}{
		{"one short", got[:WordCount-1]},
		{"one too many", append(append([]string{}, got...), got[0])},
		{"empty", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.Join(tc.words, " "))
			var de *DecodeError
			if !errors.As(err, &de) || de.Reason != ReasonWordCount || de.Count != len(tc.words) {
				t.Fatalf("Decode of %d words = %v, want a word count error naming %d", len(tc.words), err, len(tc.words))
			}
		})
	}
}

func TestDecodeTakesPastedAndTypedInput(t *testing.T) {
	secret, words, err := New()
	if err != nil {
		t.Fatal(err)
	}
	split := strings.Fields(words)

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"as generated", words},
		{"upper case", strings.ToUpper(words)},
		{"leading and trailing space", "   " + words + "   \n"},
		{"newlines between words", strings.Join(split, "\n")},
		{"double spaces", strings.Join(split, "  ")},
		{"tabs", strings.Join(split, "\t")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			back, err := Decode(tc.input)
			if err != nil {
				t.Fatalf("Decode(%q) = %v", tc.input, err)
			}
			if !bytes.Equal(back, secret) {
				t.Fatalf("Decode(%q) = %x, want %x", tc.input, back, secret)
			}
		})
	}
}

func TestEncodeRefusesASecretOfTheWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, SecretLen - 1, SecretLen + 1, 32} {
		if _, err := Encode(make([]byte, n)); err == nil {
			t.Errorf("Encode accepted a %d-byte secret", n)
		}
	}
}

// Swapping a word in the list would decode every phrase ever written down to
// another secret.
func TestTheWordlistIsTheOfficialOne(t *testing.T) {
	const official = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	sum := sha256.Sum256([]byte(wordlistFile))
	if got := hex.EncodeToString(sum[:]); got != official {
		t.Fatalf("wordlist hash = %s, want the official BIP39 English list %s", got, official)
	}
	list := Wordlist()
	if len(list) != 2048 || list[0] != "abandon" || list[2047] != "zoo" {
		t.Fatalf("Wordlist() has %d words from %q, want 2048 from abandon to zoo", len(list), list[0])
	}
	list[0] = "changed"
	if Wordlist()[0] != "abandon" {
		t.Fatal("a caller changed the list Decode reads")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	f.Add("")
	f.Add("zoo zoo zoo")
	f.Add("ABANDON\tabandon\n abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	f.Fuzz(func(t *testing.T, input string) {
		secret, err := Decode(input)
		if err != nil {
			return
		}
		words, err := Encode(secret)
		if err != nil {
			t.Fatalf("Decode(%q) gave a secret Encode refuses: %v", input, err)
		}
		if words != strings.Join(strings.Fields(strings.ToLower(input)), " ") {
			t.Fatalf("Decode(%q) then Encode gave %q", input, words)
		}
	})
}
