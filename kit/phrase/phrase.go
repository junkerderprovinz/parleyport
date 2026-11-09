// Package phrase turns the secret that joins a person's instances into twelve
// words and back.
//
// The words come from the BIP39 English list because its 2048 words differ in
// their first four letters, have no near-homophones and no accents, which
// makes a phrase safe to read aloud and to type on a phone. 128 bits keep the
// phrase at twelve words, and the BIP39 checksum catches a mistyped word
// before it turns into a group that silently never forms.
package phrase

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
)

//go:embed english.txt
var wordlistFile string

const (
	// SecretLen is the secret's size in bytes.
	SecretLen = 16
	// WordCount is what SecretLen encodes to: 128 bits of secret and a 4-bit
	// checksum, in 11-bit groups.
	WordCount = 12

	bitsPerWord  = 11
	checksumBits = SecretLen * 8 / 32
)

var (
	wordlist  []string
	wordIndex map[string]int
)

func init() {
	wordlist = strings.Fields(wordlistFile)
	if len(wordlist) != 1<<bitsPerWord {
		panic(fmt.Sprintf("phrase: wordlist has %d words, need %d", len(wordlist), 1<<bitsPerWord))
	}
	wordIndex = make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		wordIndex[w] = i
	}
}

// Wordlist returns the 2048 words a phrase is made of, in BIP39 order, for an
// interface that checks each word as it is typed.
func Wordlist() []string {
	return slices.Clone(wordlist)
}

// New mints a fresh secret and returns it with its words.
func New() (secret []byte, words string, err error) {
	secret = make([]byte, SecretLen)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("phrase: reading randomness: %w", err)
	}
	words, err = Encode(secret)
	if err != nil {
		return nil, "", err
	}
	return secret, words, nil
}

// Encode renders a secret as its words. It is a pure function of the secret,
// so the phrase shown again later is the one written down at the start.
func Encode(secret []byte) (string, error) {
	if len(secret) != SecretLen {
		return "", fmt.Errorf("phrase: secret is %d bytes, need %d", len(secret), SecretLen)
	}
	sum := sha256.Sum256(secret)
	full := make([]byte, 0, SecretLen+1)
	full = append(full, secret...)
	full = append(full, sum[0])

	out := make([]string, WordCount)
	for i := range out {
		out[i] = wordlist[bitsAt(full, i*bitsPerWord, bitsPerWord)]
	}
	return strings.Join(out, " "), nil
}

// ErrChecksum matches a phrase whose words are all real but do not check out
// together, the mark of a typo that landed on another word or of two swapped
// words.
var ErrChecksum = errors.New("phrase: the phrase is not valid; check for a mistyped or swapped word")

// Reason is what is wrong with a phrase, as a code an interface can put into
// words in its own language.
type Reason string

// The reasons Decode refuses a phrase for.
const (
	ReasonWordCount   Reason = "word_count"
	ReasonUnknownWord Reason = "unknown_word"
	ReasonChecksum    Reason = "checksum"
)

// DecodeError is every way Decode can refuse a phrase, with what a caller needs
// to say which word to fix.
type DecodeError struct {
	Reason   Reason
	Word     string // ReasonUnknownWord: the word that is not on the list
	Position int    // ReasonUnknownWord: its position, counted from 1
	Count    int    // ReasonWordCount: how many words there were
}

func (e *DecodeError) Error() string {
	switch e.Reason {
	case ReasonWordCount:
		return fmt.Sprintf("phrase: the phrase has %d words, it needs %d", e.Count, WordCount)
	case ReasonUnknownWord:
		return fmt.Sprintf("phrase: word %d (%q) is not one of the accepted words", e.Position, e.Word)
	default:
		return ErrChecksum.Error()
	}
}

// Unwrap lets errors.Is(err, ErrChecksum) match the checksum case.
func (e *DecodeError) Unwrap() error {
	if e.Reason == ReasonChecksum {
		return ErrChecksum
	}
	return nil
}

// Decode parses words back into their secret. Case is ignored and any run of
// whitespace separates two words, since a phrase arrives pasted or typed from
// what somebody read out.
func Decode(words string) ([]byte, error) {
	got := strings.Fields(strings.ToLower(words))
	if len(got) != WordCount {
		return nil, &DecodeError{Reason: ReasonWordCount, Count: len(got)}
	}

	full := make([]byte, SecretLen+1)
	for i, w := range got {
		idx, ok := wordIndex[w]
		if !ok {
			return nil, &DecodeError{Reason: ReasonUnknownWord, Word: w, Position: i + 1}
		}
		setBits(full, i*bitsPerWord, bitsPerWord, idx)
	}

	secret := full[:SecretLen]
	sum := sha256.Sum256(secret)
	if bitsAt(sum[:1], 0, checksumBits) != bitsAt(full, SecretLen*8, checksumBits) {
		return nil, &DecodeError{Reason: ReasonChecksum}
	}
	return secret, nil
}

// bitsAt reads count bits from b at bit offset, most significant first.
func bitsAt(b []byte, offset, count int) int {
	v := 0
	for i := 0; i < count; i++ {
		bit := offset + i
		v <<= 1
		if b[bit/8]&(1<<(7-bit%8)) != 0 {
			v |= 1
		}
	}
	return v
}

// setBits writes the low count bits of v into b at bit offset, most
// significant first, into bits that are still clear.
func setBits(b []byte, offset, count, v int) {
	for i := 0; i < count; i++ {
		if v&(1<<(count-1-i)) != 0 {
			bit := offset + i
			b[bit/8] |= 1 << (7 - bit%8)
		}
	}
}
