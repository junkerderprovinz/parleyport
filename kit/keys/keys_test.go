package keys

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/junkerderprovinz/parleyport/kit/internal/vectors"
)

// A changed derivation stays consistent with itself while it splits every
// existing group, so each one is pinned to what the apps derive today.
func TestDerivationsMatchTheVectors(t *testing.T) {
	v, err := vectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Derivations) == 0 {
		t.Fatal("no derivation vectors")
	}
	for _, tc := range v.Derivations {
		input, err := hex.DecodeString(tc.Input)
		if err != nil {
			t.Fatal(err)
		}
		d := Domain(tc.Domain)
		var got string
		switch tc.Purpose {
		case "group":
			got = d.GroupKey(input)
		case "frame":
			got = hex.EncodeToString(d.FrameKey(input))
		case "peer-auth":
			got = hex.EncodeToString(d.PeerAuthKey(input))
		case "manual-frame":
			got = hex.EncodeToString(d.ManualFrameKey(string(input)))
		default:
			t.Fatalf("unknown purpose %q", tc.Purpose)
		}
		if got != tc.Output {
			t.Errorf("%s %s key of %s = %s, want %s", tc.Domain, tc.Purpose, tc.Input, got, tc.Output)
		}
	}
}

// The relay receives the group key in every hello, so neither the secret nor
// any key that seals or signs may be computable from it.
func TestTheGroupKeyGivesNothingElseAway(t *testing.T) {
	const d = Domain("alpha")
	secret := []byte("0123456789abcdef")
	group := d.GroupKey(secret)
	if strings.Contains(group, hex.EncodeToString(secret)) {
		t.Fatal("the group key contains the secret")
	}
	for name, key := range map[string][]byte{
		"frame":                d.FrameKey(secret),
		"peer-auth":            d.PeerAuthKey(secret),
		"frame from the group": d.ManualFrameKey(group),
	} {
		if hex.EncodeToString(key) == group {
			t.Errorf("the %s key is the group key", name)
		}
	}
	if bytes.Equal(d.FrameKey(secret), d.ManualFrameKey(group)) {
		t.Error("the frame key follows from the group key the relay holds")
	}
}

// One secret shared by two apps must not put them in one group or let one
// open the other's frames.
func TestDomainsKeepAppsApart(t *testing.T) {
	secret := []byte("0123456789abcdef")
	a, b := Domain("alpha"), Domain("beta")
	if a.GroupKey(secret) == b.GroupKey(secret) {
		t.Error("two domains derive the same group key")
	}
	if bytes.Equal(a.FrameKey(secret), b.FrameKey(secret)) {
		t.Error("two domains derive the same frame key")
	}
	if bytes.Equal(a.PeerAuthKey(secret), b.PeerAuthKey(secret)) {
		t.Error("two domains derive the same peer-auth key")
	}
	if a.Signing() == b.Signing() {
		t.Error("two domains sign under the same labels")
	}
}

func TestKeysHaveTheSizeTheirUseNeeds(t *testing.T) {
	const d = Domain("alpha")
	secret := []byte("0123456789abcdef")
	if got := d.GroupKey(secret); len(got) != 64 {
		t.Errorf("group key is %d characters, want 64 hex", len(got))
	}
	for name, key := range map[string][]byte{
		"frame":        d.FrameKey(secret),
		"peer-auth":    d.PeerAuthKey(secret),
		"manual frame": d.ManualFrameKey("a-relay-key-typed-in-by-hand-0123456789"),
	} {
		if len(key) != 32 {
			t.Errorf("%s key is %d bytes, want 32", name, len(key))
		}
	}
}

func TestSigningLabelsStartAtTheFirstVersion(t *testing.T) {
	want := Signing{Call: "alpha/relay/member-call/v1", Result: "alpha/relay/member-result/v1"}
	if got := Domain("alpha").Signing(); got != want {
		t.Errorf("Signing() = %+v, want %+v", got, want)
	}
}

func TestASetHoldsTheKeysOfItsDomain(t *testing.T) {
	secret := []byte("0123456789abcdef")
	d := Domain("alpha")
	s := d.Keys(secret)
	if s.Group != d.GroupKey(secret) || !bytes.Equal(s.Frame, d.FrameKey(secret)) || !bytes.Equal(s.PeerAuth, d.PeerAuthKey(secret)) {
		t.Errorf("the set of alpha is %+v", s)
	}
	if !s.Complete() {
		t.Error("a derived set is not complete")
	}
	for name, broken := range map[string]Set{
		"empty":         {},
		"no frame key":  {Group: s.Group, PeerAuth: s.PeerAuth},
		"short group":   {Group: s.Group[:10], Frame: s.Frame, PeerAuth: s.PeerAuth},
		"long peer key": {Group: s.Group, Frame: s.Frame, PeerAuth: append(bytes.Clone(s.PeerAuth), 0)},
	} {
		if broken.Complete() {
			t.Errorf("%s counts as complete", name)
		}
	}
}
