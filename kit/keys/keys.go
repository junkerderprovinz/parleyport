// Package keys derives an app's keys from the secret behind its phrase.
//
// Every key is the SHA-256 of a label and the secret, and every label starts
// with the app's domain, so one phrase typed into two apps puts them in two
// groups on a shared relay and neither can open the other's frames.
package keys

import (
	"crypto/sha256"
	"encoding/hex"
)

// Domain is the name an app derives its keys under, such as "alpha".
type Domain string

func (d Domain) derive(label string, input []byte) []byte {
	h := sha256.New()
	h.Write([]byte(string(d) + label))
	h.Write(input)
	return h.Sum(nil)
}

// GroupKey is the key a member presents to the relay in its hello, in hex.
// The relay learns it and nothing it could reproduce the phrase from.
func (d Domain) GroupKey(secret []byte) string {
	return hex.EncodeToString(d.derive("/relay/group-key/v1", secret))
}

// FrameKey is the AES-256 key the members seal their frames under. It never
// leaves a member, and the relay cannot compute it from the group key.
func (d Domain) FrameKey(secret []byte) []byte {
	return d.derive("/relay/frame-key/v1", secret)
}

// PeerAuthKey is the HMAC key members tag their announces and direct calls
// on the local network with.
func (d Domain) PeerAuthKey(secret []byte) []byte {
	return d.derive("/peer-auth/v1", secret)
}

// ManualFrameKey is the frame key for a group key typed in by hand, which has
// no secret behind it. The relay is given that key, so it could derive this
// one as well: the seal then hides frames from everyone between the members
// and their relay, but not from the relay.
func (d Domain) ManualFrameKey(groupKey string) []byte {
	return d.derive("/relay/frame-key-manual/v1", []byte(groupKey))
}

// Signing returns the labels d's members sign calls and answers under.
func (d Domain) Signing() Signing {
	return Signing{
		Call:   string(d) + "/relay/member-call/v1",
		Result: string(d) + "/relay/member-result/v1",
	}
}

// Signing is the pair of labels that open every call and every answer a
// member signs, so a signature made for one app or one kind of message never
// counts for another. An app whose members already sign under other labels
// gives those.
type Signing struct {
	Call   string
	Result string
}
