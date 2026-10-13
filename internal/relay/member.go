package relay

// Member keys, the part of them the relay checks. A KnightLoader member, from
// 1.9 on, holds an Ed25519 key pair and goes by an id made from its public
// half (MemberID), so nobody can speak for that id without the key behind it.
// Its hello proves the id by signing the challenge the relay sent on that
// connection (IDProof), and only such a proof lets a connection take the place
// of one already holding the id. Calls are signed too, but inside the seal,
// where the relay never looks.
//
// The domain strings and message layout are what KnightLoader's instances, app
// and extension sign, so they keep the names they were introduced under.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/url"
	"slices"
	"strings"
)

// The kinds a member signs as.
const (
	KindInstance  = "instance"
	KindMobile    = "mobile"
	KindExtension = "extension"
)

// MemberID is the id a member of kind goes by with key: the hex of the key's
// SHA-256 after "phone-" for the app and "browser-" for the extension, and for
// an instance the first 20 bytes of it, the 40 hex digits an instance id has.
// It is "" for a key of the wrong length or an unknown kind.
func MemberID(kind string, key []byte) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(key)
	switch kind {
	case KindInstance:
		return hex.EncodeToString(sum[:20])
	case KindMobile:
		return "phone-" + hex.EncodeToString(sum[:])
	case KindExtension:
		return "browser-" + hex.EncodeToString(sum[:])
	}
	return ""
}

// helloDomain opens every signed hello, so a member key's signature over a
// hello can never be taken for one over a call or an answer.
const helloDomain = "knightloader/relay/member-hello/v3\x00"

// signedMessage is domain followed by every field with its length and then n,
// the one layout every message a member signs has.
func signedMessage(domain string, n uint64, fields ...[]byte) []byte {
	out := []byte(domain)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return binary.BigEndian.AppendUint64(out, n)
}

// IDProof shows that a connection holds the key its announced id is made
// from. It signs the challenge the relay sent on that connection, so a hello
// somebody saw proves nothing on another one, and it names the relay the
// member dialled (RelayHost), so another relay that passes on its own
// challenge gets a proof it cannot use.
type IDProof struct {
	Kind  string `json:"kind"`
	Relay string `json:"relay"`
	Key   []byte `json:"key"`
	Sig   []byte `json:"sig"`
}

// HelloMessage is what a member signs to prove that id is its own on the
// relay key key, at the relay it reached under the host name relay, on the
// connection that relay sent challenge on.
func HelloMessage(key, relay, id, kind string, challenge []byte) []byte {
	return signedMessage(helloDomain, 0, []byte(key), []byte(relay), []byte(id), []byte(kind), challenge)
}

// ProveID signs the proof that member, a member of kind, holds id on the relay
// key key, for the connection on which the relay it reached as relay sent
// challenge.
func ProveID(member ed25519.PrivateKey, kind, key, relay, id string, challenge []byte) *IDProof {
	return &IDProof{
		Kind:  kind,
		Relay: relay,
		Key:   member.Public().(ed25519.PublicKey),
		Sig:   ed25519.Sign(member, HelloMessage(key, relay, id, kind, challenge)),
	}
}

// proves reports whether h shows the key its announced id is made from, on the
// connection the relay sent challenge on, to a relay going by one of names.
func (h Hello) proves(challenge []byte, names []string) bool {
	p := h.Proof
	if p == nil || MemberID(p.Kind, p.Key) != h.Announce.InstanceID || len(p.Sig) != ed25519.SignatureSize ||
		p.Relay == "" || !slices.Contains(names, p.Relay) {
		return false
	}
	return ed25519.Verify(p.Key, HelloMessage(h.Key, p.Relay, h.Announce.InstanceID, p.Kind, challenge), p.Sig)
}

// RelayHost is the name a hello's proof gives the relay it is meant for: the
// host of address, a URL or a bare host with or without a port, in lower case
// and without the port, the brackets of an IPv6 literal or the dot of a fully
// qualified name. The port is left out because a reverse proxy in front of a
// relay listens on another one than the relay itself.
func RelayHost(address string) string {
	address = strings.TrimSpace(address)
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	u, err := url.Parse(address)
	if err != nil {
		return ""
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}
