package relay

// The secret behind a connection phrase and the key that groups instances on
// a relay are different values. The relay key travels in the clear in every
// hello frame, so it is derived from the secret with a hash: a relay learns
// an identifier for the group and never the secret that would reproduce its
// phrase. Proxy frames are sealed with a second key derived from the same
// secret under its own domain (see seal.go).

import (
	"crypto/sha256"
	"encoding/hex"
)

// DefaultRelayURL is the relay every instance dials unless its owner points it
// elsewhere. Because the address is compiled in, a phrase only has to carry
// the secret, and every released binary depends on this domain staying alive.
// Moving it means serving both names while old builds still dial the old one,
// which is why PARLEYPORT_DOMAIN takes a list (see cmd/parleyport).
const DefaultRelayURL = "wss://relay.halleluja.design/relay/connect"

// SeedAccountService is the credential-store service the seed-phrase secret is
// sealed under. It is separate from AccountService, which holds a hand-entered
// relay key: this is the secret itself, and only DeriveKey of it reaches a relay.
const SeedAccountService = "relay-seed"

// keyDomain keeps this hash of the secret distinct from any other key derived
// from it, so two features never end up sharing one credential.
//
// The domain strings below are part of the wire protocol that KnightLoader and
// BombVault speak, so they keep the name they were introduced under.
const keyDomain = "knightloader/relay/group-key/v1"

// DeriveKey returns the relay key for a secret, the value an instance puts in
// its hello frame. It is hex so it survives logs, URLs and config files.
func DeriveKey(secret []byte) string {
	h := sha256.New()
	h.Write([]byte(keyDomain))
	h.Write(secret)
	return hex.EncodeToString(h.Sum(nil))
}

// frameDomain separates the frame key from the relay key. The relay receives
// DeriveKey's output in every hello, so a frame key derived from that value or
// the same domain would be one the relay already holds.
const frameDomain = "knightloader/relay/frame-key/v1"

// DeriveFrameKey returns the AES-256-GCM key that seals proxy frames between
// instances sharing a connection phrase. It is derived on both ends and never
// stored or sent, so a relay operator holding the group key cannot compute it.
func DeriveFrameKey(secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte(frameDomain))
	h.Write(secret)
	return h.Sum(nil)
}

// peerAuthDomain separates the key that tags local-network announces and
// signs direct calls between members from the relay and frame keys.
const peerAuthDomain = "knightloader/peer-auth/v1"

// DerivePeerAuthKey returns the HMAC key members sign their announces and
// direct calls with. Like the frame key it never leaves an instance.
func DerivePeerAuthKey(secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte(peerAuthDomain))
	h.Write(secret)
	return h.Sum(nil)
}

// manualFrameDomain is the domain for a hand-entered relay key, which has no
// secret to derive from.
const manualFrameDomain = "knightloader/relay/frame-key-manual/v1"

// FrameKeyFromRelayKey derives a frame key from a hand-entered relay key.
// That key travels to the relay, so this is not end-to-end: the relay operator
// could derive it too. It still hides the traffic from proxies and logs
// between the instances and a relay their owner runs, and keeps the protocol
// to a single sealed shape. No UI text claims more for this path.
func FrameKeyFromRelayKey(key string) []byte {
	h := sha256.New()
	h.Write([]byte(manualFrameDomain))
	h.Write([]byte(key))
	return h.Sum(nil)
}
