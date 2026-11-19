package signintest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/junkerderprovinz/parleyport/kit/signin"
)

// Authenticator makes passkeys in software, as a browser with a platform
// authenticator would, for one origin. It answers the options the contract
// hands out with what navigator.credentials would return.
type Authenticator struct {
	// Origin is what the browser reports as the page's origin.
	Origin string
	// SkipVerification leaves the user-verified flag out, as a security key
	// without a PIN would.
	SkipVerification bool
	// Synced marks new passkeys as backed up, as a password manager does.
	Synced bool

	mu    sync.Mutex
	creds []*softCredential
}

type softCredential struct {
	id     []byte
	rpID   string
	handle []byte
	key    *ecdsa.PrivateKey
	count  uint32
	synced bool
}

// NewAuthenticator returns an authenticator for origin, such as
// "https://app.example".
func NewAuthenticator(origin string) *Authenticator { return &Authenticator{Origin: origin} }

var b64 = base64.RawURLEncoding

// Create answers creation options, the JSON the contract returns for a new
// passkey, with a registration response.
func (a *Authenticator) Create(options []byte) ([]byte, error) {
	var in struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &in); err != nil {
		return nil, err
	}
	handle, err := b64.DecodeString(in.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("user id: %w", err)
	}
	c, err := a.newCredential(in.PublicKey.RP.ID, handle)
	if err != nil {
		return nil, err
	}
	client := a.clientData("webauthn.create", in.PublicKey.Challenge)
	auth := a.authData(c, true)
	att := cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(auth),
	)
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.id), "rawId": b64.EncodeToString(c.id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(client),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal"},
		},
	})
}

// Get answers request options with an assertion from the newest passkey for
// the relying party, or one of those the options allow.
func (a *Authenticator) Get(options []byte) ([]byte, error) {
	var in struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RPID      string `json:"rpId"`
			Allow     []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &in); err != nil {
		return nil, err
	}
	c := a.pick(in.PublicKey.RPID, func(id []byte) bool {
		if len(in.PublicKey.Allow) == 0 {
			return true
		}
		for _, allow := range in.PublicKey.Allow {
			if allow.ID == b64.EncodeToString(id) {
				return true
			}
		}
		return false
	})
	if c == nil {
		return nil, errors.New("signintest: no passkey for this relying party")
	}
	a.mu.Lock()
	c.count++
	a.mu.Unlock()
	client := a.clientData("webauthn.get", in.PublicKey.Challenge)
	auth := a.authData(c, false)
	sum := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.id), "rawId": b64.EncodeToString(c.id), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(client),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.handle),
		},
	})
}

// Passkey makes a passkey for rpID and handle in the form an app imports,
// as if it had been registered before the app used the package.
func (a *Authenticator) Passkey(rpID string, handle []byte) (signin.ImportedPasskey, error) {
	c, err := a.newCredential(rpID, handle)
	if err != nil {
		return signin.ImportedPasskey{}, err
	}
	return signin.ImportedPasskey{
		Name: "imported", ID: c.id, PublicKey: coseKey(&c.key.PublicKey), RPID: rpID,
		AttestationType: "none", Transports: []string{"internal"}, BackupEligible: c.synced, BackupState: c.synced,
	}, nil
}

func (a *Authenticator) newCredential(rpID string, handle []byte) (*softCredential, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	c := &softCredential{id: id, rpID: rpID, handle: handle, key: key, synced: a.Synced}
	a.mu.Lock()
	a.creds = append(a.creds, c)
	a.mu.Unlock()
	return c, nil
}

func (a *Authenticator) pick(rpID string, allowed func([]byte) bool) *softCredential {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.creds) - 1; i >= 0; i-- {
		if c := a.creds[i]; c.rpID == rpID && allowed(c.id) {
			return c
		}
	}
	return nil
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

// The flags of authenticator data, from the WebAuthn specification.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

func (a *Authenticator) authData(c *softCredential, attested bool) []byte {
	rp := sha256.Sum256([]byte(c.rpID))
	flags := byte(flagUP)
	if !a.SkipVerification {
		flags |= flagUV
	}
	if c.synced {
		flags |= flagBE | flagBS
	}
	if attested {
		flags |= flagAT
	}
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, c.count)
	if attested {
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(c.id)))
		out = append(out, c.id...)
		out = append(out, coseKey(&c.key.PublicKey)...)
	}
	return out
}

// coseKey is an ES256 public key as COSE: kty EC2, alg -7, crv P-256.
func coseKey(k *ecdsa.PublicKey) []byte {
	raw, _ := k.Bytes()
	x, y := raw[1:33], raw[33:]
	return cborMap(cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1), cborInt(-2), cborBytes(x), cborInt(-3), cborBytes(y))
}

// cborHead and the helpers after it write the few CBOR items a registration
// needs.

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	default:
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
}

func cborInt(n int) []byte {
	if n >= 0 {
		return cborHead(0, uint64(n))
	}
	return cborHead(1, uint64(-1-n))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

func cborText(s string) []byte { return append(cborHead(3, uint64(len(s))), s...) }

func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}
