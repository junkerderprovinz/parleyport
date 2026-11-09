// Package vectors reads testdata/vectors.json, the values every port of the
// protocol has to reproduce byte for byte.
package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// File is the whole of testdata/vectors.json.
type File struct {
	Phrase      []Phrase     `json:"phrase"`
	Derivations []Derivation `json:"derivations"`
	Member      Member       `json:"member"`
	Call        Call         `json:"call"`
	Result      Result       `json:"result"`
	Signing     []Signing    `json:"signing"`
	Sealed      Sealed       `json:"sealed"`
}

// Phrase is a secret in hex and the words it encodes to.
type Phrase struct {
	Secret string `json:"secret"`
	Words  string `json:"words"`
}

// Derivation is one key derived under an app's domain: purpose is "group",
// "frame", "peer-auth" or "manual-frame", input and output are hex.
type Derivation struct {
	Domain  string `json:"domain"`
	Purpose string `json:"purpose"`
	Input   string `json:"input"`
	Output  string `json:"output"`
}

// Member is the key the hex seed makes, the ids and fingerprint it goes by
// and the hello it signs.
type Member struct {
	Seed        string            `json:"seed"`
	PublicKey   string            `json:"publicKey"`
	IDs         map[string]string `json:"ids"`
	Fingerprint string            `json:"fingerprint"`
	Hello       Hello             `json:"hello"`
}

// Hello is the hello the member key signs as kind, for the id of that kind.
type Hello struct {
	RelayKey  string `json:"relayKey"`
	RelayHost string `json:"relayHost"`
	Kind      string `json:"kind"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

// Call is the call every signing vector signs, sent to Target.
type Call struct {
	Target string `json:"target"`
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
	From   string `json:"from"`
	Kind   string `json:"kind"`
	Sent   int64  `json:"sent"`
}

// Result is the answer every signing vector signs as the instance id of the
// member key, to the call that arrived as SealedCall under Call.ID.
type Result struct {
	SealedCall string `json:"sealedCall"`
	Status     int    `json:"status"`
	Body       string `json:"body"`
}

// Signing is one app's pair of signature labels and the signatures the member
// key makes under them.
type Signing struct {
	Call            string `json:"call"`
	Result          string `json:"result"`
	CallSignature   string `json:"callSignature"`
	ResultSignature string `json:"resultSignature"`
}

// Sealed holds frames another implementation sealed under the frame key
// Domain derives from Secret.
type Sealed struct {
	Domain   string         `json:"domain"`
	Secret   string         `json:"secret"`
	Call     SealedCall     `json:"call"`
	Identity SealedIdentity `json:"identity"`
}

// SealedCall is a sealed call and what it opens to.
type SealedCall struct {
	RequestID string `json:"requestId"`
	Target    string `json:"target"`
	Sealed    string `json:"sealed"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Sent      int64  `json:"sent"`
}

// SealedIdentity is a sealed announce identity and what it opens to.
type SealedIdentity struct {
	InstanceID string `json:"instanceId"`
	Sealed     string `json:"sealed"`
	Name       string `json:"name"`
	Deployment string `json:"deployment"`
	Client     bool   `json:"client"`
}

// Load reads the vectors from the module's testdata directory.
func Load() (*File, error) {
	_, here, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "testdata", "vectors.json"))
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
