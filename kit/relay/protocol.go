// Package relay lets the members of a group reach each other through a relay
// that both dial out to, so two instances behind NAT need no inbound
// connection.
//
// The relay groups connections by the key in their hello and never opens a
// frame: calls, answers and each member's name travel sealed under a frame key
// the relay does not hold, and every call and answer is signed with the
// member's own key inside the seal. Client is a member's side of it, Server
// the relay's.
//
// Every frame is one JSON text message of the shape {type, data}, with bytes
// as base64, so a client needs nothing but a WebSocket and a JSON parser.
package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// The frame types. Anything else on the socket is ignored, so a newer peer
// never costs an older one its connection.
const (
	// TypeChallenge is sent by the relay only, first on every connection: what
	// a hello's proof signs.
	TypeChallenge = "challenge"
	// TypeHello is the first frame a client sends and the only one carrying
	// the group key.
	TypeHello = "hello"
	// TypeAnnounce is sent by the relay only: who else is on this key.
	TypeAnnounce = "announce"
	// TypePresence is sent by the relay only: a sibling's connection went away.
	TypePresence = "presence"
	// TypeProxyRequest carries one call to a sibling.
	TypeProxyRequest = "proxy-request"
	// TypeProxyResponse carries that call's answer, matched by request id.
	TypeProxyResponse = "proxy-response"
)

// Envelope is every frame on the socket: a type and that type's payload.
type Envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Challenge is random bytes the relay draws for one connection.
type Challenge struct {
	Nonce []byte `json:"nonce"`
}

// Hello authenticates and introduces a connection in one frame. The key rides
// in the frame rather than the URL because a reverse proxy logs URLs and a
// browser cannot set a header on a WebSocket.
type Hello struct {
	Key      string   `json:"key"`
	Announce Announce `json:"announce"`
	// Proof shows the key the announced id is made from, which a connection
	// needs to take the place of one that proved it before.
	Proof *member.Proof `json:"proof,omitempty"`
}

// proves reports whether h's proof holds for its key and id on the connection
// the relay sent challenge on, to a relay going by one of names.
func (h Hello) proves(challenge []byte, names []string) bool {
	return h.Proof.Proves(h.Key, h.Announce.InstanceID, challenge, names)
}

// Announce is one instance introducing itself to everyone else on its key.
//
// This is the in-memory shape. On the wire everything but InstanceID travels
// inside Sealed; sealAnnounce and openAnnounce convert at the socket.
type Announce struct {
	// InstanceID is the instance's stable id and the address calls are routed
	// to, the one field the relay has to read.
	InstanceID string `json:"instanceId"`
	// Sealed carries the Identity, sealed under the frame key with InstanceID
	// as additional data, so a relay cannot hand one instance's identity to
	// another.
	Sealed []byte `json:"sealed,omitempty"`

	// Name is what siblings show. It is sealed because a hostname often names
	// the machine's owner.
	Name string `json:"name,omitempty"`
	// Deployment is how the instance runs, such as "container" or "desktop".
	Deployment string `json:"deployment,omitempty"`
	// Client marks a connection that calls siblings without serving calls
	// itself, such as a phone, so nobody lists it as a target.
	Client bool `json:"client,omitempty"`
	// Address is where the instance's web interface is.
	Address string `json:"address,omitempty"`
	// Member is the lasting id of a client that joins under a fresh
	// InstanceID for every session, so the group still knows it.
	Member string `json:"member,omitempty"`
}

// Identity is the sealed half of an announce. The relay routes on InstanceID
// alone, though it still sees the group key, each member's address, the ids
// and when they come and go.
type Identity struct {
	Name       string `json:"name,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	Client     bool   `json:"client,omitempty"`
	Address    string `json:"address,omitempty"`
	Member     string `json:"member,omitempty"`
}

// The additional data of each sealed blob starts with its own label, so a blob
// of one frame type never opens as another.
func announceAAD(instanceID string) string {
	return "announce\x00" + instanceID
}

func requestAAD(requestID, target string) string {
	return "proxy-request\x00" + requestID + "\x00" + target
}

func responseAAD(requestID string) string {
	return "proxy-response\x00" + requestID
}

// SealIdentity seals the identity half of an announce for instanceID.
func SealIdentity(key []byte, instanceID string, id Identity) ([]byte, error) {
	plain, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	return seal(key, announceAAD(instanceID), plain)
}

// OpenIdentity reverses SealIdentity.
func OpenIdentity(key []byte, instanceID string, sealed []byte) (Identity, error) {
	plain, err := open(key, announceAAD(instanceID), sealed)
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	if err := json.Unmarshal(plain, &id); err != nil {
		return Identity{}, ErrSealed
	}
	return id, nil
}

// sealAnnounce converts an announce to its wire form, with the identity
// fields blanked rather than sent beside the seal.
func sealAnnounce(frameKey []byte, a Announce) (Announce, error) {
	sealed, err := SealIdentity(frameKey, a.InstanceID, Identity{
		Name:       ClipName(a.Name),
		Deployment: a.Deployment,
		Client:     a.Client,
		Address:    FitAddress(a.Address),
		Member:     a.Member,
	})
	if err != nil {
		return Announce{}, err
	}
	return Announce{InstanceID: a.InstanceID, Sealed: sealed}, nil
}

// openAnnounce converts a wire announce back. One whose seal is missing or
// does not open comes from a peer on another frame key or from the relay
// itself, neither of which may name a member, so it is kept under its bare id
// and a key mismatch stays visible.
func openAnnounce(frameKey []byte, a Announce) Announce {
	bare := Announce{InstanceID: a.InstanceID}
	if len(a.Sealed) == 0 {
		return bare
	}
	id, err := OpenIdentity(frameKey, a.InstanceID, a.Sealed)
	if err != nil {
		return bare
	}
	out := Announce{
		InstanceID: a.InstanceID,
		Name:       ClipName(id.Name),
		Deployment: ClipName(id.Deployment),
		Client:     id.Client,
		Address:    FitAddress(id.Address),
	}
	if id.Client && len(id.Member) <= maxClientIDBytes {
		out.Member = id.Member
	}
	return out
}

// ValidInstanceID reports whether id has the shape of an instance's id: 40
// lowercase hex digits, made from its member key or drawn at random.
func ValidInstanceID(id string) bool {
	if len(id) != 40 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// maxClientIDBytes bounds the id of a client, the longest being an
// extension's member id.
const maxClientIDBytes = 72

// listable reports whether an opened announce can be kept as a sibling: an
// instance is addressed by its id, so the id has to be shaped like one.
func listable(a Announce) bool {
	if a.Client {
		return a.InstanceID != "" && len(a.InstanceID) <= maxClientIDBytes
	}
	return ValidInstanceID(a.InstanceID)
}

// MaxNameBytes keeps a name small enough that every hello fits the relay's
// limit for it.
const MaxNameBytes = 200

// ClipName cuts name to MaxNameBytes at a whole UTF-8 character.
func ClipName(name string) string {
	if len(name) <= MaxNameBytes {
		return name
	}
	cut := MaxNameBytes
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return name[:cut]
}

// MaxAddressBytes bounds an announced address like MaxNameBytes a name.
const MaxAddressBytes = 200

// FitAddress is address, or "" when it is longer than MaxAddressBytes, since a
// cut address would lead somewhere else.
func FitAddress(address string) string {
	if len(address) > MaxAddressBytes {
		return ""
	}
	return address
}

// Presence reports that a sibling went away. The relay only ever sends
// Online=false; an arrival is an Announce.
type Presence struct {
	InstanceID string `json:"instanceId"`
	Online     bool   `json:"online"`
}

// ProxyRequest is the wire form of one call: the two fields the relay routes
// on and a sealed ProxyCall it cannot read.
type ProxyRequest struct {
	// RequestID is chosen by the caller and matches the answer to the call.
	RequestID string `json:"requestId"`
	// Target is the InstanceID the call is for.
	Target string `json:"target"`
	// Sealed is the ProxyCall, sealed with RequestID and Target as additional
	// data, so a relay cannot redirect it and have it open.
	Sealed []byte `json:"sealed,omitempty"`
	// Sender is the id the sending connection announced, written by the relay
	// over whatever the sender put there. It is not sealed, so the receiver
	// only spreads its limits by it (see WithSource).
	Sender string `json:"sender,omitempty"`
}

// ProxyCall is what a ProxyRequest asks once opened. It only ever travels
// sealed.
type ProxyCall struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body,omitempty"`
	// ID and Sent are the request id and the Unix time the call was sealed
	// at, inside the seal where a relay cannot change them, so the receiver
	// can refuse a call it has run before or one that is old.
	ID   string `json:"id"`
	Sent int64  `json:"sent"`
	// From and Kind are the member id the call speaks for and its kind. Only
	// a signature from the key pinned to that id makes them count.
	From string      `json:"from,omitempty"`
	Kind member.Kind `json:"kind,omitempty"`
	// Key is the public half of the caller's member key and Sig its signature
	// over CallMessage. An unsigned call carries neither.
	Key []byte `json:"key,omitempty"`
	Sig []byte `json:"sig,omitempty"`
}

// ProxyResponse is the wire form of the answer to one ProxyRequest.
type ProxyResponse struct {
	RequestID string `json:"requestId"`
	// Sealed is the ProxyResult, sealed with RequestID as additional data.
	Sealed []byte `json:"sealed,omitempty"`
	// Error is set only when the relay answers in the target's place, such as
	// when nobody is connected under its id. The relay holds no frame key, so
	// a hostile one can fake "nobody is there" but never an answer.
	Error string `json:"error,omitempty"`
}

// ProxyResult is what a ProxyResponse answers once opened.
type ProxyResult struct {
	Status int    `json:"status"`
	Body   []byte `json:"body,omitempty"`
	// Key and Sig are the answering member's public key and its signature
	// over ResultMessage, which the caller checks before it acts on the
	// answer.
	Key []byte `json:"key,omitempty"`
	Sig []byte `json:"sig,omitempty"`
}

// stamp is call with requestID and, unless Sent is set, the current time.
func stamp(requestID string, call ProxyCall) ProxyCall {
	call.ID = requestID
	if call.Sent == 0 {
		call.Sent = time.Now().Unix()
	}
	return call
}

// SealCall seals one call for target as it is, stamped with requestID and,
// unless Sent is set, the current time.
func SealCall(key []byte, requestID, target string, call ProxyCall) ([]byte, error) {
	plain, err := json.Marshal(stamp(requestID, call))
	if err != nil {
		return nil, err
	}
	return seal(key, requestAAD(requestID, target), plain)
}

// OpenCall reverses SealCall and SealSignedCall. A signed call whose signature
// does not hold under sg opens to ErrSignature, with the call as it came, so
// the refusal can be signed for it.
func OpenCall(key []byte, sg keys.Signing, requestID, target string, sealed []byte) (ProxyCall, error) {
	plain, err := open(key, requestAAD(requestID, target), sealed)
	if err != nil {
		return ProxyCall{}, err
	}
	var call ProxyCall
	if err := json.Unmarshal(plain, &call); err != nil || call.ID != requestID {
		return ProxyCall{}, ErrSealed
	}
	if !verifyCall(sg, target, call) {
		return call, ErrSignature
	}
	return call, nil
}

// SealResult seals one answer for the wire.
func SealResult(key []byte, requestID string, result ProxyResult) ([]byte, error) {
	plain, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return seal(key, responseAAD(requestID), plain)
}

// OpenResult reverses SealResult.
func OpenResult(key []byte, requestID string, sealed []byte) (ProxyResult, error) {
	plain, err := open(key, responseAAD(requestID), sealed)
	if err != nil {
		return ProxyResult{}, err
	}
	var res ProxyResult
	if err := json.Unmarshal(plain, &res); err != nil {
		return ProxyResult{}, ErrSealed
	}
	return res, nil
}

// Encode marshals one frame ready to be written to the socket.
func Encode(typ string, data any) ([]byte, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Type: typ, Data: payload})
}

// Decode reads a frame's envelope without its payload, so a frame can be
// routed on its type and forwarded as it came.
func Decode(frame []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(frame, &env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// Into unmarshals the payload of a decoded frame.
func (e Envelope) Into(v any) error {
	return json.Unmarshal(e.Data, v)
}

var errLooseKey = errors.New("relay: a frame names a field twice or in another spelling")

// intoStrict is Into for a payload one side checks and another acts on.
// encoding/json matches keys regardless of case, Unicode folding included, and
// lets the last of two equal keys win, so this refuses a key that is not
// spelled exactly like one of v's or that comes twice. Unknown keys pass, for
// a newer sender.
func (e Envelope) intoStrict(v any) error {
	known := jsonKeys(reflect.TypeOf(v).Elem())
	dec := json.NewDecoder(bytes.NewReader(e.Data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errLooseKey
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] {
			return errLooseKey
		}
		seen[key] = true
		for _, k := range known {
			if key != k && strings.EqualFold(key, k) {
				return errLooseKey
			}
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return errLooseKey
		}
	}
	return e.Into(v)
}

// jsonKeys is the JSON names of struct type t's fields.
func jsonKeys(t reflect.Type) []string {
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" {
			name = t.Field(i).Name
		}
		keys = append(keys, name)
	}
	return keys
}
