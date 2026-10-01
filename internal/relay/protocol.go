package relay

// The wire protocol both ends of a relay connection speak. The relay server
// and the client an instance dials it with marshal these same types, so a
// renamed field cannot land on one side only.
//
// Bodies travel as []byte, which encoding/json carries as base64. One JSON
// text frame per message keeps the protocol usable from a plain WebSocket
// client with nothing but a JSON parser (the mobile app). File downloads
// (GET /api/tasks/{id}/file) pass through here too: sealed, but base64 in a
// single frame whose length the relay can see, not a stream.

import (
	"encoding/json"
	"time"
	"unicode/utf8"
)

// The frame types. Anything else on the socket is ignored rather than treated
// as an error, see Server.Route.
const (
	// TypeHello is the first frame a client sends and the only one carrying the
	// relay key.
	TypeHello = "hello"
	// TypeAnnounce is sent by the relay only: who else is on this key.
	TypeAnnounce = "announce"
	// TypePresence is sent by the relay only: a sibling's connection went away.
	TypePresence = "presence"
	// TypeProxyRequest wraps one call to a sibling's REST API.
	TypeProxyRequest = "proxy-request"
	// TypeProxyResponse is that call's answer, matched by request ID.
	TypeProxyResponse = "proxy-response"
)

// AccountService is the service id the relay key is sealed under in the
// credential store (internal/accounts). Both the API route that writes the key
// and the client that reads it import this package, so the id is spelled once.
// It is not in accounts.Catalogue because the relay is not a hoster the
// Accounts page should list.
const AccountService = "relay"

// Envelope is every frame on this socket: a type discriminator plus that
// type's payload, the same {type,data} shape internal/hub sends to the web UI.
type Envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Hello authenticates and identifies a connection in one frame.
//
// The key rides the first frame rather than the URL because a reverse proxy in
// front of the relay logs request URLs, and the browser WebSocket API cannot
// set a header. Announce is carried inside Hello so the relay can strip the key
// before telling siblings who arrived.
type Hello struct {
	Key      string   `json:"key"`
	Announce Announce `json:"announce"`
}

// Announce is one instance introducing itself to everyone else on its key.
// Receiving it means that instance is online; there is no separate online
// presence frame, so an arrival cannot be seen half-applied.
//
// This is the in-memory shape. On the wire the identity fields travel inside
// Sealed and the plaintext ones are empty; sealAnnounce and openAnnounce
// convert at the socket boundary in client.go.
type Announce struct {
	// InstanceID is the instance's own stable identifier and the address a
	// proxy-request is routed to. It is the one field that cannot be sealed,
	// because the relay routes on it.
	InstanceID string `json:"instanceId"`
	// Sealed carries this instance's Identity, sealed under the frame key with
	// InstanceID as additional data, so a relay cannot present one instance's
	// identity as another's. Empty in the in-memory form and from older peers.
	Sealed []byte `json:"sealed,omitempty"`

	// The identity fields. Current versions send them empty and put them in
	// Sealed; they keep their json tags so older peers that still send them in
	// the clear can be read (see openAnnounce).

	// Name is what the Instances page shows: InstanceName if set, else the
	// hostname. The hostname fallback is why it is sealed, since it often names
	// the machine's owner.
	Name string `json:"name,omitempty"`
	// Deployment is "container" or "desktop" (buildinfo.Deployment).
	Deployment string `json:"deployment,omitempty"`
	// Client marks a connection that uses the relay without serving an API,
	// such as the mobile app. Every connection has to announce to join a key,
	// and without this flag a phone would show up in every sibling's instance
	// list as a target that answers 501 to everything.
	Client bool `json:"client,omitempty"`
	// Address is where the instance's web interface is, which the Instances
	// page shows and opens: its first known domain, else its address on its
	// network. Sealed, because a domain says whose instance it is.
	Address string `json:"address,omitempty"`
}

// Identity is the part of an announce the relay server never reads: it routes
// on InstanceID alone. A relay operator still sees the group key, each
// member's public IP, the instance ids and the timing of arrivals and
// departures, so sealing this does not make a relay blind.
type Identity struct {
	Name       string `json:"name,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	Client     bool   `json:"client,omitempty"`
	Address    string `json:"address,omitempty"`
}

// announceAAD binds an announce's seal to its instance id. Its label differs
// from requestAAD and responseAAD, so a blob from one frame type cannot be
// opened as another.
func announceAAD(instanceID string) string {
	return "announce\x00" + instanceID
}

// SealIdentity seals the identity half of an announce. It is exported so the
// mobile app's and the extension's ports of this protocol can be tested
// against it.
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

// sealAnnounce converts an in-memory announce to its wire form. The plaintext
// identity fields are blanked rather than sent alongside the seal, which would
// leave the hostname on the wire; a peer too old to open the seal shows an
// unnamed instance until it updates.
func sealAnnounce(frameKey []byte, a Announce) (Announce, error) {
	sealed, err := SealIdentity(frameKey, a.InstanceID, Identity{
		Name:       ClipName(a.Name),
		Deployment: a.Deployment,
		Client:     a.Client,
		Address:    FitAddress(a.Address),
	})
	if err != nil {
		return Announce{}, err
	}
	return Announce{InstanceID: a.InstanceID, Sealed: sealed}, nil
}

// openAnnounce converts a wire announce back to the in-memory form. An
// unsealed announce comes from an older peer and is used as is. One whose seal
// does not open comes from a peer on a different frame key; it is kept under
// its bare id rather than dropped, so the key mismatch stays visible.
func openAnnounce(frameKey []byte, a Announce) Announce {
	if len(a.Sealed) == 0 {
		return a
	}
	id, err := OpenIdentity(frameKey, a.InstanceID, a.Sealed)
	if err != nil {
		return Announce{InstanceID: a.InstanceID}
	}
	return Announce{
		InstanceID: a.InstanceID,
		Name:       id.Name,
		Deployment: id.Deployment,
		Client:     id.Client,
		Address:    FitAddress(id.Address),
	}
}

// MaxNameBytes keeps the name an instance or an app goes by small enough that
// every hello fits in helloLimit.
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

// MaxAddressBytes bounds an announced address for the same reason as
// MaxNameBytes.
const MaxAddressBytes = 200

// FitAddress is address, or "" when it is longer than MaxAddressBytes. A cut
// address would lead somewhere else, so it is left out instead.
func FitAddress(address string) string {
	if len(address) > MaxAddressBytes {
		return ""
	}
	return address
}

// Presence reports that a sibling's connection state changed. The relay only
// sends Online=false; an arrival is an Announce.
type Presence struct {
	InstanceID string `json:"instanceId"`
	Online     bool   `json:"online"`
}

// ProxyRequest is the wire form of one call to a sibling: the two fields the
// relay routes on and a sealed ProxyCall it cannot read (see seal.go).
type ProxyRequest struct {
	// RequestID is chosen by the caller and matches the response back to it.
	RequestID string `json:"requestId"`
	// Target is the InstanceID this call is for. A target that is not
	// connected on the same key gets an error response, so the caller does not
	// wait out its timeout.
	Target string `json:"target"`
	// Sealed is a ProxyCall sealed under the frame key with RequestID and
	// Target as additional data, so a relay cannot redirect it to another
	// instance and have it open.
	Sealed []byte `json:"sealed,omitempty"`
}

// ProxyCall is what a ProxyRequest asks once opened: the same (method, path,
// body) shape federation.Manager.Proxy sends over direct HTTP. It only ever
// travels sealed.
type ProxyCall struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body,omitempty"`
	// Authorization becomes the Authorization header of the replayed request.
	// Only the mobile app sets it, because the relay is its only channel to
	// the target; instance-to-instance calls leave it empty. It is one named
	// field rather than a header map so a caller cannot set Host,
	// X-Forwarded-For or a cookie on a request the target replays against its
	// own handler. Being a reusable credential, it is the main reason calls
	// are sealed.
	Authorization string `json:"authorization,omitempty"`
	// ID and Sent are the request id and the Unix time the call was sealed
	// at. They travel inside the seal, where a relay cannot change them, so
	// the receiver can refuse a frame it has run before or one that is old.
	ID   string `json:"id"`
	Sent int64  `json:"sent"`
	// From is the phone app's relay id, so an instance can turn away a phone
	// removed from the group. Instances leave it empty.
	From string `json:"from,omitempty"`
}

// ProxyResponse is the wire form of the answer to one ProxyRequest.
type ProxyResponse struct {
	RequestID string `json:"requestId"`
	// Sealed is a ProxyResult sealed under the frame key with RequestID as
	// additional data. Empty when Error is set.
	Sealed []byte `json:"sealed,omitempty"`
	// Error is set only when the relay itself answers instead of the target:
	// nobody is connected under that ID, or the sender is over its pending
	// budget. It stays in the clear because the relay has no key. A hostile
	// relay can fake "nobody is there", which it could do by dropping the frame
	// anyway, but it cannot fake an answer: Client.Proxy never treats an
	// unsealed response as a result.
	Error string `json:"error,omitempty"`
}

// ProxyResult is what a ProxyResponse answers once opened.
type ProxyResult struct {
	Status int    `json:"status"`
	Body   []byte `json:"body,omitempty"`
}

// requestAAD and responseAAD bind each direction's sealed blob to the routing
// fields that travel in the clear, so a relay that rewrites one produces a
// frame that fails its tag. The separator cannot occur in an instance id and
// the label differs per direction, so a request cannot be replayed as a
// response.
func requestAAD(requestID, target string) string {
	return "proxy-request\x00" + requestID + "\x00" + target
}

func responseAAD(requestID string) string {
	return "proxy-response\x00" + requestID
}

// SealCall seals one call for the wire, stamped with requestID and, unless
// Sent is set, the current time. It is exported so the mobile app's
// TypeScript port can be tested against it.
func SealCall(key []byte, requestID, target string, call ProxyCall) ([]byte, error) {
	call.ID = requestID
	if call.Sent == 0 {
		call.Sent = time.Now().Unix()
	}
	plain, err := json.Marshal(call)
	if err != nil {
		return nil, err
	}
	return seal(key, requestAAD(requestID, target), plain)
}

// OpenCall reverses SealCall.
func OpenCall(key []byte, requestID, target string, sealed []byte) (ProxyCall, error) {
	plain, err := open(key, requestAAD(requestID, target), sealed)
	if err != nil {
		return ProxyCall{}, err
	}
	var call ProxyCall
	if err := json.Unmarshal(plain, &call); err != nil || call.ID != requestID {
		// No honest sender seals something unparseable or stamped with
		// another id, so the caller treats it like any other blob that fails
		// to open.
		return ProxyCall{}, ErrSealed
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

// Decode reads a frame's envelope without touching its payload, so a routing
// decision can be made on the type alone and the original bytes forwarded
// verbatim.
func Decode(frame []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(frame, &env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// Into unmarshals the payload of an already-decoded frame.
func (e Envelope) Into(v any) error {
	return json.Unmarshal(e.Data, v)
}
