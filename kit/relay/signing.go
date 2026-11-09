package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

// Every member holds the frame key, so a seal only says that somebody with the
// phrase sent a frame. Calls and answers are therefore signed with the
// member's own key as well, inside the seal where the relay never sees it:
// the receiver pins the key behind a caller's id, and a caller takes an answer
// only when the key the target's id is made from signed it, for this call
// alone.

// ErrSignature is returned for a call that opens but whose signature does not
// hold for the key it presents. Only a member can seal such a call, so unlike
// ErrSealed it is answered, with SignatureRefused.
var ErrSignature = errors.New("relay: the call's signature does not match its member key")

// CallMessage is what a member signs for a call to target: every field with
// its length, under sg's call label.
func CallMessage(sg keys.Signing, target string, c ProxyCall) []byte {
	return member.Message(sg.Call, uint64(c.Sent), //nolint:gosec // G115: the bits of the time are signed as they are
		[]byte(c.ID), []byte(target), []byte(c.Method), []byte(c.Path), c.Body, []byte(c.From), []byte(c.Kind))
}

// ResultMessage is what member from signs when it answers with r the call that
// arrived sealed as sealedCall under requestID. The call is named by the hash
// of its sealed bytes, which covers every field it carries.
func ResultMessage(sg keys.Signing, requestID, from string, sealedCall []byte, r ProxyResult) []byte {
	call := sha256.Sum256(sealedCall)
	return member.Message(sg.Result, uint64(int64(r.Status)), //nolint:gosec // G115: a status is signed as its bits
		[]byte(requestID), []byte(from), call[:], r.Body)
}

// SignCall stamps call as SealCall does and signs it for target as id, whose
// id and kind it speaks for. A nil id leaves it unsigned. The caller keeps the
// sealed call to check the answer against.
func SignCall(sg keys.Signing, id *member.Identity, requestID, target string, call ProxyCall) ProxyCall {
	call = stamp(requestID, call)
	call.Key, call.Sig = nil, nil
	if id != nil {
		call.From, call.Kind = id.ID(), id.Kind()
		call.Key = id.Public()
		call.Sig = id.Sign(CallMessage(sg, target, call))
	}
	return call
}

// SealSignedCall seals the call SignCall makes.
func SealSignedCall(frameKey []byte, sg keys.Signing, id *member.Identity, requestID, target string, call ProxyCall) ([]byte, error) {
	return SealCall(frameKey, requestID, target, SignCall(sg, id, requestID, target, call))
}

// SignResult is r signed by id as its answer to the call that arrived sealed as
// sealedCall under requestID. A nil id leaves it unsigned.
func SignResult(sg keys.Signing, id *member.Identity, requestID string, sealedCall []byte, r ProxyResult) ProxyResult {
	r.Key, r.Sig = nil, nil
	if id != nil {
		r.Key = id.Public()
		r.Sig = id.Sign(ResultMessage(sg, requestID, id.ID(), sealedCall, r))
	}
	return r
}

// VerifyResult reports whether r is target's answer to the caller's own call,
// sent sealed as sealedCall under requestID: signed by the key target's
// instance id is made from.
func VerifyResult(sg keys.Signing, requestID, target string, sealedCall []byte, r ProxyResult) bool {
	return len(r.Sig) == ed25519.SignatureSize && member.ID(member.KindInstance, r.Key) == target &&
		ed25519.Verify(r.Key, ResultMessage(sg, requestID, target, sealedCall, r), r.Sig)
}

// Signed reports whether a call presents a member key at all.
func (c ProxyCall) Signed() bool { return len(c.Key) > 0 || len(c.Sig) > 0 }

// verifyCall reports whether c is unsigned or signed with a signature that
// holds. An unsigned call only goes on to be refused or allowed by whoever
// serves it.
func verifyCall(sg keys.Signing, target string, c ProxyCall) bool {
	if !c.Signed() {
		return true
	}
	return len(c.Key) == ed25519.PublicKeySize && len(c.Sig) == ed25519.SignatureSize &&
		ed25519.Verify(c.Key, CallMessage(sg, target, c), c.Sig)
}

// RefusalBody is the body of a refused call in the {error, code} shape, so
// every client can put the code into its own words.
func RefusalBody(code, text string) []byte {
	b, _ := json.Marshal(map[string]string{"error": text, "code": code})
	return b
}

// SignatureRefused is the answer body for a call whose signature does not hold.
var SignatureRefused = RefusalBody("memberSignature", "the signature on this call does not match the key it came with")

type sourceKey struct{}

// WithSource marks ctx with where a call came in: the relay connection that
// sent it, or the address of a direct call. Whoever holds the phrase can open
// as many of either as it likes, so a source proves nothing; it only keeps one
// of them from using up a limit the whole group shares.
func WithSource(ctx context.Context, source string) context.Context {
	return context.WithValue(ctx, sourceKey{}, source)
}

// SourceOf returns what WithSource put on ctx, "" when there is nothing.
func SourceOf(ctx context.Context) string {
	s, _ := ctx.Value(sourceKey{}).(string)
	return s
}
