package relay

import "time"

// writeTimeout bounds one frame write.
const writeTimeout = 5 * time.Second

// helloTimeout bounds how long a connection may stay open without saying who
// it is, so a socket that goes quiet cannot hold a goroutine forever.
const helloTimeout = 10 * time.Second

// challengeSize is how many random bytes the challenge a hello signs has.
const challengeSize = 32

// readLimit caps one frame once the hello has passed: room for an answer of
// 8 MiB with its seal and coding, and still no way for one peer to pin
// unbounded memory. A frame is read into a buffer that grows with it, so the
// cap costs nothing until a frame that large arrives.
const readLimit = 16 << 20

// MaxAnswerBytes is the largest answer a relay frame carries. On the wire the
// body is coded as base64 twice, once in the result and once around the seal,
// which makes it 16/9 as large; 4 KiB is room for the fields, the seal and the
// envelope around it.
const MaxAnswerBytes = (readLimit - 4<<10) / 16 * 9

// minKeyLength is the shortest group key the relay accepts. It cannot enforce
// entropy, only rule out the laziest hand-made keys; a derived key has 64
// characters.
const minKeyLength = 32

// maxClientsPerKey bounds one group on the relay, so a guessed or leaked key
// can only make the relay hold so much, and a client keeps no more siblings
// than the relay would introduce.
const maxClientsPerKey = 64

// frameOf marshals one outbound frame. Every payload is a struct of this
// package that encoding/json cannot fail on.
func frameOf(typ string, data any) []byte {
	b, _ := Encode(typ, data)
	return b
}
