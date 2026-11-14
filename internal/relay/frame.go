package relay

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/coder/websocket"
)

// chunkBytes is how much of a frame goes out between two looks at the link.
const chunkBytes = 64 << 10

// messageWriter starts a message, as *websocket.Conn does.
type messageWriter interface {
	Writer(ctx context.Context, typ websocket.MessageType) (io.WriteCloser, error)
}

// errStalled is what sendFrame returns when one chunk outlasted stall.
var errStalled = errors.New("the link stopped taking the frame")

// sendFrame writes frame to conn in chunks and gives up once one chunk takes
// longer than stall. A deadline for the whole frame would cut a large answer
// off on a slow link or a busy machine, and the connection with it, while the
// link was still moving. Pings go out between the chunks.
func sendFrame(ctx context.Context, conn messageWriter, frame []byte, stall time.Duration) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stalled := func() { cancel(errStalled) }
	// The writer reports only that its context ended, not why.
	defer func() {
		if err != nil && errors.Is(context.Cause(ctx), errStalled) {
			err = errStalled
		}
	}()
	w, err := conn.Writer(ctx, websocket.MessageText)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		n := min(len(frame), chunkBytes)
		timer := time.AfterFunc(stall, stalled)
		_, err := w.Write(frame[:n])
		timer.Stop()
		if err != nil {
			return err
		}
		frame = frame[n:]
	}
	timer := time.AfterFunc(stall, stalled)
	defer timer.Stop()
	return w.Close()
}
