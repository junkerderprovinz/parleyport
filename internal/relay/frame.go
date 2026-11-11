package relay

import (
	"context"
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

// sendFrame writes frame to conn in chunks and gives up once one chunk takes
// longer than stall. A deadline for the whole frame would cut a large answer
// off on a slow link or a busy machine, and the connection with it, while the
// link was still moving. Pings go out between the chunks.
func sendFrame(ctx context.Context, conn messageWriter, frame []byte, stall time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w, err := conn.Writer(ctx, websocket.MessageText)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		n := min(len(frame), chunkBytes)
		timer := time.AfterFunc(stall, cancel)
		_, err := w.Write(frame[:n])
		timer.Stop()
		if err != nil {
			return err
		}
		frame = frame[n:]
	}
	timer := time.AfterFunc(stall, cancel)
	defer timer.Stop()
	return w.Close()
}
