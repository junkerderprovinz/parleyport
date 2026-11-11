package relay

import (
	"context"
	"io"
	"sync/atomic"
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

// The states of a client's read loop, which a call waiting for its answer
// looks at.
const (
	idle int32 = iota
	reading
	handling
)

// moving is a message reader that notes when bytes last came in.
type moving struct {
	r     io.Reader
	moved *atomic.Int64
}

func (m moving) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > 0 {
		m.moved.Store(time.Now().UnixNano())
	}
	return n, err
}

// await waits for answer. It gives up after wait without one, but not while a
// frame is being handled or still coming in and moved within stall: that
// frame may be the answer, and a large one takes a while to cross a slow link
// or to be read on a busy machine.
func (c *Client) await(ctx context.Context, answer <-chan ProxyResponse, wait, stall time.Duration) (ProxyResponse, error) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ProxyResponse{}, ctx.Err()
		case resp := <-answer:
			return resp, nil
		case <-t.C:
		}
		if !c.receiving(stall) {
			select {
			case resp := <-answer:
				return resp, nil
			default:
				return ProxyResponse{}, context.DeadlineExceeded
			}
		}
		t.Reset(stall)
	}
}

func (c *Client) receiving(stall time.Duration) bool {
	switch c.inbound.Load() {
	case handling:
		return true
	case reading:
		return time.Since(time.Unix(0, c.moved.Load())) < stall
	}
	return false
}
