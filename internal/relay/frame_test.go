package relay

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// pacedConn takes every chunk of a message after a pause, like a slow link.
// The chunk numbered stuck never goes out.
type pacedConn struct {
	pause time.Duration
	stuck int

	mu     sync.Mutex
	got    bytes.Buffer
	chunks int
	closed bool
}

func (p *pacedConn) Writer(ctx context.Context, _ websocket.MessageType) (io.WriteCloser, error) {
	return &pacedWriter{conn: p, ctx: ctx}, nil
}

type pacedWriter struct {
	conn *pacedConn
	ctx  context.Context
}

func (w *pacedWriter) Write(b []byte) (int, error) {
	p := w.conn
	p.mu.Lock()
	p.chunks++
	n := p.chunks
	p.mu.Unlock()
	if n == p.stuck {
		<-w.ctx.Done()
		return 0, w.ctx.Err()
	}
	select {
	case <-time.After(p.pause):
	case <-w.ctx.Done():
		return 0, w.ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.got.Write(b)
}

func (w *pacedWriter) Close() error {
	w.conn.mu.Lock()
	defer w.conn.mu.Unlock()
	w.conn.closed = true
	return nil
}

func TestAFrameCrossesASlowLinkThatKeepsMoving(t *testing.T) {
	frame := bytes.Repeat([]byte("x"), 10*chunkBytes+1)
	conn := &pacedConn{pause: 20 * time.Millisecond}
	start := time.Now()
	if err := sendFrame(context.Background(), conn, frame, 100*time.Millisecond); err != nil {
		t.Fatalf("a link that kept moving for %v: %v", time.Since(start), err)
	}
	if !bytes.Equal(conn.got.Bytes(), frame) || !conn.closed {
		t.Errorf("wrote %d of %d bytes, closed %v", conn.got.Len(), len(frame), conn.closed)
	}
	if conn.chunks != 11 {
		t.Errorf("wrote %d chunks", conn.chunks)
	}
}

func TestAFrameStopsWhenTheLinkStalls(t *testing.T) {
	frame := bytes.Repeat([]byte("x"), 10*chunkBytes)
	conn := &pacedConn{stuck: 3}
	done := make(chan error, 1)
	go func() { done <- sendFrame(context.Background(), conn, frame, 50*time.Millisecond) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a stalled link took the frame")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled link held the write")
	}
}
