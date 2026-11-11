package relay

import (
	"bytes"
	"context"
	"errors"
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

func TestACallWaitsForAnAnswerThatIsStillArriving(t *testing.T) {
	c := &Client{}
	answer := make(chan ProxyResponse, 1)
	c.inbound.Store(reading)
	go func() {
		for range 20 {
			c.moved.Store(time.Now().UnixNano())
			time.Sleep(10 * time.Millisecond)
		}
		c.inbound.Store(handling)
		time.Sleep(80 * time.Millisecond)
		answer <- ProxyResponse{RequestID: "r1"}
		c.inbound.Store(idle)
	}()
	resp, err := c.await(context.Background(), answer, 50*time.Millisecond, 40*time.Millisecond)
	if err != nil || resp.RequestID != "r1" {
		t.Errorf("got %+v, %v", resp, err)
	}
}

func TestACallGivesUpWhenNothingComes(t *testing.T) {
	for name, state := range map[string]int32{"nothing arriving": idle, "a frame that stopped": reading} {
		t.Run(name, func(t *testing.T) {
			c := &Client{}
			c.inbound.Store(state)
			c.moved.Store(time.Now().UnixNano())
			start := time.Now()
			_, err := c.await(context.Background(), make(chan ProxyResponse), 50*time.Millisecond, 40*time.Millisecond)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
				t.Errorf("after %v: %v", time.Since(start), err)
			}
		})
	}
}

func TestACallEndsWithItsContext(t *testing.T) {
	c := &Client{}
	c.inbound.Store(handling)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.await(ctx, make(chan ProxyResponse), time.Hour, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v", err)
	}
}
