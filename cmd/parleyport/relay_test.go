package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/junkerderprovinz/parleyport/kit/member"
)

const testKey = "relay-key-of-the-endpoint-test-0123456789"

// frame is one frame as a client reads it off the socket.
type frame struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

func dialRelay(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

func writeRaw(t *testing.T, c *websocket.Conn, raw string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, []byte(raw)); err != nil {
		t.Fatal(err)
	}
}

func readRaw(t *testing.T, c *websocket.Conn, want string) frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("waiting for %s: %v", want, err)
	}
	var f frame
	if err := json.Unmarshal(b, &f); err != nil || f.Type != want {
		t.Fatalf("got %s, want a %s frame", b, want)
	}
	return f
}

// TestTheRelayEndpointServesEveryKindOfClient drives the endpoint main mounts
// with frames written by hand the way the clients write them: one that proves
// its id after reading the challenge, and an older one that sends its hello at
// once without a proof.
func TestTheRelayEndpointServesEveryKindOfClient(t *testing.T) {
	srv := httptest.NewServer(routes(newRelay([]string{"relay.example.com"}, nil)))
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay/connect"

	ident, err := member.FromSeed(member.KindInstance, bytes.Repeat([]byte{'i'}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	instanceID := ident.ID()
	const olderID = "0123456789abcdef0123456789abcdef01234567"

	instance := dialRelay(t, url)
	nonce, err := base64.StdEncoding.DecodeString(readRaw(t, instance, "challenge").Data["nonce"].(string))
	if err != nil {
		t.Fatal(err)
	}
	// The proof names the relay's public name, not the address dialled here.
	proof := ident.ProveHello(testKey, "relay.example.com", nonce)
	writeRaw(t, instance, `{"type":"hello","data":{"key":"`+testKey+`","announce":{"instanceId":"`+instanceID+
		`","sealed":"AAAA"},"proof":{"kind":"instance","relay":"relay.example.com","key":"`+
		base64.StdEncoding.EncodeToString(proof.Key)+`","sig":"`+base64.StdEncoding.EncodeToString(proof.Sig)+`"}}}`)

	older := dialRelay(t, url)
	writeRaw(t, older, `{"type":"hello","data":{"key":"`+testKey+`","announce":{"instanceId":"`+olderID+`","sealed":"AAAA"}}}`)
	readRaw(t, older, "challenge")
	if got := readRaw(t, older, "announce").Data; got["instanceId"] != instanceID || got["sealed"] != "AAAA" {
		t.Fatalf("the older client was introduced to %v", got)
	}
	if got := readRaw(t, instance, "announce").Data; got["instanceId"] != olderID || got["sealed"] != "AAAA" {
		t.Fatalf("the instance was introduced to %v", got)
	}

	writeRaw(t, older, `{"type":"proxy-request","data":{"requestId":"r1","target":"`+instanceID+`","sealed":"AQID","sender":"somebody"}}`)
	if got := readRaw(t, instance, "proxy-request").Data; got["requestId"] != "r1" || got["sealed"] != "AQID" || got["sender"] != olderID {
		t.Fatalf("the instance got the call as %v", got)
	}
	writeRaw(t, instance, `{"type":"proxy-response","data":{"requestId":"r1","sealed":"BAUG"}}`)
	if got := readRaw(t, older, "proxy-response").Data; got["requestId"] != "r1" || got["sealed"] != "BAUG" {
		t.Fatalf("the older client got the answer as %v", got)
	}

	impostor := dialRelay(t, url)
	writeRaw(t, impostor, `{"type":"hello","data":{"key":"`+testKey+`","announce":{"instanceId":"`+instanceID+`"}}}`)
	readRaw(t, impostor, "challenge")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := impostor.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("a connection announcing the proven id without its key got %v, want it turned away", err)
	}

	_ = older.Close(websocket.StatusNormalClosure, "")
	if got := readRaw(t, instance, "presence").Data; got["instanceId"] != olderID || got["online"] != false {
		t.Fatalf("the instance was told %v when the older client left", got)
	}
}
