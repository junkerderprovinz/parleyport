package relay

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/junkerderprovinz/parleyport/kit/keys"
	"github.com/junkerderprovinz/parleyport/kit/member"
)

func TestClientAnnouncesItselfAndTracksSiblings(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	waitFor(t, "alpha to connect", alpha.Connected)

	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)

	// bravo is a raw socket, so it reads the wire form a relay operator sees:
	// the id in the clear, the name and deployment only sealed.
	var seen Announce
	if err := readFrame(t, bravo, TypeAnnounce).Into(&seen); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if seen.InstanceID != alphaID {
		t.Errorf("bravo was introduced to %+v, want alpha's id in the clear", seen)
	}
	if seen.Name != "" || seen.Deployment != "" {
		t.Errorf("the wire announce still carries identity in the clear: %+v", seen)
	}
	id, err := OpenIdentity(testFrameKey, seen.InstanceID, seen.Sealed)
	if err != nil {
		t.Fatalf("the sealed identity did not open: %v", err)
	}
	if id.Name != alphaID || id.Deployment != "desktop" {
		t.Errorf("sealed identity = %+v, want alpha/desktop", id)
	}

	waitFor(t, "alpha to see bravo", func() bool {
		sibs := alpha.Siblings()
		return len(sibs) == 1 && sibs[0].InstanceID == bravoID
	})

	_ = bravo.CloseNow()
	waitFor(t, "alpha to see bravo go", func() bool { return len(alpha.Siblings()) == 0 })
}

func TestARenamedClientIsSeenUnderItsNewName(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	bravo := startClient(t, addr, "shared-relay-test-key-0123456789ab", bravoID, nil)
	waitFor(t, "bravo to see alpha", func() bool { return len(bravo.Siblings()) == 1 })

	alpha.SetSelf(Announce{InstanceID: "someone else", Name: "Cellar", Deployment: "container", Address: "https://cellar.lan"})
	waitFor(t, "bravo to see alpha's new name", func() bool {
		sibs := bravo.Siblings()
		return len(sibs) == 1 && sibs[0].InstanceID == alphaID && sibs[0].Name == "Cellar" &&
			sibs[0].Deployment == "container" && sibs[0].Address == "https://cellar.lan"
	})
}

func TestClientProxiesToASibling(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })

	type result struct {
		body   []byte
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		body, status, err := alpha.Proxy(context.Background(), bravoID, http.MethodPost, "/api/links", []byte(`{"url":"x"}`))
		done <- result{body, status, err}
	}()

	var req ProxyRequest
	if err := readFrame(t, bravo, TypeProxyRequest).Into(&req); err != nil {
		t.Fatalf("proxy-request: %v", err)
	}
	if req.Target != bravoID {
		t.Fatalf("bravo received %+v, want alpha's call unchanged", req)
	}
	call := openFrom(t, req.RequestID, bravoID, req.Sealed)
	if call.Method != http.MethodPost || call.Path != "/api/links" {
		t.Fatalf("bravo opened %+v, want alpha's call unchanged", call)
	}
	if string(call.Body) != `{"url":"x"}` {
		t.Errorf("body arrived as %s, want it byte for byte", call.Body)
	}
	writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{
		RequestID: req.RequestID,
		Sealed:    sealResultFor(t, req.RequestID, SignResult(testSigning, &bravoKey, req.RequestID, req.Sealed, ProxyResult{Status: 201, Body: []byte(`{"added":1}`)})),
	})

	got := <-done
	if got.err != nil {
		t.Fatalf("proxy: %v", got.err)
	}
	if got.status != 201 || string(got.body) != `{"added":1}` {
		t.Errorf("got %d %s, want bravo's own answer", got.status, got.body)
	}
}

func TestClientAnswersASiblingsCall(t *testing.T) {
	tests := []struct {
		name       string
		serve      ProxyHandler
		wantStatus int
		wantBody   string
	}{
		{
			name: "the handler answers",
			serve: func(_ context.Context, call ProxyCall) (int, []byte) {
				return http.StatusOK, []byte(call.Method + " " + call.Path)
			},
			wantStatus: http.StatusOK,
			wantBody:   "GET /api/tasks",
		},
		{
			name:       "no handler configured",
			serve:      nil,
			wantStatus: http.StatusNotImplemented,
			wantBody:   "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, _ := relayOn(t, "127.0.0.1:0")
			alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, tc.serve)
			waitFor(t, "alpha to connect", alpha.Connected)
			bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
			readFrame(t, bravo, TypeAnnounce)

			sealed := sealFor(t, "r1", alphaID, ProxyCall{Method: http.MethodGet, Path: "/api/tasks"})
			writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r1", Target: alphaID, Sealed: sealed})
			var resp ProxyResponse
			if err := readFrame(t, bravo, TypeProxyResponse).Into(&resp); err != nil {
				t.Fatalf("proxy-response: %v", err)
			}
			if resp.RequestID != "r1" {
				t.Fatalf("got %+v, want the answer to r1", resp)
			}
			res := openResultFrom(t, "r1", resp.Sealed)
			if res.Status != tc.wantStatus || string(res.Body) != tc.wantBody {
				t.Errorf("got %+v, want status %d body %q", res, tc.wantStatus, tc.wantBody)
			}
			if !VerifyResult(testSigning, "r1", alphaID, sealed, res) {
				t.Error("alpha's answer is not signed by its member key")
			}
		})
	}
}

// TestACallSentAgainOrLateIsNotRun has a handler drop what a ReplayGuard
// refuses, and checks that a dropped call gets no answer at all.
func TestACallSentAgainOrLateIsNotRun(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	var mu sync.Mutex
	var ran []string
	guard := NewReplayGuard()
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, func(_ context.Context, call ProxyCall) (int, []byte) {
		if !guard.Admit(call) {
			return StatusDrop, nil
		}
		mu.Lock()
		ran = append(ran, call.ID)
		mu.Unlock()
		return http.StatusOK, nil
	})
	waitFor(t, "alpha to connect", alpha.Connected)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)

	signer := identityFrom('m')
	signed := func(id string, call ProxyCall) []byte {
		sealed, err := SealSignedCall(testFrameKey, testSigning, &signer, id, alphaID, call)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	call := ProxyCall{Method: http.MethodPost, Path: "/api/queue/pause"}
	first := ProxyRequest{RequestID: "r1", Target: alphaID, Sealed: signed("r1", call)}
	late := call
	late.Sent = time.Now().Add(-10 * time.Minute).Unix()
	writeFrame(t, bravo, TypeProxyRequest, first)
	writeFrame(t, bravo, TypeProxyRequest, first)
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r2", Target: alphaID, Sealed: signed("r2", late)})
	writeFrame(t, bravo, TypeProxyRequest, ProxyRequest{RequestID: "r3", Target: alphaID, Sealed: signed("r3", call)})

	// Each call is answered on its own goroutine, so the answers to r1 and
	// r3 may come in either order.
	answered := map[string]bool{}
	for range 2 {
		var resp ProxyResponse
		if err := readFrame(t, bravo, TypeProxyResponse).Into(&resp); err != nil {
			t.Fatalf("proxy-response: %v", err)
		}
		answered[resp.RequestID] = true
	}
	if !answered["r1"] || !answered["r3"] {
		t.Fatalf("answered %v, want r1 and r3", answered)
	}
	quiet, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, frame, err := bravo.Read(quiet); err == nil {
		t.Fatalf("a third answer came: %s", frame)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 2 {
		t.Fatalf("ran %v, want r1 and r3 once each", ran)
	}
}

// TestProxyFailsFastRatherThanWaiting: a call that cannot reach its peer fails
// at once, not at the end of proxyTimeout.
func TestProxyFailsFastRatherThanWaiting(t *testing.T) {
	tests := []struct {
		name    string
		connect bool
		target  string
		wantErr string
	}{
		{
			name:    "the relay is not connected",
			connect: false,
			target:  bravoID,
			wantErr: "not connected",
		},
		{
			// The relay answers this one, and the client has to pass its
			// text on.
			name:    "nobody is connected as the target",
			connect: true,
			target:  "nobody",
			wantErr: "no instance nobody is connected",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, stop := relayOn(t, "127.0.0.1:0")
			// Stopped before the client exists, so it cannot briefly connect.
			if !tc.connect {
				stop()
			}
			alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
			if tc.connect {
				waitFor(t, "alpha to connect", alpha.Connected)
			}

			began := time.Now()
			_, _, err := alpha.Proxy(context.Background(), tc.target, http.MethodGet, "/api/tasks", nil)
			if err == nil {
				t.Fatal("the call succeeded, want it to fail")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got %v, want it to mention %q", err, tc.wantErr)
			}
			if time.Since(began) >= proxyTimeout {
				t.Errorf("the call took %v, want it to fail without waiting out the timeout", time.Since(began))
			}
		})
	}
}

// TestReconnectsAfterTheRelayDrops: an outage costs the instance its relay
// peers, and they come back on their own once the relay does.
func TestReconnectsAfterTheRelayDrops(t *testing.T) {
	addr, stop := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })

	stop()
	waitFor(t, "alpha to notice the outage", func() bool {
		return !alpha.Connected() && len(alpha.Siblings()) == 0
	})
	_ = bravo.CloseNow()

	// A fresh relay on the same address shares no state with the old one, so
	// everything the client sees now it re-established itself.
	relayOn(t, addr)
	waitFor(t, "alpha to reconnect", alpha.Connected)

	charlie := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", charlieID)
	var seen Announce
	if err := readFrame(t, charlie, TypeAnnounce).Into(&seen); err != nil {
		t.Fatalf("announce after reconnect: %v", err)
	}
	if seen.InstanceID != alphaID {
		t.Errorf("charlie was introduced to %+v, want the reconnected alpha", seen)
	}
	waitFor(t, "alpha to see charlie", func() bool {
		sibs := alpha.Siblings()
		return len(sibs) == 1 && sibs[0].InstanceID == charlieID
	})
}

func TestCallInFlightFailsWhenTheConnectionDies(t *testing.T) {
	addr, stop := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })

	failed := make(chan error, 1)
	go func() {
		_, _, err := alpha.Proxy(context.Background(), bravoID, http.MethodGet, "/api/tasks", nil)
		failed <- err
	}()
	// bravo receives the call and never answers it.
	readFrame(t, bravo, TypeProxyRequest)
	stop()

	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("the call succeeded, want it to fail with the connection")
		}
		// Two paths race and either is correct: alpha notices its own
		// connection died ("dropped"), or the relay notices bravo left first
		// and fails the call through failPending.
		if !strings.Contains(err.Error(), "dropped") && !strings.Contains(err.Error(), "disconnected before it replied") {
			t.Errorf("got %v, want it to say the connection dropped or that the target disconnected first", err)
		}
	case <-time.After(wsTimeout):
		t.Fatal("the call is still waiting; a dead connection must fail it at once")
	}
}

func TestNewClientRejectsMisconfiguration(t *testing.T) {
	valid := ClientOptions{
		URL:      "https://relay.example.com",
		Key:      "shared-relay-test-key-0123456789ab",
		FrameKey: testFrameKey,
		Signing:  testSigning,
		Self:     Announce{InstanceID: alphaID},
		Identity: &alphaKey,
	}
	tests := []struct {
		name   string
		mangle func(o *ClientOptions)
	}{
		{"no address", func(o *ClientOptions) { o.URL = "" }},
		{"no key", func(o *ClientOptions) { o.Key = "   " }},
		{"no instance id", func(o *ClientOptions) { o.Self.InstanceID, o.Identity = "", nil }},
		{"no frame key", func(o *ClientOptions) { o.FrameKey = nil }},
		{"a frame key of the wrong length", func(o *ClientOptions) { o.FrameKey = []byte("too short") }},
		{"an identity without labels to sign under", func(o *ClientOptions) { o.Signing = keys.Signing{} }},
		{"an identity that makes another id", func(o *ClientOptions) { o.Identity = &bravoKey }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := valid
			tc.mangle(&opts)
			if _, err := NewClient(opts); err == nil {
				t.Fatal("accepted, want an error")
			}
		})
	}
	if _, err := NewClient(valid); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}
	unsigned := valid
	unsigned.Identity, unsigned.Signing = nil, keys.Signing{}
	if _, err := NewClient(unsigned); err != nil {
		t.Fatalf("a client that signs nothing was rejected: %v", err)
	}
}

func TestAnIdentityGivesTheClientItsInstanceID(t *testing.T) {
	c, err := NewClient(ClientOptions{
		URL:      "https://relay.example.com",
		Key:      "shared-relay-test-key-0123456789ab",
		FrameKey: testFrameKey,
		Signing:  testSigning,
		Identity: &alphaKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.self.InstanceID != alphaID {
		t.Errorf("the client announces %q, want the id its identity makes", c.self.InstanceID)
	}
}

func TestACallIsSignedAsTheClientsIdentity(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })

	go func() { _, _, _ = alpha.Proxy(context.Background(), bravoID, http.MethodGet, "/api/tasks", nil) }()
	var req ProxyRequest
	if err := readFrame(t, bravo, TypeProxyRequest).Into(&req); err != nil {
		t.Fatal(err)
	}
	call := openFrom(t, req.RequestID, bravoID, req.Sealed)
	if !call.Signed() || call.From != alphaID || call.Kind != member.KindInstance || !bytes.Equal(call.Key, alphaKey.Public()) {
		t.Errorf("bravo opened a call from %q as %q with key %x, want alpha's signed call", call.From, call.Kind, call.Key)
	}
}

// TestAnAnswerNotSignedByTheTargetIsNoAnswer: bravo is on the relay, and
// somebody else holding the words answers alpha's calls to it, sealed under the
// frame key, as one who took bravo's place on the relay would. Neither an
// unsigned answer, one signed by another key, bravo's own answer to another
// call nor its answer to alpha's call altered on the way reaches alpha's
// caller, and a "removed" least of all.
func TestAnAnswerNotSignedByTheTargetIsNoAnswer(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	alpha := startClient(t, addr, "shared-relay-test-key-0123456789ab", alphaID, nil)
	bravo := dialInstance(t, "ws://"+addr+connectPath, "shared-relay-test-key-0123456789ab", bravoID)
	readFrame(t, bravo, TypeAnnounce)
	waitFor(t, "alpha to see bravo", func() bool { return len(alpha.Siblings()) == 1 })

	removed := ProxyResult{Status: http.StatusGone, Body: []byte("removed")}
	// Whoever holds the words can call bravo under the request id of alpha's
	// call and get bravo's signed answer to that call instead.
	another := sealFor(t, "another", bravoID, SignCall(testSigning, &charlieKey, "another", bravoID, ProxyCall{Method: http.MethodGet, Path: "/api/tasks"}))
	// Or change what alpha's call asks and keep its id, key and signature,
	// which bravo refuses with a signed answer of its own.
	altered := func(id string, sealed []byte) []byte {
		call := openFrom(t, id, bravoID, sealed)
		call.Body = []byte(`{"urls":["https://example.com/other"]}`)
		return mustSeal(t, id, bravoID, call)
	}
	for name, answer := range map[string]func(requestID string, sealed []byte) ProxyResult{
		"unsigned": func(string, []byte) ProxyResult { return removed },
		"signed by a stranger": func(id string, sealed []byte) ProxyResult {
			return SignResult(testSigning, &charlieKey, id, sealed, removed)
		},
		"signed by bravo for another call": func(id string, _ []byte) ProxyResult { return SignResult(testSigning, &bravoKey, id, another, removed) },
		"signed by bravo for the call altered on the way": func(id string, sealed []byte) ProxyResult {
			return SignResult(testSigning, &bravoKey, id, altered(id, sealed), ProxyResult{Status: http.StatusForbidden, Body: SignatureRefused})
		},
		"signed by bravo": func(id string, sealed []byte) ProxyResult {
			return SignResult(testSigning, &bravoKey, id, sealed, removed)
		},
	} {
		done := make(chan error, 1)
		go func() {
			_, _, err := alpha.Proxy(context.Background(), bravoID, http.MethodGet, "/api/tasks", nil)
			done <- err
		}()
		var req ProxyRequest
		if err := readFrame(t, bravo, TypeProxyRequest).Into(&req); err != nil {
			t.Fatal(err)
		}
		writeFrame(t, bravo, TypeProxyResponse, ProxyResponse{RequestID: req.RequestID, Sealed: sealResultFor(t, req.RequestID, answer(req.RequestID, req.Sealed))})
		err := <-done
		if want := name == "signed by bravo"; (err == nil) != want {
			t.Errorf("an answer %s: err %v, want it taken %v", name, err, want)
		}
	}
}

// A member of an app's version from before it moved to this package seals its
// announce under the same frame key but goes by an id of another shape.
func TestAnOlderMemberOnTheKeyIsNamedApart(t *testing.T) {
	addr, _ := relayOn(t, "127.0.0.1:0")
	const key = "shared-relay-test-key-0123456789ab"
	alpha := startClient(t, addr, key, alphaID, nil)
	waitFor(t, "alpha to connect", alpha.Connected)

	const older = "0123456789abcdef0123456789abcdef"
	conn := dialOlder(t, "ws://"+addr+connectPath, key, older, testFrameKey)
	waitFor(t, "alpha to name the older member", func() bool {
		o := alpha.Older()
		return len(o) == 1 && o[0].InstanceID == older && o[0].Name == "attic"
	})
	if len(alpha.Siblings()) != 0 {
		t.Fatalf("the older member is listed as a sibling: %+v", alpha.Siblings())
	}

	// A connection on the key whose announce does not open is somebody else.
	dialOlder(t, "ws://"+addr+connectPath, key, strings.Repeat("e", 32), []byte("0123456789abcdef0123456789abcdef"))
	_ = conn.CloseNow()
	waitFor(t, "alpha to see the older member go and name nobody else", func() bool { return len(alpha.Older()) == 0 })
}

// dialOlder connects the way an older app did: an id of its own shape and its
// name sealed under frameKey, without a proof.
func dialOlder(t *testing.T, url, key, id string, frameKey []byte) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsTimeout)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial %s as %s: %v", url, id, err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	readFrame(t, c, TypeChallenge)
	sealed, err := SealIdentity(frameKey, id, Identity{Name: "attic"})
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(t, c, TypeHello, Hello{Key: key, Announce: Announce{InstanceID: id, Sealed: sealed}})
	return c
}
