package relay

import (
	"bytes"
	"errors"
	"fmt"
)

// maxParts bounds the parts of one answer, which together are no larger than
// a frame may be.
const maxParts = readLimit / partBytes

// waiting is a call waiting for its answer, which may come in parts.
type waiting struct {
	// answer takes the whole answer once.
	answer chan ProxyResponse
	// moved hears of every part that came in before the last.
	moved chan struct{}
	parts [][]byte
	of    int
	size  int
}

func newWaiting() *waiting {
	return &waiting{answer: make(chan ProxyResponse, 1), moved: make(chan struct{}, 1)}
}

// take adds r to the answer and reports whether the answer is whole. A part
// that is missing, comes twice or names another count of parts is an error,
// and so is an answer larger than a frame.
func (w *waiting) take(r ProxyResponse) (ProxyResponse, bool, error) {
	if r.Parts == 0 {
		return r, true, nil
	}
	switch {
	case r.Parts > maxParts:
		return ProxyResponse{}, false, fmt.Errorf("the answer comes in %d parts, more than it may", r.Parts)
	case w.of != 0 && r.Parts != w.of:
		return ProxyResponse{}, false, errors.New("the parts of the answer disagree on their count")
	case r.Part < len(w.parts):
		return ProxyResponse{}, false, fmt.Errorf("part %d of the answer came twice", r.Part)
	case r.Part > len(w.parts):
		return ProxyResponse{}, false, fmt.Errorf("part %d of the answer is missing", len(w.parts))
	}
	w.of = r.Parts
	w.parts = append(w.parts, r.Sealed)
	w.size += len(r.Sealed)
	if w.size > readLimit {
		return ProxyResponse{}, false, errors.New("the answer in parts is larger than a frame may be")
	}
	if len(w.parts) < w.of {
		return ProxyResponse{}, false, nil
	}
	return ProxyResponse{RequestID: r.RequestID, Sealed: bytes.Join(w.parts, nil)}, true, nil
}

// split cuts a sealed answer into the frames it goes out in: one frame unless
// the caller takes parts and the answer is larger than one part.
func split(resp ProxyResponse, framing int) []ProxyResponse {
	if framing < framingParts || len(resp.Sealed) <= partBytes {
		return []ProxyResponse{resp}
	}
	sealed := resp.Sealed
	n := (len(sealed) + partBytes - 1) / partBytes
	out := make([]ProxyResponse, 0, n)
	for i := range n {
		part := resp
		part.Sealed = sealed[i*partBytes : min((i+1)*partBytes, len(sealed))]
		part.Part, part.Parts = i, n
		out = append(out, part)
	}
	return out
}
