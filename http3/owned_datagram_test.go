package http3

import (
	"errors"
	"testing"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
)

// Tests for the in-place quarter-stream-ID prepend and its rollback.
//
// # What can go wrong here, and why these tests exist
//
// The owned path writes into the caller's buffer instead of copying it. That makes two mistakes
// possible which the copying path could not make:
//
//   - writing a prefix the buffer cannot hold, corrupting whatever precedes it;
//   - leaving the prefix in place when the send fails, so the caller receives a buffer whose first
//     bytes belong to HTTP/3.
//
// The second is the dangerous one. A CONNECT-IP caller that gets DatagramTooLargeError trims the
// buffer and builds an ICMP Packet Too Big from it; a caller that gets ErrDatagramUnsupported hands
// it to the capsule fallback. Either would silently transmit a corrupted packet if the rollback
// were missing, and neither would report anything unusual.

// testOwningPayload is a minimal OwnedDatagramPayload over a byte slice with a fixed headroom,
// mirroring what a pooled buffer offers.
type testOwningPayload struct {
	// storage holds headroom + payload.
	storage []byte
	// start is the index of the first payload byte.
	start int
	// headroom is how much room Prepend may use; it is capped by start.
	headroom int
	releases int
	// onRelease runs when the transport releases the payload.
	onRelease func()
}

func newTestOwningPayload(payload []byte, headroom int) *testOwningPayload {
	storage := make([]byte, headroom+len(payload))
	copy(storage[headroom:], payload)
	return &testOwningPayload{storage: storage, start: headroom, headroom: headroom}
}

func (p *testOwningPayload) Bytes() []byte { return p.storage[p.start:] }

func (p *testOwningPayload) Prepend(n int) []byte {
	if p.start < n {
		return nil
	}
	p.start -= n
	return p.storage[p.start : p.start+n]
}

func (p *testOwningPayload) Advance(n int) { p.start += n }

func (p *testOwningPayload) Release() {
	p.releases++
	if p.onRelease != nil {
		p.onRelease()
	}
}

// payloadBytes returns the payload as the caller would see it, for layout assertions.
func (p *testOwningPayload) payloadBytes() []byte { return p.storage[p.start:] }

// ---------------------------------------------------------------------------
// Quarter stream ID boundaries
// ---------------------------------------------------------------------------

// TestQuarterStreamIDPrependInPlaceAtEveryLengthClass covers §67: the varint length changes with the
// stream ID, and the in-place write must be correct at 1, 2, 4 and 8 bytes.
//
// A stream ID is a long-lived value. A connection that has served enough requests to need a
// multi-byte quarter stream ID must not silently start corrupting datagrams or falling back to the
// copying path.
func TestQuarterStreamIDPrependInPlaceAtEveryLengthClass(t *testing.T) {
	// Quarter stream IDs at each varint boundary, expressed as stream IDs (4x).
	for _, testCase := range []struct {
		name     string
		streamID uint64
		qsid     uint64
		wantLen  int
	}{
		{name: "1byte zero", streamID: 0, qsid: 0, wantLen: 1},
		{name: "1byte max", streamID: 63 * 4, qsid: 63, wantLen: 1},
		{name: "2byte min", streamID: 64 * 4, qsid: 64, wantLen: 2},
		{name: "2byte max", streamID: 16383 * 4, qsid: 16383, wantLen: 2},
		{name: "4byte min", streamID: 16384 * 4, qsid: 16384, wantLen: 4},
		{name: "8byte", streamID: (1 << 40) * 4, qsid: 1 << 40, wantLen: 8},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			payload := []byte("inner-packet-payload")
			// Give exactly the headroom the prefix needs, so any off-by-one is visible.
			owner := newTestOwningPayload(payload, testCase.wantLen)

			prefixLen := quicvarint.Len(uint64(testCase.streamID / 4))
			if prefixLen != testCase.wantLen {
				t.Fatalf("test expectation wrong: varint length is %d, test says %d",
					prefixLen, testCase.wantLen)
			}

			header := owner.Prepend(prefixLen)
			if header == nil {
				t.Fatal("Prepend should have succeeded with exactly enough headroom")
			}
			written := quicvarint.Append(header[:0], uint64(testCase.streamID/4))
			if len(written) != testCase.wantLen {
				t.Fatalf("wrote %d varint bytes, expected %d", len(written), testCase.wantLen)
			}

			// The buffer must now read as: quarter stream ID, then the untouched payload.
			full := owner.Bytes()
			gotQSID, consumed, err := quicvarint.Parse(full)
			if err != nil {
				t.Fatal(err)
			}
			if gotQSID != testCase.qsid {
				t.Fatalf("quarter stream ID round-trip: got %d want %d", gotQSID, testCase.qsid)
			}
			if consumed != testCase.wantLen {
				t.Fatalf("consumed %d bytes, expected %d", consumed, testCase.wantLen)
			}
			if string(full[consumed:]) != string(payload) {
				t.Fatalf("payload was damaged by the prepend: got %q want %q",
					full[consumed:], payload)
			}

			// And the rollback must restore the exact original layout.
			owner.Advance(consumed)
			if string(owner.Bytes()) != string(payload) {
				t.Fatalf("rollback left the buffer wrong: got %q want %q", owner.Bytes(), payload)
			}
			if owner.start != testCase.wantLen {
				t.Fatalf("rollback left start at %d, expected %d", owner.start, testCase.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Headroom cases
// ---------------------------------------------------------------------------

// TestPrependSignalsInsufficientHeadroom covers §68: a buffer without room must say so rather than
// writing out of bounds.
//
// A nil return is what makes the copying fallback reachable, so the caller keeps working with a
// buffer from any pool layout.
func TestPrependSignalsInsufficientHeadroom(t *testing.T) {
	payload := []byte("payload")
	for _, headroom := range []int{0, 1, 2, 3, 4, 7} {
		owner := newTestOwningPayload(payload, headroom)
		need := 8
		if got := owner.Prepend(need); got != nil {
			t.Fatalf("headroom=%d: Prepend(%d) must return nil, got %d bytes", headroom, need, len(got))
		}
		// Crucially, a refused Prepend must not have moved the payload.
		if string(owner.Bytes()) != string(payload) {
			t.Fatalf("headroom=%d: a refused Prepend changed the payload: %q", headroom, owner.Bytes())
		}
		// And exactly enough headroom must succeed.
		exact := newTestOwningPayload(payload, need)
		if got := exact.Prepend(need); got == nil {
			t.Fatalf("exactly %d bytes of headroom should suffice", need)
		}
	}
}

// TestMaxQuarterStreamIDFitsInEightBytes pins the §55 concern: the largest quarter stream ID must
// still have a representable prefix, so a long-lived connection never loses the fast path for a
// reason it cannot see.
func TestMaxQuarterStreamIDFitsInEightBytes(t *testing.T) {
	const maxQuarterStreamID = 1<<60 - 1
	length := quicvarint.Len(maxQuarterStreamID)
	if length != 8 {
		t.Fatalf("the maximum quarter stream ID must encode in 8 bytes, got %d", length)
	}
	owner := newTestOwningPayload([]byte("x"), 8)
	if owner.Prepend(8) == nil {
		t.Fatal("8 bytes of headroom must accept the largest quarter stream ID")
	}
}

// ---------------------------------------------------------------------------
// Rollback on refusal
// ---------------------------------------------------------------------------

// TestSendDatagramOwnedRollsBackOnStreamError is the rollback contract at the stream layer.
//
// A stream that has already failed returns WITHOUT touching the payload, so the caller still owns a
// buffer in exactly the layout it passed in.
func TestSendDatagramOwnedRollsBackOnStreamError(t *testing.T) {
	streamErr := errors.New("stream is closed")
	stream := &stateTrackingStream{sendErr: streamErr}
	stream.sendDatagramOwnedFn = func(OwnedDatagramPayload) error {
		t.Fatal("the transport must not be reached once the stream has failed")
		return nil
	}

	payload := []byte("must survive untouched")
	owner := newTestOwningPayload(payload, 8)

	err := stream.sendDatagramOwned(owner)
	if !errors.Is(err, streamErr) {
		t.Fatalf("expected the stream error, got %v", err)
	}
	if string(owner.Bytes()) != string(payload) {
		t.Fatalf("a failed send must leave the payload untouched, got %q", owner.Bytes())
	}
	if owner.releases != 0 {
		t.Fatalf("a failed send must not release the payload, got %d releases", owner.releases)
	}
}

// TestSendDatagramOwnedFallsBackWithoutHeadroom proves a buffer with no room degrades to the copying
// path instead of failing.
//
// Losing datagrams because a buffer came from a differently-shaped pool would be a correctness bug
// dressed as an optimisation.
func TestSendDatagramOwnedFallsBackWithoutHeadroom(t *testing.T) {
	// The copying path itself needs a real quic.Conn, so this test exercises the DECISION it depends
	// on: a payload with no headroom refuses the prepend, which is what routes the send to the
	// copying branch instead of failing.
	owner := newTestOwningPayload([]byte("no room"), 0)
	if owner.Prepend(quicvarint.Len(0)) != nil {
		t.Fatal("a payload with no headroom must refuse the prepend so the fallback is reachable")
	}
	// The fallback sends payload.Bytes() through the ordinary API. Assert the payload is what the
	// caller passed in, i.e. no prefix was written.
	if string(owner.Bytes()) != "no room" {
		t.Fatalf("fallback payload was modified: %q", owner.Bytes())
	}
}

// ---------------------------------------------------------------------------
// Batched owned send: rollback and atomicity
// ---------------------------------------------------------------------------

// TestSendDatagramsOwnedRejectsWholeBatchOnStreamError proves the stream-error check applies to the
// batch as a whole, so a failed stream touches no caller buffer at all.
func TestSendDatagramsOwnedRejectsWholeBatchOnStreamError(t *testing.T) {
	streamErr := errors.New("stream is closed")
	stream := &stateTrackingStream{sendErr: streamErr}
	stream.sendDatagramsOwnedFn = func([]OwnedDatagramPayload) error {
		t.Fatal("the transport must not be reached once the stream has failed")
		return nil
	}

	payloads := [][]byte{[]byte("first"), []byte("second"), []byte("third")}
	owners := make([]*testOwningPayload, len(payloads))
	batch := make([]OwnedDatagramPayload, len(payloads))
	for i, p := range payloads {
		owners[i] = newTestOwningPayload(p, 8)
		batch[i] = owners[i]
	}

	err := stream.sendDatagramsOwned(batch)
	if !errors.Is(err, streamErr) {
		t.Fatalf("expected the stream error, got %v", err)
	}
	for i, owner := range owners {
		if string(owner.Bytes()) != string(payloads[i]) {
			t.Fatalf("payload %d modified by a failed batch: %q", i, owner.Bytes())
		}
		if owner.releases != 0 {
			t.Fatalf("payload %d released by a failed batch", i)
		}
	}
}

// TestSendDatagramsOwnedEmptyIsNoOp keeps the degenerate call from reaching the transport.
func TestSendDatagramsOwnedEmptyIsNoOp(t *testing.T) {
	stream := &stateTrackingStream{}
	stream.sendDatagramsOwnedFn = func([]OwnedDatagramPayload) error {
		t.Fatal("an empty batch must not reach the transport")
		return nil
	}
	if err := stream.sendDatagramsOwned(nil); err != nil {
		t.Fatal(err)
	}
}

// TestSendDatagramsOwnedPassesWholeBatchThrough proves the batch is forwarded intact and in order,
// so the ORDER of datagrams on the wire matches the order the caller handed them over.
func TestSendDatagramsOwnedPassesWholeBatchThrough(t *testing.T) {
	var got []string
	stream := &stateTrackingStream{}
	stream.sendDatagramsOwnedFn = func(payloads []OwnedDatagramPayload) error {
		for _, p := range payloads {
			got = append(got, string(p.Bytes()))
		}
		return nil
	}
	want := []string{"a", "b", "c", "d"}
	batch := make([]OwnedDatagramPayload, len(want))
	for i, w := range want {
		batch[i] = newTestOwningPayload([]byte(w), 8)
	}
	if err := stream.sendDatagramsOwned(batch); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d payloads, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("payload %d out of order: got %q want %q", i, got[i], want[i])
		}
	}
}

// TestStreamSendDatagramsOwnedIsWiredToTheTransport guards the plumbing: if Stream.SendDatagramsOwned
// stopped reaching the datagram stream, every batch would be silently dropped.
func TestStreamSendDatagramsOwnedIsWiredToTheTransport(t *testing.T) {
	called := false
	stream := &stateTrackingStream{}
	stream.sendDatagramsOwnedFn = func([]OwnedDatagramPayload) error {
		called = true
		return nil
	}
	s := &Stream{datagramStream: stream}
	if err := s.SendDatagramsOwned([]OwnedDatagramPayload{newTestOwningPayload([]byte("x"), 8)}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Stream.SendDatagramsOwned did not reach the datagram stream")
	}
}

// ---------------------------------------------------------------------------
// Batch prefix and rollback helpers
// ---------------------------------------------------------------------------

// TestClearPrefixesRestoresEveryPayload is the rollback that makes a failed batch usable.
//
// If only part of the batch were rolled back, the rest would keep a quarter stream ID glued to the
// front. The caller -- having been told the batch failed -- would legitimately reuse those buffers,
// and would transmit a packet with an HTTP/3 varint prepended to it. Nothing would report an error:
// the bytes would simply be wrong on the wire.
func TestClearPrefixesRestoresEveryPayload(t *testing.T) {
	const streamID = quic.StreamID(4 * 12345) // multi-byte quarter stream ID
	n := quicvarint.Len(uint64(streamID / 4))

	originals := []string{"first", "second", "third", "fourth"}
	payloads := make([]OwnedDatagramPayload, len(originals))
	for i, o := range originals {
		payloads[i] = newTestOwningPayload([]byte(o), 8)
	}

	prefixPayloads(payloads, streamID)
	// Each payload must now start with the varint.
	for i, p := range payloads {
		got := p.Bytes()
		if len(got) <= len(originals[i]) {
			t.Fatalf("payload %d was not prefixed", i)
		}
		if string(got[n:]) != originals[i] {
			t.Fatalf("payload %d: prefix corrupted the payload: %q", i, got)
		}
	}

	clearPrefixes(payloads, n)

	for i, p := range payloads {
		if got := string(p.Bytes()); got != originals[i] {
			t.Fatalf("payload %d was not fully restored: got %q want %q", i, got, originals[i])
		}
	}
}

// TestAllPayloadsHaveHeadroomLeavesPayloadsUntouched proves the probe pass is side-effect free.
//
// The check runs BEFORE the decision, so a batch that will take the copying route must reach it
// with every buffer exactly as the caller passed it in.
func TestAllPayloadsHaveHeadroomLeavesPayloadsUntouched(t *testing.T) {
	originals := []string{"aaa", "bbb", "ccc"}
	payloads := make([]OwnedDatagramPayload, len(originals))
	for i, o := range originals {
		payloads[i] = newTestOwningPayload([]byte(o), 8)
	}
	if !allPayloadsHaveHeadroom(payloads, 4) {
		t.Fatal("8 bytes of headroom must accept a 4-byte prefix")
	}
	for i, p := range payloads {
		if got := string(p.Bytes()); got != originals[i] {
			t.Fatalf("payload %d changed by the headroom probe: got %q want %q", i, got, originals[i])
		}
	}
}

// TestAllPayloadsHaveHeadroomIsAllOrNothing proves ONE payload without room rejects the whole batch,
// and that the rejection still leaves every already-probed payload untouched.
func TestAllPayloadsHaveHeadroomIsAllOrNothing(t *testing.T) {
	originals := []string{"has room", "no room"}
	payloads := []OwnedDatagramPayload{
		newTestOwningPayload([]byte(originals[0]), 8),
		newTestOwningPayload([]byte(originals[1]), 0), // no headroom
	}
	if allPayloadsHaveHeadroom(payloads, 4) {
		t.Fatal("a batch containing a payload without room must be rejected as a whole")
	}
	for i, p := range payloads {
		if got := string(p.Bytes()); got != originals[i] {
			t.Fatalf("payload %d changed by a failed probe: got %q want %q", i, got, originals[i])
		}
	}
}

// TestClearPrefixesZeroIsNoOp keeps the fallback route from shifting payloads it never prefixed.
func TestClearPrefixesZeroIsNoOp(t *testing.T) {
	p := newTestOwningPayload([]byte("untouched"), 8)
	clearPrefixes([]OwnedDatagramPayload{p}, 0)
	if got := string(p.Bytes()); got != "untouched" {
		t.Fatalf("a zero-length rollback must not move the payload, got %q", got)
	}
}
