package quic

import (
	"errors"
	"sync"
	"testing"

	"github.com/sagernet/quic-go/internal/wire"
)

// Tests for the ownership contract of SendDatagramOwned and the DATAGRAM frame release point.
//
// # Why these exist as their own file
//
// This module ships with almost no upstream tests, so the owned-datagram path has no existing
// safety net. The contract it implements is the kind that fails silently: a buffer released one
// step too early produces corrupted packets on the wire rather than a crash, and a buffer released
// one step too late leaks. Both are invisible without a test that counts releases and poisons the
// memory.

// countingOwner records how many times it was released, and optionally notes whether the payload
// looked like it had already been poisoned.
type countingOwner struct {
	mu       sync.Mutex
	releases int
	payload  []byte
	// poison fills the payload on release, so a later reader can tell that a release happened
	// before the bytes were consumed.
	poison byte
	// snapshot is taken at release time, capturing what the payload held when release ran.
	snapshot []byte
}

func (o *countingOwner) Release() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.releases++
	if o.payload != nil {
		o.snapshot = append([]byte(nil), o.payload...)
	}
	if o.poison != 0 {
		for i := range o.payload {
			o.payload[i] = o.poison
		}
	}
}

func (o *countingOwner) releaseCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.releases
}

// ---------------------------------------------------------------------------
// The release point
// ---------------------------------------------------------------------------

// TestOwnedDatagramReleasesAfterSerialization is the core proof that the release happens only after
// the payload is safely inside the packet buffer.
//
// The owner POISONS its payload when released. If the release ran before the frame was serialized,
// the serialized bytes would come out as poison and this test would see the corruption. Because the
// release runs after the copy, the serialized bytes are the real payload and the poisoned original
// is never read again.
func TestOwnedDatagramReleasesAfterSerialization(t *testing.T) {
	payload := []byte("the actual datagram payload")
	// The expected serialization is captured BEFORE the frame is built, because the owner poisons
	// the very slice it was handed. Building `want` afterwards would compare the poisoned bytes
	// against themselves and the test would prove nothing.
	want := append([]byte{0x31, byte(len(payload))}, payload...)
	owner := &countingOwner{payload: payload, poison: 0xAA}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: payload}
	frame.SetOwner(owner)

	if owner.releaseCount() != 0 {
		t.Fatal("release ran before the frame was serialized")
	}

	serialized, err := frame.Append(nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	if owner.releaseCount() != 1 {
		t.Fatalf("expected exactly one release after serialization, got %d", owner.releaseCount())
	}
	// The serialized bytes must be the REAL payload, not the poison. This is what proves the copy
	// happened before the release: if the release ran first, the poison would have overwritten the
	// bytes before Append read them.
	if string(serialized) != string(want) {
		t.Fatalf("serialized bytes were corrupted by an early release:\n got %q\nwant %q",
			serialized, want)
	}
	// The source really was poisoned, so the comparison above is not vacuous.
	if owner.payload[0] != 0xAA {
		t.Fatal("the owner did not poison its payload, so this test cannot detect an early release")
	}
	// The owner captured what it saw at release time. Compare against the EXPECTED bytes captured
	// before the frame was built, not against `payload` -- the owner poisons that slice, so it no
	// longer holds the original by the time this runs.
	expectedPayload := want[2:]
	if owner.snapshot == nil || string(owner.snapshot) != string(expectedPayload) {
		t.Fatalf("release observed a payload that was not the original: %q", owner.snapshot)
	}
}

// TestOwnedDatagramReleaseIsIdempotent proves a second release cannot double-free.
//
// The frame outlives its serialization -- it is carried in the packet's frame list for qlog and
// ack-handler bookkeeping -- so a future change that added another release path must not be able to
// turn a duplicate call into memory corruption.
func TestOwnedDatagramReleaseIsIdempotent(t *testing.T) {
	owner := &countingOwner{payload: make([]byte, 8)}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
	frame.SetOwner(owner)

	frame.Release()
	frame.Release()
	frame.Release()

	if owner.releaseCount() != 1 {
		t.Fatalf("release must run exactly once however often Release is called, got %d",
			owner.releaseCount())
	}
}

// TestCopyingDatagramHasNoOwner proves the existing API is untouched.
//
// A frame built by the copying path carries no ownership handle, so Release must be a harmless
// no-op rather than a nil dereference.
func TestCopyingDatagramHasNoOwner(t *testing.T) {
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: []byte("copied")}
	frame.Release()
	serialized, err := frame.Append(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) == 0 {
		t.Fatal("serialization must still work for a frame with no owner")
	}
	// Appending again is fine: the payload is still there, because nothing released it.
	if _, err = frame.Append(nil, 0); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Queue close drain
// ---------------------------------------------------------------------------

// TestQueueCloseReleasesEveryQueuedFrame is the §14 requirement.
//
// A frame left in the send queue when the connection closes will never be serialized, so nothing
// else will ever release it. With a 32-entry queue and a session re-established on every network
// change, a missing drain is a leak that grows with reconnects.
func TestQueueCloseReleasesEveryQueuedFrame(t *testing.T) {
	queue := newDatagramQueue(func() {}, nil)

	const queued = 8
	owners := make([]*countingOwner, 0, queued)
	for range queued {
		owner := &countingOwner{payload: make([]byte, 64)}
		owners = append(owners, owner)
		frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
		frame.SetOwner(owner)
		if err := queue.Add(frame); err != nil {
			t.Fatal(err)
		}
	}

	for i, owner := range owners {
		if owner.releaseCount() != 0 {
			t.Fatalf("frame %d was released while still queued", i)
		}
	}

	queue.CloseWithError(errors.New("test close"))

	for i, owner := range owners {
		if owner.releaseCount() != 1 {
			t.Fatalf("frame %d: expected exactly one release on close, got %d", i, owner.releaseCount())
		}
	}
}

// TestQueueCloseWithEmptyQueueIsSafe covers the ordinary case, so the drain cannot be the thing that
// breaks a normal shutdown.
func TestQueueCloseWithEmptyQueueIsSafe(t *testing.T) {
	queue := newDatagramQueue(func() {}, nil)
	queue.CloseWithError(errors.New("nothing queued"))
}

// TestQueueAddAfterCloseAlwaysRejects proves a closed queue never accepts another frame.
//
// # This was a real bug, caught by these tests
//
// The queue originally consulted its closed channel only while BLOCKED, and CloseWithError drained
// the queue AFTER signalling. That left a window: a caller blocked for space would wake, re-check the
// length, find the room the drain had just freed, and accept a frame for a connection that was
// already gone.
//
// It reproduced every single time, not intermittently. With the copying API the consequence was
// mild -- a frame that is never sent. With the owned-datagram API it is a leak: the packetizer has
// stopped and the drain has already run, so nothing would ever release that payload.
//
// The fix marks the queue closed and drains it under the same lock, so a woken caller re-checks both
// together and takes the closed branch.
func TestQueueAddAfterCloseAlwaysRejects(t *testing.T) {
	// The empty-queue case first: space IS available, so only the closed flag can reject it.
	queue := newDatagramQueue(func() {}, nil)
	queue.CloseWithError(errors.New("closed"))

	owner := &countingOwner{payload: []byte("must be rejected")}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
	frame.SetOwner(owner)

	if err := queue.Add(frame); err == nil {
		t.Fatal("a closed queue must reject even when it has room")
	}
	if owner.releaseCount() != 0 {
		t.Fatalf("a rejected frame must stay with its caller, got %d releases", owner.releaseCount())
	}
	if string(frame.Data) != "must be rejected" {
		t.Fatalf("a rejected frame's payload was modified: %q", frame.Data)
	}
}

// TestQueueAddBlockedOnClosedQueueRejects proves the OTHER half: a caller blocked for space when the
// connection closes is rejected and keeps its buffer.
func TestQueueAddBlockedOnClosedQueueRejects(t *testing.T) {
	queue := newDatagramQueue(func() {}, nil)
	for range maxDatagramSendQueueLen {
		frame := &wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, 8)}
		if err := queue.Add(frame); err != nil {
			t.Fatal(err)
		}
	}

	owner := &countingOwner{payload: []byte("caller keeps this")}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
	frame.SetOwner(owner)

	blocked := make(chan error, 1)
	go func() { blocked <- queue.Add(frame) }()
	queue.CloseWithError(errors.New("closed under load"))

	if err := <-blocked; err == nil {
		t.Fatal("a blocked Add must report the close rather than accepting the frame")
	}
	if owner.releaseCount() != 0 {
		t.Fatalf("a REJECTED frame must stay with its caller, got %d releases", owner.releaseCount())
	}
	if string(frame.Data) != "caller keeps this" {
		t.Fatalf("a rejected frame's payload was modified: %q", frame.Data)
	}
}

// ---------------------------------------------------------------------------
// Discard paths
// ---------------------------------------------------------------------------

// TestDiscardFrontReleasesWithoutSerializing covers the packetizer's drop paths.
//
// A frame the packetizer cannot fit is removed from the queue and never serialized, so the release
// in Append never runs for it. Without DiscardFront that payload would be stranded in the pool.
func TestDiscardFrontReleasesWithoutSerializing(t *testing.T) {
	queue := newDatagramQueue(func() {}, nil)
	owner := &countingOwner{payload: make([]byte, 32)}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
	frame.SetOwner(owner)
	if err := queue.Add(frame); err != nil {
		t.Fatal(err)
	}

	if queue.Peek() == nil {
		t.Fatal("the frame should be queued")
	}
	queue.DiscardFront()

	if owner.releaseCount() != 1 {
		t.Fatalf("a discarded frame must be released exactly once, got %d", owner.releaseCount())
	}
	if queue.Peek() != nil {
		t.Fatal("the discarded frame should be gone from the queue")
	}
}

// TestPopDoesNotRelease proves the two paths are genuinely different, which is the whole reason
// DiscardFront exists.
//
// Pop queues a frame for serialization; its payload must still be readable afterwards, because the
// packet builder has not run yet.
func TestPopDoesNotRelease(t *testing.T) {
	queue := newDatagramQueue(func() {}, nil)
	owner := &countingOwner{payload: []byte("still needed")}
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
	frame.SetOwner(owner)
	if err := queue.Add(frame); err != nil {
		t.Fatal(err)
	}

	queue.Pop()

	if owner.releaseCount() != 0 {
		t.Fatalf("Pop must not release: the packet builder has not read the payload yet, got %d",
			owner.releaseCount())
	}
	// The payload must still be intact for the packet builder.
	serialized, err := frame.Append(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(serialized[len(serialized)-len("still needed"):]) != "still needed" {
		t.Fatal("the payload was damaged between Pop and serialization")
	}
	if owner.releaseCount() != 1 {
		t.Fatalf("serialization should have released exactly once, got %d", owner.releaseCount())
	}
}

// ---------------------------------------------------------------------------
// Queue-full and concurrent close
// ---------------------------------------------------------------------------

// TestQueueFullThenCloseLeavesNoOwnerStranded drives the §62 scenario: a caller blocked in Add
// because the queue is full, while the connection closes underneath it.
//
// Every frame the queue ACCEPTED must be released by the queue; the one it rejected must remain the
// caller's. No frame may be released twice and none may be left unreleased.
func TestQueueFullThenCloseLeavesNoOwnerStranded(t *testing.T) {
	queue := newDatagramQueue(func() {}, nil)

	accepted := make([]*countingOwner, 0, maxDatagramSendQueueLen)
	for range maxDatagramSendQueueLen {
		owner := &countingOwner{payload: make([]byte, 8)}
		accepted = append(accepted, owner)
		frame := &wire.DatagramFrame{DataLenPresent: true, Data: owner.payload}
		frame.SetOwner(owner)
		if err := queue.Add(frame); err != nil {
			t.Fatal(err)
		}
	}

	// This one blocks: the queue is at its limit.
	rejected := &countingOwner{payload: make([]byte, 8)}
	rejectedFrame := &wire.DatagramFrame{DataLenPresent: true, Data: rejected.payload}
	rejectedFrame.SetOwner(rejected)
	blocked := make(chan error, 1)
	go func() { blocked <- queue.Add(rejectedFrame) }()

	// Close while the caller is waiting.
	queue.CloseWithError(errors.New("closed under load"))

	if err := <-blocked; err == nil {
		t.Fatal("Add must report the close rather than accepting the frame")
	}

	for i, owner := range accepted {
		if count := owner.releaseCount(); count != 1 {
			t.Fatalf("accepted frame %d: expected exactly one release, got %d", i, count)
		}
	}
	if count := rejected.releaseCount(); count != 0 {
		t.Fatalf("the REJECTED frame must stay with its caller, got %d releases", count)
	}
}
