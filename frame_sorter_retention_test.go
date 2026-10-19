package quic

import (
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
)

// A small STREAM frame that arrived in a packet-sized pooled buffer must be right-sized before it
// is held across a gap.
//
// ParseStreamFrame hands every payload of at least MinStreamFrameBufferSize a buffer of
// MaxPacketBufferSize. Holding that buffer for a 128-byte frame is up to ~11x the bytes the frame
// needs, and the sorter can hold it for as long as the gap stays open.
func TestFrameSorterRightSizesOverProvisionedFrames(t *testing.T) {
	sorter := newFrameSorter()
	backing := make([]byte, protocol.MaxPacketBufferSize)
	data := backing[:protocol.MinStreamFrameBufferSize]
	for i := range data {
		data[i] = byte(i)
	}
	released := 0
	if err := sorter.Push(data, 0, func() { released++ }); err != nil {
		t.Fatal(err)
	}
	entry, ok := sorter.queue[0]
	if !ok {
		t.Fatal("the frame was not queued")
	}
	if cap(entry.Data) != len(entry.Data) {
		t.Fatalf("queued frame keeps cap %d for len %d", cap(entry.Data), len(entry.Data))
	}
	if released != 1 {
		t.Fatalf("the over-provisioned pool buffer must be returned exactly once, got %d", released)
	}
	for i := range data {
		if entry.Data[i] != data[i] {
			t.Fatalf("byte %d changed by the right-sizing copy", i)
		}
	}
}

// An ordinary MTU-sized frame must keep its pooled buffer: copying it would add an allocation on
// the normal path and save nothing.
func TestFrameSorterKeepsThePooledBufferForAFullSizeFrame(t *testing.T) {
	sorter := newFrameSorter()
	backing := make([]byte, protocol.MaxPacketBufferSize)
	data := backing[:protocol.MaxPacketBufferSize-52]
	released := 0
	if err := sorter.Push(data, 0, func() { released++ }); err != nil {
		t.Fatal(err)
	}
	entry, ok := sorter.queue[0]
	if !ok {
		t.Fatal("the frame was not queued")
	}
	if cap(entry.Data) != cap(backing) {
		t.Fatalf("a full-size frame must keep its pooled buffer, cap %d", cap(entry.Data))
	}
	if released != 0 {
		t.Fatal("a full-size frame must not be released early")
	}
}
