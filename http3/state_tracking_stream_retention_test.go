package http3

import (
	"context"
	"testing"
)

// The per-stream DATAGRAM queue has the same retention shape as quic.datagramQueue: Receive
// advanced the slice without clearing the popped slot. See the datagramQueue test for the
// reasoning; this one pins the second call site.
func TestStateTrackingStreamClearsDeliveredPayloadSlot(t *testing.T) {
	stream := &stateTrackingStream{}
	stream.enqueueDatagram([]byte{0xC3})
	stream.enqueueDatagram([]byte{0xD4})

	backing := stream.queue[:cap(stream.queue)]

	first, err := stream.ReceiveDatagram(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0] != 0xC3 {
		t.Fatalf("first datagram = %v", first)
	}
	if backing[0] != nil {
		t.Fatal("the delivered datagram is still reachable through the stream queue's backing array")
	}

	second, err := stream.ReceiveDatagram(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0] != 0xD4 {
		t.Fatalf("second datagram = %v", second)
	}
}
