package quic

import (
	"context"
	"testing"

	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

// A delivered datagram must not stay reachable through the queue's backing array.
//
// Receive used to advance the slice without clearing the popped slot. The slice header moves but
// the array object still holds the pointer, and the GC scans the whole array, so every delivered
// payload lived until the queue was reallocated. Bounded (128 entries) but it makes a drained
// connection's heap indistinguishable from a full one.
func TestDatagramQueueClearsDeliveredPayloadSlot(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{0xA1}})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{0xB2}})

	// Keep the original array: after the reslice, the delivered slot is before queue.rcvQueue[0]
	// and only reachable through this view.
	backing := queue.rcvQueue[:cap(queue.rcvQueue)]

	first, err := queue.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0] != 0xA1 {
		t.Fatalf("first datagram = %v", first)
	}
	if backing[0] != nil {
		t.Fatal("the delivered datagram is still reachable through the queue's backing array")
	}

	second, err := queue.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0] != 0xB2 {
		t.Fatalf("second datagram = %v", second)
	}
}
