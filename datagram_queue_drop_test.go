package quic

import (
	"testing"

	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

// A full receive queue must count the frames it drops, so a lossy tunnel can be told apart from
// an idle one without per-packet logging.
func TestDatagramQueueCountsReceiveDrops(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}
	if got := queue.DroppedDatagrams(); got != 0 {
		t.Fatalf("a queue that is exactly full has dropped nothing, got %d", got)
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{0xFF}})
	if got := queue.DroppedDatagrams(); got != 1 {
		t.Fatalf("the overflowing frame must be counted, got %d", got)
	}
	if len(queue.rcvQueue) != maxDatagramRcvQueueLen {
		t.Fatalf("the queue must stay at its bound, len %d", len(queue.rcvQueue))
	}
}
