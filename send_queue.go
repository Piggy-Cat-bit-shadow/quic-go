package quic

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue         chan queueEntry
	closeCalled   chan struct{} // runStopped when Close() is called
	runStopped    chan struct{} // runStopped when the run loop returns
	available     chan struct{}
	conn          sendConn
	highWater     atomic.Uint64
	hardBlocks    atomic.Uint64
	blockedAt     atomic.Int64
	hardBlockNS   atomic.Uint64
	enqueued      atomic.Uint64
	sent          atomic.Uint64
	enqueuedBytes atomic.Uint64
	sentBytes     atomic.Uint64
	writes        atomic.Uint64
	gsoBytes      atomic.Uint64
}

type sendQueueRuntimeStats struct {
	Depth                 uint64
	HighWater             uint64
	HardBlocks            uint64
	HardBlockedDurationNS uint64
	Enqueued              uint64
	Sent                  uint64
	EnqueuedBytes         uint64
	SentBytes             uint64
	Writes                uint64
	GSOBytes              uint64
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
		h.enqueued.Add(1)
		h.enqueuedBytes.Add(uint64(len(p.Data)))
		updateAtomicMax(&h.highWater, uint64(len(h.queue)))
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	blocked := len(h.queue) == sendQueueCapacity
	if blocked && h.blockedAt.CompareAndSwap(0, time.Now().UnixNano()) {
		h.hardBlocks.Add(1)
	} else if !blocked {
		h.clearBlocked()
	}
	return blocked
}

func (h *sendQueue) clearBlocked() {
	if started := h.blockedAt.Swap(0); started != 0 {
		h.hardBlockNS.Add(uint64(max(0, time.Now().UnixNano()-started)))
	}
}

func (h *sendQueue) runtimeStats() sendQueueRuntimeStats {
	blocked := h.blockedAt.Load()
	d := h.hardBlockNS.Load()
	if blocked != 0 {
		d += uint64(max(0, time.Now().UnixNano()-blocked))
	}
	return sendQueueRuntimeStats{Depth: uint64(len(h.queue)), HighWater: h.highWater.Load(), HardBlocks: h.hardBlocks.Load(), HardBlockedDurationNS: d, Enqueued: h.enqueued.Load(), Sent: h.sent.Load(), EnqueuedBytes: h.enqueuedBytes.Load(), SentBytes: h.sentBytes.Load(), Writes: h.writes.Load(), GSOBytes: h.gsoBytes.Load()}
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			h.clearBlocked()
			h.writes.Add(1)
			if e.gsoSize > 0 {
				h.gsoBytes.Add(uint64(len(e.buf.Data)))
			}
			if err := h.conn.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				if !isSendMsgSizeErr(err) {
					return err
				}
			}
			h.sent.Add(1)
			h.sentBytes.Add(uint64(len(e.buf.Data)))
			e.buf.Release()
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
