package quic

import (
	"errors"
	"net"

	"github.com/sagernet/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
	// SetSendFailureHandler sets the callback for a hard write error. The connection decides
	// whether that error ends it: the failing path may be one it is migrating away from.
	SetSendFailureHandler(func(error))
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
	// onSendFailure reports a hard write error to the connection, which decides whether it ends
	// the connection. The queue keeps running so that a path switch can still carry packets.
	onSendFailure func(error)
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) *sendQueue {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// SetSendFailureHandler sets the callback that receives a hard write error. The queue keeps
// running: whether such an error ends the connection is the connection's decision, because the
// failing path may be one it is migrating away from.
func (h *sendQueue) SetSendFailureHandler(handler func(error)) { h.onSendFailure = handler }

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
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
	return len(h.queue) == sendQueueCapacity
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
			if err := h.conn.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				var tooLarge *DatagramTooLargeError
				if !isSendMsgSizeErr(err) && !isNoBufferSpaceErr(err) && !errors.As(err, &tooLarge) {
					// A hard write error is a fact about this path, not necessarily about this
					// connection: the connection may be migrating to another path right now. Hand
					// it to the run loop, which owns that decision, and keep the queue usable so
					// the switch can still carry packets.
					e.buf.Release()
					select {
					case h.available <- struct{}{}:
					default:
					}
					if h.onSendFailure != nil {
						h.onSendFailure(err)
					}
					continue
				}
			}
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
