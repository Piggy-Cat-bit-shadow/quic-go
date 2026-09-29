package quic

import (
	"context"
	"sync"

	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/utils/ringbuffer"
	"github.com/sagernet/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue [][]byte
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}
	// sendClosed mirrors the closed channel for the SEND side, under sendMx. See drainSendQueue for
	// why the ordering between this flag and the drain is load-bearing.
	sendClosed bool

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
//
// On a non-nil return the frame was NOT queued, and the caller retains ownership of it -- including
// any payload ownership the frame carries. Add therefore never releases a frame it did not accept,
// which is what makes the owned-datagram contract hold when the connection closes while a caller is
// blocked here.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		// Checked before the length, and under the same lock the drain takes, so a caller that was
		// blocked when the queue closed cannot go on to claim the space the drain just freed.
		if h.sendClosed {
			h.sendMx.Unlock()
			return h.closeErr
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// DiscardFront removes the front frame and hands back its payload ownership, for the paths where a
// frame is dropped WITHOUT being serialized.
//
// # Why this is separate from Pop
//
// Pop only unlinks. For a frame that is about to be serialized that is correct, because the packet
// builder reads the payload later and releases it then. But the packetizer also drops frames it
// cannot fit, and those are never serialized -- so nothing else would ever release them. Routing
// every drop through this method keeps the release tied to the frame's actual fate.
func (h *datagramQueue) DiscardFront() {
	h.sendMx.Lock()
	// PopFront panics on an empty buffer, so the emptiness check is required rather than defensive.
	var frame *wire.DatagramFrame
	if !h.sendQueue.Empty() {
		frame = h.sendQueue.PopFront()
	}
	h.sendMx.Unlock()
	if frame != nil {
		frame.Release()
	}
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued && h.logger.Debug() {
		h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// CloseWithError shuts the queue down and RELEASES every frame still waiting to be sent.
//
// # Why the drain is not optional
//
// A frame in the send queue may hold ownership of a packet-sized buffer. Nothing will ever
// serialize a frame left here: the packetizer stops pulling once the connection is closed. Without
// this drain, closing a connection with a full queue would strand up to 32 payload buffers per
// session -- and because a session is re-established on every network change, that is a leak that
// grows with reconnects rather than a fixed cost.
//
// Each frame is released exactly once. Frames already serialized are not in the queue and were
// released by their own Append; a frame dropped concurrently by the packetizer is released by
// whichever of the two paths removes it first, because both take the queue lock and only one can
// pop a given frame.
func (h *datagramQueue) CloseWithError(e error) {
	h.drainSendQueue(e)
	close(h.closed)
}

// drainSendQueue marks the queue closed and releases every frame waiting to be sent.
//
// # Ordering matters here, and an earlier version of this patch got it wrong
//
// The queue is marked closed and drained BEFORE the closed channel is signalled, and that order is
// observable rather than cosmetic. Add re-checks the queue length after waking, so a caller blocked
// for space when the connection closes will:
//
//   - take the closed branch and keep its frame, if the queue was already marked closed and empty;
//   - otherwise loop, find the room the drain just freed, and ACCEPT a frame for a connection that
//     is already gone.
//
// The second behaviour is what this queue did before, and it reproduced every time: closing while a
// caller was blocked accepted the frame rather than rejecting it. With the copying API that frame is
// merely never sent. With the owned-datagram API its payload would be stranded, because the packet
// izer has stopped and the drain has already run -- nothing would ever release it.
//
// Marking closed under the same lock that empties the queue closes that window, because a woken
// caller re-checks both under that lock.
//
// # Why a separate flag
//
// A channel cannot serve as the flag: it can only be closed once, and Add must read the state
// without blocking. sendClosed is guarded by sendMx, the same lock the length check takes.
func (h *datagramQueue) drainSendQueue(e error) {
	h.sendMx.Lock()
	h.closeErr = e
	h.sendClosed = true
	// PopFront PANICS on an empty buffer and returns a value rather than a pointer, so every pop is
	// guarded by an emptiness check.
	pending := make([]*wire.DatagramFrame, 0, h.sendQueue.Len())
	for !h.sendQueue.Empty() {
		pending = append(pending, h.sendQueue.PopFront())
	}
	h.sendMx.Unlock()

	// Released outside the lock: a release callback may take locks of its own, and running it while
	// holding sendMx would give the buffer pool's lock an ordering dependency on the queue's.
	for _, frame := range pending {
		frame.Release()
	}
}
