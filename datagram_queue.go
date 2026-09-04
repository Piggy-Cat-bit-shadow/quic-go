package quic

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/metacubex/quic-go/internal/utils"
	"github.com/metacubex/quic-go/internal/utils/ringbuffer"
	"github.com/metacubex/quic-go/internal/wire"
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
	rcvQueue []*DatagramBuffer
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

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
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
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

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	var queued bool
	b := &DatagramBuffer{Data: f.Data, owner: f.DataOwner}
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		// DatagramFrame.Data is an owned parser allocation. Transfer that
		// ownership into the receive queue; the parser has already detached it
		// from the decrypted packet buffer.
		h.rcvQueue = append(h.rcvQueue, b)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued {
		b.Release()
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
	}
}

type DatagramBuffer struct {
	Data     []byte
	owner    interface{ Release() }
	released atomic.Bool
}

func (b *DatagramBuffer) Release() {
	if b != nil && b.released.CompareAndSwap(false, true) && b.owner != nil {
		b.owner.Release()
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	b, err := h.ReceiveBuffer(ctx)
	if err != nil {
		return nil, err
	}
	data := append([]byte(nil), b.Data...)
	b.Release()
	return data, nil
}

func (h *datagramQueue) ReceiveBuffer(ctx context.Context) (*DatagramBuffer, error) {
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

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	h.rcvMx.Lock()
	for _, b := range h.rcvQueue {
		b.Release()
	}
	h.rcvQueue = nil
	h.rcvMx.Unlock()
	close(h.closed)
}
