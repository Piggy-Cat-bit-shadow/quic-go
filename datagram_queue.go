package quic

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go/internal/utils"
	"github.com/metacubex/quic-go/internal/utils/ringbuffer"
	"github.com/metacubex/quic-go/internal/wire"
)

const (
	// MASQUE can feed a QUIC connection much faster than the pacer can emit
	// packets on a high-RTT WAN. A 32-frame send queue turns normal pacing
	// bursts into application-level backpressure almost immediately. Keep the
	// queue bounded, but large enough to absorb a useful WAN burst.
	maxDatagramSendQueueLen    = 512
	maxDatagramRcvQueueLen     = 256
	maxRetainedDatagramBuffers = 64
)

type datagramRetentionBudget struct {
	inFlight       atomic.Int32
	highWater      atomic.Int32
	fallbackCopies atomic.Int64
}

func (b *datagramRetentionBudget) tryAcquire() bool {
	for {
		n := b.inFlight.Load()
		if n >= maxRetainedDatagramBuffers {
			return false
		}
		if b.inFlight.CompareAndSwap(n, n+1) {
			for {
				high := b.highWater.Load()
				if n+1 <= high || b.highWater.CompareAndSwap(high, n+1) {
					break
				}
			}
			return true
		}
	}
}

func (b *datagramRetentionBudget) release() {
	if n := b.inFlight.Add(-1); n < 0 {
		panic("negative datagram retention budget")
	}
}

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue ringbuffer.RingBuffer[*DatagramBuffer]
	rcvd     chan struct{} // used to notify Receive that a new datagram was received
	retained *datagramRetentionBudget

	closeErr error
	closed   chan struct{}

	hasData func()

	logger        utils.Logger
	sendHighWater atomic.Uint64
	sendBlocked   atomic.Uint64
	sendBlockedNS atomic.Uint64
	receiveDrops  atomic.Uint64
}

type datagramQueueRuntimeStats struct {
	SendDepth, SendHighWater, SendBlocked uint64
	SendBlockedDurationNS                 uint64
	ReceiveDepth, ReceiveDrops            uint64
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	q := &datagramQueue{
		hasData:  hasData,
		rcvd:     make(chan struct{}, 1),
		sent:     make(chan struct{}, 1),
		closed:   make(chan struct{}),
		retained: new(datagramRetentionBudget),
		logger:   logger,
	}
	q.sendQueue.Init(maxDatagramSendQueueLen)
	q.rcvQueue.Init(maxDatagramRcvQueueLen)
	return q
}

// Add queues a new DATAGRAM frame for sending.
// Up to maxDatagramSendQueueLen DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		select {
		case <-h.closed:
			err := h.closeErr
			h.sendMx.Unlock()
			return err
		default:
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			updateAtomicMax(&h.sendHighWater, uint64(h.sendQueue.Len()))
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		blockedAt := time.Now()
		h.sendBlocked.Add(1)
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
		h.sendBlockedNS.Add(uint64(time.Since(blockedAt)))
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

// Drop removes the front frame without giving the packet packer ownership.
// This is used for frames that won't be serialized.
func (h *datagramQueue) Drop() {
	h.sendMx.Lock()
	f := h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
	h.sendMx.Unlock()
	if f != nil {
		f.ReleaseSendOwner()
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	owner := f.TakeDataOwner()
	h.rcvMx.Lock()
	if h.rcvQueue.Len() >= maxDatagramRcvQueueLen {
		h.receiveDrops.Add(1)
		h.rcvMx.Unlock()
		if owner != nil {
			owner.Release()
		}
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
		return
	}

	var budget *datagramRetentionBudget
	if owner != nil {
		if h.retained.tryAcquire() {
			budget = h.retained
		} else {
			// Copy before releasing the packet-buffer owner. The compact copy is
			// intentionally not backed by either transport buffer pool.
			f.Data = append([]byte(nil), f.Data...)
			owner.Release()
			owner = nil
			h.retained.fallbackCopies.Add(1)
		}
	}
	b := &DatagramBuffer{Data: f.Data, owner: owner, budget: budget}
	h.rcvQueue.PushBack(b)
	select {
	case h.rcvd <- struct{}{}:
	default:
	}
	h.rcvMx.Unlock()
}

func (h *datagramQueue) runtimeStats() datagramQueueRuntimeStats {
	h.sendMx.Lock()
	sendDepth := uint64(h.sendQueue.Len())
	h.sendMx.Unlock()
	h.rcvMx.Lock()
	receiveDepth := uint64(h.rcvQueue.Len())
	h.rcvMx.Unlock()
	return datagramQueueRuntimeStats{
		SendDepth: sendDepth, SendHighWater: h.sendHighWater.Load(),
		SendBlocked: h.sendBlocked.Load(), SendBlockedDurationNS: h.sendBlockedNS.Load(),
		ReceiveDepth: receiveDepth, ReceiveDrops: h.receiveDrops.Load(),
	}
}

type DatagramBuffer struct {
	Data     []byte
	owner    interface{ Release() }
	budget   *datagramRetentionBudget
	released atomic.Bool
}

func (b *DatagramBuffer) Release() {
	if b == nil || !b.released.CompareAndSwap(false, true) {
		return
	}
	owner := b.owner
	budget := b.budget
	b.owner = nil
	b.budget = nil
	b.Data = nil
	if owner != nil {
		owner.Release()
	}
	if budget != nil {
		budget.release()
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
		if !h.rcvQueue.Empty() {
			data := h.rcvQueue.PopFront()
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
	h.sendMx.Lock()
	h.closeErr = e
	for !h.sendQueue.Empty() {
		h.sendQueue.PopFront().ReleaseSendOwner()
	}
	select {
	case <-h.closed:
		h.sendMx.Unlock()
		return
	default:
	}
	h.rcvMx.Lock()
	for !h.rcvQueue.Empty() {
		h.rcvQueue.PopFront().Release()
	}
	h.rcvMx.Unlock()
	close(h.closed)
	h.sendMx.Unlock()
}
