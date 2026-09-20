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
	writable  chan struct{} // generation channel, closed when a full queue gains capacity

	rcvMx    sync.Mutex
	rcvQueue ringbuffer.RingBuffer[*DatagramBuffer]
	rcvd     chan struct{} // used to notify Receive that a new datagram was received
	retained *datagramRetentionBudget

	closeErr error
	closed   chan struct{}

	hasData func()

	logger           utils.Logger
	sendHighWater    atomic.Uint64
	sendBlocked      atomic.Uint64
	sendBlockedNS    atomic.Uint64
	receiveDrops     atomic.Uint64
	sendEnqueue      atomic.Uint64
	sendDequeue      atomic.Uint64
	sendEnqueueBytes atomic.Uint64
	sendDequeueBytes atomic.Uint64
	nonEmptyNS       atomic.Uint64
	nonEmptyAt       atomic.Int64
}

type datagramQueueRuntimeStats struct {
	SendDepth, SendHighWater, SendBlocked uint64
	SendBlockedDurationNS                 uint64
	ReceiveDepth, ReceiveDrops            uint64
	SendEnqueue, SendDequeue              uint64
	SendEnqueueBytes, SendDequeueBytes    uint64
	NonEmptyDurationNS                    uint64
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	q := &datagramQueue{
		hasData:  hasData,
		rcvd:     make(chan struct{}, 1),
		writable: make(chan struct{}),
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
	return h.AddContext(context.Background(), f)
}

// TryAdd enqueues f only when capacity is immediately available. If it
// returns false, ownership remains with the caller. A nil error with true
// transfers ownership to the queue.
func (h *datagramQueue) TryAdd(f *wire.DatagramFrame) (bool, error) {
	h.sendMx.Lock()
	select {
	case <-h.closed:
		err := h.closeErr
		h.sendMx.Unlock()
		return false, err
	default:
	}
	if h.sendQueue.Len() >= maxDatagramSendQueueLen {
		h.sendMx.Unlock()
		return false, nil
	}
	h.enqueueLocked(f)
	h.sendMx.Unlock()
	h.hasData()
	return true, nil
}

// TryAddBatch atomically accepts the largest prefix that fits. Ownership of
// accepted frames transfers to the queue; ownership of the remaining frames
// stays with the caller.
func (h *datagramQueue) TryAddBatch(frames []*wire.DatagramFrame) (int, error) {
	h.sendMx.Lock()
	select {
	case <-h.closed:
		err := h.closeErr
		h.sendMx.Unlock()
		return 0, err
	default:
	}
	count := min(len(frames), maxDatagramSendQueueLen-h.sendQueue.Len())
	for _, frame := range frames[:count] {
		h.enqueueLocked(frame)
	}
	h.sendMx.Unlock()
	if count > 0 {
		h.hasData()
	}
	return count, nil
}

// Capacity reports the bounded send queue capacity.
func (h *datagramQueue) Capacity() int { return maxDatagramSendQueueLen }

// Depth reports the current send queue depth.
func (h *datagramQueue) Depth() int {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	return h.sendQueue.Len()
}

var datagramQueueReady = func() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// Writable returns a channel that becomes ready when at least one queue slot
// is available or the queue is closed. It is safe to call after a failed
// TryAdd; the returned channel is already ready if capacity opened in between.
func (h *datagramQueue) Writable() <-chan struct{} {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	select {
	case <-h.closed:
		return h.closed
	default:
	}
	if h.sendQueue.Len() < maxDatagramSendQueueLen {
		return datagramQueueReady
	}
	return h.writable
}

func (h *datagramQueue) enqueueLocked(f *wire.DatagramFrame) {
	wasEmpty := h.sendQueue.Empty()
	h.sendQueue.PushBack(f)
	h.sendEnqueue.Add(1)
	h.sendEnqueueBytes.Add(uint64(len(f.Data)))
	if wasEmpty {
		h.nonEmptyAt.Store(time.Now().UnixNano())
	}
	updateAtomicMax(&h.sendHighWater, uint64(h.sendQueue.Len()))
}

// AddContext preserves the blocking Add behavior while allowing callers to
// cancel a full-queue wait.
func (h *datagramQueue) AddContext(ctx context.Context, f *wire.DatagramFrame) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		accepted, err := h.TryAdd(f)
		if err != nil || accepted {
			return err
		}
		blockedAt := time.Now()
		h.sendBlocked.Add(1)
		select {
		case <-h.Writable():
		case <-h.closed:
			h.sendBlockedNS.Add(uint64(time.Since(blockedAt)))
			return h.closeErr
		case <-ctx.Done():
			h.sendBlockedNS.Add(uint64(time.Since(blockedAt)))
			return ctx.Err()
		}
		h.sendBlockedNS.Add(uint64(time.Since(blockedAt)))
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

func (h *datagramQueue) HasData() bool {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	return !h.sendQueue.Empty()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	wasFull := h.sendQueue.Len() == maxDatagramSendQueueLen
	f := h.sendQueue.PopFront()
	if f != nil {
		h.sendDequeue.Add(1)
		h.sendDequeueBytes.Add(uint64(len(f.Data)))
	}
	if h.sendQueue.Empty() {
		h.closeNonEmptyWindow()
	}
	if wasFull {
		close(h.writable)
		h.writable = make(chan struct{})
	}
}

// Drop removes the front frame without giving the packet packer ownership.
// This is used for frames that won't be serialized.
func (h *datagramQueue) Drop() {
	h.sendMx.Lock()
	wasFull := h.sendQueue.Len() == maxDatagramSendQueueLen
	f := h.sendQueue.PopFront()
	if f != nil {
		h.sendDequeue.Add(1)
		h.sendDequeueBytes.Add(uint64(len(f.Data)))
	}
	if h.sendQueue.Empty() {
		h.closeNonEmptyWindow()
	}
	if wasFull {
		close(h.writable)
		h.writable = make(chan struct{})
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
	nonEmpty := h.nonEmptyNS.Load()
	if started := h.nonEmptyAt.Load(); started != 0 {
		nonEmpty += uint64(max(0, time.Now().UnixNano()-started))
	}
	return datagramQueueRuntimeStats{
		SendDepth: sendDepth, SendHighWater: h.sendHighWater.Load(),
		SendBlocked: h.sendBlocked.Load(), SendBlockedDurationNS: h.sendBlockedNS.Load(),
		ReceiveDepth: receiveDepth, ReceiveDrops: h.receiveDrops.Load(),
		SendEnqueue: h.sendEnqueue.Load(), SendDequeue: h.sendDequeue.Load(),
		SendEnqueueBytes: h.sendEnqueueBytes.Load(), SendDequeueBytes: h.sendDequeueBytes.Load(),
		NonEmptyDurationNS: nonEmpty,
	}
}

func (h *datagramQueue) closeNonEmptyWindow() {
	if started := h.nonEmptyAt.Swap(0); started != 0 {
		h.nonEmptyNS.Add(uint64(max(0, time.Now().UnixNano()-started)))
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
	close(h.writable)
	h.sendMx.Unlock()
}
