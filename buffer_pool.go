package quic

import (
	"sync"
	"sync/atomic"

	"github.com/metacubex/quic-go/internal/protocol"
)

type packetBuffer struct {
	Data []byte

	// refCount counts how many packets Data is used in.
	// The reference count is safe to transition concurrently. Payload access
	// still follows the ownership contract of the individual packet users.
	// It is > 1 when used for coalesced packets or retained DATAGRAMs.
	refCount atomic.Int32
}

// Split increases the refCount.
// It must be called when a packet buffer is used for more than one packet,
// e.g. when splitting coalesced packets.
func (b *packetBuffer) Split() {
	b.refCount.Add(1)
}

func (b *packetBuffer) Retain() { b.Split() }

// retainedPacketBufferRef is a named pointer view over packetBuffer. It lets a
// retained packet reference implement the owner interface without allocating a
// second heap object. Each view owns exactly one retained reference and must be
// released exactly once.
type retainedPacketBufferRef packetBuffer

func (r *retainedPacketBufferRef) Release() {
	if r != nil {
		(*packetBuffer)(r).releaseRef()
	}
}

// releaseRef releases one reference. The atomic decrement and the final
// put-back decision are one state transition, so exactly one caller can
// return the buffer to its pool.
func (b *packetBuffer) releaseRef() int32 {
	n := b.refCount.Add(-1)
	if n < 0 {
		panic("negative packetBuffer refCount")
	}
	if n == 0 {
		b.putBack()
	}
	return n
}

// Release puts back the packet buffer into the pool.
// It asserts that this caller owns the final reference. Shared lifetimes must
// use releaseRef instead.
func (b *packetBuffer) Release() {
	if b.releaseRef() != 0 {
		panic("packetBuffer refCount not zero")
	}
}

// Len returns the length of Data
func (b *packetBuffer) Len() protocol.ByteCount { return protocol.ByteCount(len(b.Data)) }
func (b *packetBuffer) Cap() protocol.ByteCount { return protocol.ByteCount(cap(b.Data)) }

func (b *packetBuffer) putBack() {
	if packetBufferPutBackHook != nil {
		packetBufferPutBackHook()
	}
	if cap(b.Data) == protocol.MaxPacketBufferSize {
		bufferPool.Put(b)
		return
	}
	if cap(b.Data) == protocol.MaxLargePacketBufferSize {
		largeBufferPool.Put(b)
		return
	}
	panic("putPacketBuffer called with packet of wrong size!")
}

// packetBufferPutBackHook is used by package tests to count final ownership
// transitions. It is nil in production.
var packetBufferPutBackHook func()

var bufferPool, largeBufferPool sync.Pool

func getPacketBuffer() *packetBuffer {
	buf := bufferPool.Get().(*packetBuffer)
	buf.refCount.Store(1)
	buf.Data = buf.Data[:0]
	return buf
}

func getLargePacketBuffer() *packetBuffer {
	buf := largeBufferPool.Get().(*packetBuffer)
	buf.refCount.Store(1)
	buf.Data = buf.Data[:0]
	return buf
}

func init() {
	bufferPool.New = func() any {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxPacketBufferSize)}
	}
	largeBufferPool.New = func() any {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxLargePacketBufferSize)}
	}
}
