package quic

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestBufferPoolSizes(t *testing.T) {
	buf1 := getPacketBuffer()
	require.Equal(t, protocol.MaxPacketBufferSize, cap(buf1.Data))
	require.Zero(t, buf1.Len())
	buf1.Data = append(buf1.Data, []byte("foobar")...)
	require.Equal(t, protocol.ByteCount(6), buf1.Len())

	buf2 := getLargePacketBuffer()
	require.Equal(t, protocol.MaxLargePacketBufferSize, cap(buf2.Data))
	require.Zero(t, buf2.Len())
}

func TestBufferPoolRelease(t *testing.T) {
	buf1 := getPacketBuffer()
	buf1.Release()
	// panics if released twice
	require.Panics(t, func() { buf1.Release() })

	// panics if wrong-sized buffers are passed
	buf2 := getLargePacketBuffer()
	buf2.Data = make([]byte, 10) // replace the underlying slice
	require.Panics(t, func() { buf2.Release() })
}

func TestBufferPoolSplitting(t *testing.T) {
	buf := getPacketBuffer()
	buf.Split()
	buf.Split()
	// now we have 3 parts
	buf.releaseRef()
	buf.releaseRef()
	buf.releaseRef()
	require.Panics(t, func() { buf.releaseRef() })
}

func TestPacketBufferConcurrentFinalReleaseReturnsToPoolOnce(t *testing.T) {
	var putBacks atomic.Int32
	packetBufferPutBackHook = func() { putBacks.Add(1) }
	defer func() { packetBufferPutBackHook = nil }()

	const rounds = 1000
	for i := 0; i < rounds; i++ {
		refs := 2 + i%7
		buf := getPacketBuffer()
		handles := make([]*retainedPacketBufferRef, refs-1)
		for j := range handles {
			buf.Retain()
			handles[j] = (*retainedPacketBufferRef)(buf)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(refs)
		go func() {
			defer wg.Done()
			<-start
			buf.releaseRef() // base packet-processing reference
		}()
		for _, handle := range handles {
			go func(h *retainedPacketBufferRef) {
				defer wg.Done()
				<-start
				h.Release()
			}(handle)
		}
		close(start)
		wg.Wait()
	}

	require.EqualValues(t, rounds, putBacks.Load())
}

func TestPacketBufferReleaseRefAndRetainedRelease(t *testing.T) {
	var putBacks atomic.Int32
	packetBufferPutBackHook = func() { putBacks.Add(1) }
	defer func() { packetBufferPutBackHook = nil }()

	buf := getPacketBuffer()
	buf.Retain()
	handle := (*retainedPacketBufferRef)(buf)
	handle.Release()
	require.Zero(t, putBacks.Load(), "the base reference is still live")
	buf.releaseRef()
	require.EqualValues(t, 1, putBacks.Load())
}

var retainedOwnerBenchmarkSink interface{ Release() }

func BenchmarkRetainDatagramBufferOwner(b *testing.B) {
	conn := new(Conn)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := getPacketBuffer()
		retainedOwnerBenchmarkSink = conn.retainDatagramBuffer(buf)
		retainedOwnerBenchmarkSink.Release()
		buf.Release()
	}
}

func TestPacketBufferSplitReferencesUseSingleFinalRelease(t *testing.T) {
	var putBacks atomic.Int32
	packetBufferPutBackHook = func() { putBacks.Add(1) }
	defer func() { packetBufferPutBackHook = nil }()

	buf := getPacketBuffer()
	buf.Split()
	buf.Split()
	buf.Retain()
	buf.Retain()
	for i := 0; i < 5; i++ {
		buf.releaseRef()
	}
	require.EqualValues(t, 1, putBacks.Load())
}
