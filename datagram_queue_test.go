package quic

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/quic-go/internal/utils"
	"github.com/metacubex/quic-go/internal/wire"
	"github.com/metacubex/quic-go/testutils/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingDatagramOwner struct {
	releases atomic.Int32
}

func (o *countingDatagramOwner) Release() {
	o.releases.Add(1)
}

func (o *countingDatagramOwner) count() int32 {
	return o.releases.Load()
}

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueOwnedSendLifecycle(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	owner := new(countingDatagramOwner)
	frame := &wire.DatagramFrame{Data: []byte("owned"), SendOwner: owner}
	require.NoError(t, queue.Add(frame))
	queue.Pop()
	require.Zero(t, owner.count(), "Pop transfers ownership to the packer")
	frame.ReleaseSendOwner()
	frame.ReleaseSendOwner()
	require.EqualValues(t, 1, owner.count())
	require.Nil(t, frame.Data, "released frame must not retain mutable caller backing")
}

func TestDatagramQueueDropAndCloseReleaseOwnedSends(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	dropped := new(countingDatagramOwner)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("drop"), SendOwner: dropped}))
	queue.Drop()
	require.EqualValues(t, 1, dropped.count())

	owners := []*countingDatagramOwner{new(countingDatagramOwner), new(countingDatagramOwner), new(countingDatagramOwner)}
	for _, owner := range owners {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("close"), SendOwner: owner}))
	}
	queue.CloseWithError(assert.AnError)
	for _, owner := range owners {
		require.EqualValues(t, 1, owner.count())
	}
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		for j := 0; j < maxDatagramSendQueueLen; j++ {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan := make(chan error, 1)
		go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

		synctest.Wait()

		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		// peeking doesn't remove the datagram from the queue...
		require.NotNil(t, queue.Peek())
		synctest.Wait()
		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		// ...but popping does
		queue.Pop()
		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
		// pop all the remaining datagrams
		for j := 0; j < maxDatagramSendQueueLen-1; j++ {
			queue.Pop()
		}
		f := queue.Peek()
		require.NotNil(t, f)
		require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
	})
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func BenchmarkDatagramQueueBorrowedReceiveRelease(b *testing.B) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	data := make([]byte, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data, DataOwner: new(countingDatagramOwner)})
		buffer, err := queue.ReceiveBuffer(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		buffer.Release()
	}
}

func TestDatagramQueueReceiveWraparoundFIFO(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}
	for i := 0; i < maxDatagramRcvQueueLen/2; i++ {
		b, err := queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{byte(i)}, b.Data)
		b.Release()
	}
	for i := maxDatagramRcvQueueLen; i < maxDatagramRcvQueueLen+maxDatagramRcvQueueLen/2; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}

	for i := maxDatagramRcvQueueLen / 2; i < maxDatagramRcvQueueLen+maxDatagramRcvQueueLen/2; i++ {
		b, err := queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
		require.Equal(t, []byte{byte(i)}, b.Data)
		b.Release()
	}
	require.True(t, queue.rcvQueue.Empty())
}

func TestDatagramQueueWraparoundCloseReleasesQueuedOwners(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}
	for i := 0; i < maxDatagramRcvQueueLen/2; i++ {
		b, err := queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
		b.Release()
	}
	for i := 0; i < maxDatagramRcvQueueLen/2-3; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}

	owners := []*countingDatagramOwner{new(countingDatagramOwner), new(countingDatagramOwner), new(countingDatagramOwner)}
	for _, owner := range owners {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: owner})
	}
	queue.CloseWithError(assert.AnError)
	for _, owner := range owners {
		require.EqualValues(t, 1, owner.count())
	}
}

func TestDatagramBufferReleaseDetachesData(t *testing.T) {
	b := &DatagramBuffer{Data: []byte("payload")}
	b.Release()
	require.Nil(t, b.Data)
	b.Release()
}

func TestDatagramQueueTransfersFrameDataOwnership(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	data := []byte("owned datagram")
	frame := &wire.DatagramFrame{Data: data}
	queue.HandleDatagramFrame(frame)
	received, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, received)
	require.True(t, &received.Data[0] == &data[0], "receive queue made a duplicate payload allocation")
	received.Data[0] = 'O'
	require.Equal(t, byte('O'), data[0])
}

func TestDatagramQueueFullReleasesDroppedBufferWithoutDebugLogging(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}

	owner := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("dropped"), DataOwner: owner})
	require.EqualValues(t, 1, owner.count())
}

func TestDatagramQueueFullReleasesDroppedBufferWithDebugLogging(t *testing.T) {
	logger := utils.DefaultLogger.WithPrefix("datagram-queue-test")
	logger.SetLogLevel(utils.LogLevelDebug)
	queue := newDatagramQueue(func() {}, logger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}

	owner := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("dropped"), DataOwner: owner})
	require.EqualValues(t, 1, owner.count())
}

func TestDatagramQueueCloseDrainsQueuedBuffers(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	owners := []*countingDatagramOwner{new(countingDatagramOwner), new(countingDatagramOwner), new(countingDatagramOwner)}
	for _, owner := range owners {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: owner})
	}

	queue.CloseWithError(assert.AnError)
	for _, owner := range owners {
		require.EqualValues(t, 1, owner.count())
	}
}

func TestDatagramQueuePopThenCloseTransfersReleaseResponsibility(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	first := new(countingDatagramOwner)
	second := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: first})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{2}, DataOwner: second})

	b, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 0, first.count())
	queue.CloseWithError(assert.AnError)
	require.EqualValues(t, 0, first.count(), "popped buffers must not be released by queue close")
	require.EqualValues(t, 1, second.count())
	b.Release()
	require.EqualValues(t, 1, first.count())
}

func TestDatagramRetentionBudgetKeepsFirst64Borrowed(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	borrowed := make([]*DatagramBuffer, maxRetainedDatagramBuffers)
	owners := make([]*countingDatagramOwner, maxRetainedDatagramBuffers)
	backings := make([][]byte, maxRetainedDatagramBuffers)
	for i := range borrowed {
		backings[i] = []byte{byte(i), 2, 3}
		owners[i] = new(countingDatagramOwner)
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: backings[i], DataOwner: owners[i]})
		var err error
		borrowed[i], err = queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
		require.Equal(t, &backings[i][0], &borrowed[i].Data[0])
	}

	require.EqualValues(t, maxRetainedDatagramBuffers, queue.retained.inFlight.Load())
	require.Zero(t, queue.retained.fallbackCopies.Load())
	for i := range borrowed {
		borrowed[i].Release()
		require.EqualValues(t, 1, owners[i].count())
	}
	require.Zero(t, queue.retained.inFlight.Load())
}

func TestDatagramRetentionBudgetFallsBackToCompactCopy(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	borrowed := make([]*DatagramBuffer, 0, maxRetainedDatagramBuffers)
	for i := 0; i < maxRetainedDatagramBuffers; i++ {
		owner := new(countingDatagramOwner)
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}, DataOwner: owner})
		b, err := queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
		// Keep the borrowed buffer outstanding so the budget remains full.
		borrowed = append(borrowed, b)
		require.Zero(t, owner.count())
	}

	original := []byte("compact fallback")
	owner := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: original, DataOwner: owner})
	fallback, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	require.Equal(t, original, fallback.Data)
	fallback.Data[0] = 'X'
	require.Equal(t, byte('c'), original[0], "budget fallback must use an independent backing allocation")
	require.Equal(t, len(fallback.Data), cap(fallback.Data))
	require.EqualValues(t, 1, owner.count())
	require.EqualValues(t, maxRetainedDatagramBuffers, queue.retained.inFlight.Load())
	require.EqualValues(t, 1, queue.retained.fallbackCopies.Load())
	fallback.Release()
	for _, b := range borrowed {
		b.Release()
	}
	require.Zero(t, queue.retained.inFlight.Load())
}

func TestDatagramRetentionBudgetReacquiresAfterRelease(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	borrowed := make([]*DatagramBuffer, maxRetainedDatagramBuffers)
	for i := range borrowed {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: new(countingDatagramOwner)})
		var err error
		borrowed[i], err = queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
	}
	borrowed[0].Release()
	require.EqualValues(t, maxRetainedDatagramBuffers-1, queue.retained.inFlight.Load())

	owner := new(countingDatagramOwner)
	data := []byte("borrowed again")
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data, DataOwner: owner})
	b, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	require.Equal(t, &data[0], &b.Data[0])
	require.EqualValues(t, maxRetainedDatagramBuffers, queue.retained.inFlight.Load())
	b.Release()
	for _, b := range borrowed[1:] {
		b.Release()
	}
	require.Zero(t, queue.retained.inFlight.Load())
}

func TestDatagramQueueFullPrecedesRetentionFallback(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	for i := 0; i < maxDatagramRcvQueueLen; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{byte(i)}})
	}
	owner := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("dropped"), DataOwner: owner})
	require.EqualValues(t, 1, owner.count())
	require.Zero(t, queue.retained.fallbackCopies.Load())
}

func TestDatagramQueueOwnerlessFrameDoesNotConsumeBudget(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	borrowed := make([]*DatagramBuffer, maxRetainedDatagramBuffers)
	for i := range borrowed {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: new(countingDatagramOwner)})
		var err error
		borrowed[i], err = queue.ReceiveBuffer(context.Background())
		require.NoError(t, err)
	}

	data := []byte("ownerless")
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data})
	b, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	require.Equal(t, &data[0], &b.Data[0])
	require.EqualValues(t, maxRetainedDatagramBuffers, queue.retained.inFlight.Load())
	b.Release()
	for _, b := range borrowed {
		b.Release()
	}
}

func TestDatagramRetentionBudgetCountsHandlesNotBackingOwners(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	owner := new(countingDatagramOwner)
	data := []byte("shared backing owner")
	for i := 0; i < 2; i++ {
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: data, DataOwner: owner})
	}
	require.EqualValues(t, 2, queue.retained.inFlight.Load())
	first, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	second, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	first.Release()
	require.EqualValues(t, 1, queue.retained.inFlight.Load())
	second.Release()
	require.Zero(t, queue.retained.inFlight.Load())
	require.EqualValues(t, 2, owner.count())
}

func TestDatagramRetentionBudgetConcurrentStress(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	const rounds = 1000
	for i := 0; i < rounds; i++ {
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if queue.retained.tryAcquire() {
					queue.retained.release()
				}
			}()
		}
		wg.Wait()
		require.LessOrEqual(t, queue.retained.highWater.Load(), int32(maxRetainedDatagramBuffers))
		require.GreaterOrEqual(t, queue.retained.inFlight.Load(), int32(0))
	}
	require.Zero(t, queue.retained.inFlight.Load())
}

func TestDatagramQueueCloseReturnsRetainedBudget(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	owners := make([]*countingDatagramOwner, maxRetainedDatagramBuffers)
	for i := range owners {
		owners[i] = new(countingDatagramOwner)
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: owners[i]})
	}
	queue.CloseWithError(assert.AnError)
	for _, owner := range owners {
		require.EqualValues(t, 1, owner.count())
	}
	require.Zero(t, queue.retained.inFlight.Load())
}

func TestDatagramQueuePopCloseKeepsCallerBudget(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	owner := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte{1}, DataOwner: owner})
	b, err := queue.ReceiveBuffer(context.Background())
	require.NoError(t, err)
	queue.CloseWithError(assert.AnError)
	require.EqualValues(t, 1, queue.retained.inFlight.Load())
	require.Zero(t, owner.count())
	b.Release()
	require.EqualValues(t, 0, queue.retained.inFlight.Load())
	require.EqualValues(t, 1, owner.count())
}

func TestDatagramQueueLegacyReceiveReturnsBudget(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)
	owner := new(countingDatagramOwner)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("legacy"), DataOwner: owner})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("legacy"), data)
	require.Zero(t, queue.retained.inFlight.Load())
	require.EqualValues(t, 1, owner.count())
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		// block until a new frame is received
		type result struct {
			data []byte
			err  error
		}
		resultChan := make(chan result, 1)
		go func() {
			data, err := queue.Receive(context.Background())
			resultChan <- result{data, err}
		}()

		synctest.Wait()

		select {
		case <-resultChan:
			t.Fatal("expected to not receive result")
		default:
		}
		queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
		synctest.Wait()
		select {
		case result := <-resultChan:
			require.NoError(t, result.err)
			require.Equal(t, []byte("foobar"), result.data)
		default:
			t.Fatal("should have received a datagram frame")
		}

		// unblock when the context is canceled
		ctx, cancel := context.WithCancel(context.Background())
		errChan := make(chan error, 1)
		go func() {
			_, err := queue.Receive(ctx)
			errChan <- err
		}()

		synctest.Wait()
		select {
		case <-errChan:
			t.Fatal("expected to not receive error")
		default:
		}

		cancel()
		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, context.Canceled)
		default:
			t.Fatal("should have received a context canceled error")
		}
	})
}

func TestDatagramQueueClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)

		for j := 0; j < maxDatagramSendQueueLen; j++ {
			require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
		}
		errChan1 := make(chan error, 1)
		go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
		errChan2 := make(chan error, 1)
		go func() {
			_, err := queue.Receive(context.Background())
			errChan2 <- err
		}()

		queue.CloseWithError(assert.AnError)
		synctest.Wait()

		select {
		case err := <-errChan1:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}

		select {
		case err := <-errChan2:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("should have received an error")
		}
	})
}
