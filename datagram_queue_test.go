package quic

import (
	"context"
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
