package http3

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/internal/utils/ringbuffer"
)

const streamDatagramQueueLen = 32

// stateTrackingStream is an implementation of quic.Stream that delegates
// to an underlying stream
// it takes care of proxying send and receive errors onto an implementation of
// the errorSetter interface (intended to be occupied by a datagrammer)
// it is also responsible for clearing the stream based on its ID from its
// parent connection, this is done through the streamClearer interface when
// both the send and receive sides are closed
type stateTrackingStream struct {
	*quic.Stream

	sendDatagram            func([]byte) error
	sendDatagramBuffer      func([]byte, int, int) error
	sendDatagramBufferOwned func([]byte, int, int, quic.DatagramPayloadOwner) error
	hasData                 chan struct{}
	queue                   ringbuffer.RingBuffer[*quic.DatagramBuffer]

	mx      sync.Mutex
	sendErr error
	recvErr error

	clearer streamClearer
}

var _ datagramStream = &stateTrackingStream{}

type streamClearer interface {
	clearStream(quic.StreamID)
}

func newStateTrackingStream(s *quic.Stream, clearer streamClearer, sendDatagram func([]byte) error) *stateTrackingStream {
	t := &stateTrackingStream{
		Stream:       s,
		clearer:      clearer,
		sendDatagram: sendDatagram,
		hasData:      make(chan struct{}, 1),
	}
	t.queue.Init(streamDatagramQueueLen)

	context.AfterFunc(s.Context(), func() {
		t.closeSend(context.Cause(s.Context()))
	})

	return t
}

func (s *stateTrackingStream) closeSend(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.sendErr == nil {
		if s.recvErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.sendErr = e
	}
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.recvErr == nil {
		if s.sendErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.recvErr = e
		for !s.queue.Empty() {
			s.queue.PopFront().Release()
		}
		s.signalHasDatagram()
	}
}

func (s *stateTrackingStream) Close() error {
	s.closeSend(errors.New("write on closed stream"))
	return s.Stream.Close()
}

func (s *stateTrackingStream) CancelWrite(e quic.StreamErrorCode) {
	s.closeSend(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelWrite(e)
}

func (s *stateTrackingStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeSend(err)
	}
	return n, err
}

func (s *stateTrackingStream) CancelRead(e quic.StreamErrorCode) {
	s.closeReceive(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelRead(e)
}

func (s *stateTrackingStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeReceive(err)
	}
	return n, err
}

func (s *stateTrackingStream) SendDatagram(b []byte) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return s.sendDatagram(b)
}

func (s *stateTrackingStream) SendDatagramBuffer(buf []byte, offset, length int) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return fmt.Errorf("invalid datagram buffer range: offset=%d length=%d buffer=%d", offset, length, len(buf))
	}
	if s.sendDatagramBuffer != nil {
		return s.sendDatagramBuffer(buf, offset, length)
	}
	return s.sendDatagram(buf[offset : offset+length])
}

// SendDatagramBufferOwned forwards an explicitly owned buffer. A nil error
// transfers ownership to the lower layer; an error leaves it with the caller.
func (s *stateTrackingStream) SendDatagramBufferOwned(buf []byte, offset, length int, owner quic.DatagramPayloadOwner) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return fmt.Errorf("invalid datagram buffer range: offset=%d length=%d buffer=%d", offset, length, len(buf))
	}
	if s.sendDatagramBufferOwned != nil {
		return s.sendDatagramBufferOwned(buf, offset, length, owner)
	}
	var err error
	if s.sendDatagramBuffer != nil {
		err = s.sendDatagramBuffer(buf, offset, length)
	} else {
		err = s.sendDatagram(buf[offset : offset+length])
	}
	if err == nil && owner != nil {
		owner.Release()
	}
	return err
}

func (s *stateTrackingStream) signalHasDatagram() {
	select {
	case s.hasData <- struct{}{}:
	default:
	}
}

func (s *stateTrackingStream) enqueueDatagram(data []byte) {
	s.enqueueDatagramBuffer(&quic.DatagramBuffer{Data: data})
}

func (s *stateTrackingStream) enqueueDatagramBuffer(data *quic.DatagramBuffer) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.recvErr != nil {
		data.Release()
		return
	}
	if s.queue.Len() >= streamDatagramQueueLen {
		data.Release()
		return
	}
	s.queue.PushBack(data)
	s.signalHasDatagram()
}

func (s *stateTrackingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	b, err := s.ReceiveDatagramBuffer(ctx)
	if err != nil {
		return nil, err
	}
	data := append([]byte(nil), b.Data...)
	b.Release()
	return data, nil
}

func (s *stateTrackingStream) ReceiveDatagramBuffer(ctx context.Context) (*quic.DatagramBuffer, error) {
start:
	s.mx.Lock()
	if !s.queue.Empty() {
		data := s.queue.PopFront()
		s.mx.Unlock()
		return data, nil
	}
	if receiveErr := s.recvErr; receiveErr != nil {
		s.mx.Unlock()
		return nil, receiveErr
	}
	s.mx.Unlock()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.hasData:
	}
	goto start
}

// TryReceiveDatagramBuffer returns one queued datagram without waiting for a
// future datagram. An open stream with an empty queue is reported as
// context.Canceled to preserve the existing nonblocking receive convention.
func (s *stateTrackingStream) TryReceiveDatagramBuffer() (*quic.DatagramBuffer, error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if !s.queue.Empty() {
		return s.queue.PopFront(), nil
	}
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	return nil, context.Canceled
}

func (s *stateTrackingStream) QUICStream() *quic.Stream {
	return s.Stream
}
