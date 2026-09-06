package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3/qlog"
	"github.com/metacubex/quic-go/qlogwriter"
	"github.com/metacubex/quic-go/quicvarint"
)

const maxQuarterStreamID = 1<<60 - 1

// Keep one request DATAGRAM briefly when QUIC delivers it before the server
// accept loop has registered its request stream. The aggregate cap matches the
// per-stream HTTP/3 receive queue limit, so this ordering bridge cannot create
// an unbounded orphan queue.
const maxEarlyDatagrams = 32

var earlyDatagramLifetime = time.Second

type earlyDatagram struct {
	buffer *quic.DatagramBuffer
	offset int
	timer  *time.Timer
}

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

// rawConn is an HTTP/3 connection.
// It provides HTTP/3 specific functionality by wrapping a quic.Conn,
// in particular handling of unidirectional HTTP/3 streams, SETTINGS and datagrams.
type rawConn struct {
	conn *quic.Conn

	logger *slog.Logger

	enableDatagrams bool

	streamMx       sync.Mutex
	streams        map[quic.StreamID]*stateTrackingStream
	earlyDatagrams map[quic.StreamID]*earlyDatagram

	rcvdControlStr      atomic.Bool
	rcvdQPACKEncoderStr atomic.Bool
	rcvdQPACKDecoderStr atomic.Bool
	controlStrHandler   func(*quic.ReceiveStream, *frameParser) // is called *after* the SETTINGS frame was parsed

	onStreamsEmpty func()

	settings         *Settings
	receivedSettings chan struct{}

	qlogger   qlogwriter.Recorder
	qloggerWG sync.WaitGroup // tracks goroutines that may produce qlog events
}

func newRawConn(
	quicConn *quic.Conn,
	enableDatagrams bool,
	onStreamsEmpty func(),
	controlStrHandler func(*quic.ReceiveStream, *frameParser),
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
) *rawConn {
	c := &rawConn{
		conn:              quicConn,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		receivedSettings:  make(chan struct{}),
		streams:           make(map[quic.StreamID]*stateTrackingStream),
		earlyDatagrams:    make(map[quic.StreamID]*earlyDatagram),
		qlogger:           qlogger,
		onStreamsEmpty:    onStreamsEmpty,
		controlStrHandler: controlStrHandler,
	}
	if qlogger != nil {
		context.AfterFunc(quicConn.Context(), c.closeQlogger)
	}
	context.AfterFunc(quicConn.Context(), c.releaseEarlyDatagrams)
	return c
}

func (c *rawConn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// openControlStream opens the control stream and sends the SETTINGS frame.
// It returns the control stream (needed by the server for sending GOAWAY later).
func (c *rawConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	str, err := c.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	b = settings.Append(b)
	if c.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: settings.MaxFieldSectionSize,
			Other:               maps.Clone(settings.Other),
		}
		if settings.Datagram {
			sf.Datagram = new(true)
		}
		if settings.ExtendedConnect {
			sf.ExtendedConnect = new(true)
		}
		c.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}
	if _, err := str.Write(b); err != nil {
		return nil, err
	}
	return str, nil
}

func (c *rawConn) TrackStream(str *quic.Stream) *stateTrackingStream {
	hstr := newStateTrackingStream(str, c, func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })
	hstr.sendDatagramBuffer = func(buf []byte, offset, length int) error {
		return c.sendDatagramBuffer(str.StreamID(), buf, offset, length)
	}
	hstr.sendDatagramBufferOwned = func(buf []byte, offset, length int, owner quic.DatagramPayloadOwner) error {
		return c.sendDatagramBufferOwned(str.StreamID(), buf, offset, length, owner)
	}

	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	early := c.earlyDatagrams[str.StreamID()]
	delete(c.earlyDatagrams, str.StreamID())
	c.qloggerWG.Add(1)
	c.streamMx.Unlock()
	if early != nil {
		early.timer.Stop()
		early.buffer.Data = early.buffer.Data[early.offset:]
		hstr.enqueueDatagramBuffer(early.buffer)
	}
	return hstr
}

// retainEarlyDatagramLocked records a pre-registration DATAGRAM. The caller
// holds streamMx, making stream lookup and retention one atomic lifecycle
// decision with TrackStream.
func (c *rawConn) retainEarlyDatagramLocked(id quic.StreamID, offset int, b *quic.DatagramBuffer) bool {
	if len(c.earlyDatagrams) >= maxEarlyDatagrams {
		return false
	}
	if _, exists := c.earlyDatagrams[id]; exists {
		return false
	}
	early := &earlyDatagram{buffer: b, offset: offset}
	c.earlyDatagrams[id] = early
	early.timer = time.AfterFunc(earlyDatagramLifetime, func() { c.expireEarlyDatagram(id, early) })
	return true
}

func (c *rawConn) expireEarlyDatagram(id quic.StreamID, early *earlyDatagram) {
	c.streamMx.Lock()
	if c.earlyDatagrams[id] != early {
		c.streamMx.Unlock()
		return
	}
	delete(c.earlyDatagrams, id)
	c.streamMx.Unlock()
	early.buffer.Release()
}

func (c *rawConn) releaseEarlyDatagrams() {
	c.streamMx.Lock()
	early := c.earlyDatagrams
	c.earlyDatagrams = make(map[quic.StreamID]*earlyDatagram)
	c.streamMx.Unlock()
	for _, entry := range early {
		entry.timer.Stop()
		entry.buffer.Release()
	}
}

func (c *rawConn) UpdateStreamPriority(id quic.StreamID, urgency int8, incremental bool) {
	c.streamMx.Lock()
	str := c.streams[id]
	c.streamMx.Unlock()
	// A PRIORITY_UPDATE can arrive before its request stream. We deliberately ignore such reordered frames.
	if str != nil {
		str.SetPriority(urgency, incremental)
	}
}

func (c *rawConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *rawConn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *rawConn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	if _, ok := c.streams[id]; ok {
		delete(c.streams, id)
		c.qloggerWG.Done()
	}
	if len(c.streams) == 0 {
		c.onStreamsEmpty()
	}
}

func (c *rawConn) hasActiveStreams() bool {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	return len(c.streams) > 0
}

func (c *rawConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.conn.CloseWithError(code, msg)
}

func (c *rawConn) handleUnidirectionalStream(str *quic.ReceiveStream, isServer bool) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
		}
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypePushStream:
		if isServer {
			// only the server can push
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		} else {
			// we never increased the Push ID, so we don't expect any push streams
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	c.handleControlStream(str)
}

func (c *rawConn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID()}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		if errors.Is(err, errPriorityUpdateForPush) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
			return
		}
		_, isStreamError := errors.AsType[*quic.StreamError](err)
		if err == io.EOF || isStreamError {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams.Remote {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		c.qloggerWG.Go(func() {
			err := c.receiveDatagrams()
			if c.logger != nil {
				c.logger.Debug("receiving datagrams failed", "error", err)
			}
		})
	}

	c.controlStrHandler(str, fp)
}

func (c *rawConn) sendDatagram(streamID quic.StreamID, b []byte) error {
	data := make([]byte, 0, len(b)+8)
	quarterStreamID := uint64(streamID / 4)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuarterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
		})
	}
	return c.conn.SendDatagram(data)
}

func (c *rawConn) sendDatagramBuffer(streamID quic.StreamID, buf []byte, offset, length int) error {
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return fmt.Errorf("invalid datagram buffer range: offset=%d length=%d buffer=%d", offset, length, len(buf))
	}
	payload := buf[offset : offset+length]
	quarterStreamID := uint64(streamID / 4)
	var encoded [8]byte
	prefix := quicvarint.Append(encoded[:0], quarterStreamID)
	if offset < len(prefix) {
		// Callers without enough headroom remain compatible, but use the
		// legacy allocating path rather than risking an overwrite.
		return c.sendDatagram(streamID, payload)
	}
	start := offset - len(prefix)
	copy(buf[start:offset], prefix)
	data := buf[start : offset+length]
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuarterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(payload),
			},
		})
	}
	return c.conn.SendDatagram(data)
}

func (c *rawConn) sendDatagramBufferOwned(streamID quic.StreamID, buf []byte, offset, length int, owner quic.DatagramPayloadOwner) error {
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return fmt.Errorf("invalid datagram buffer range: offset=%d length=%d buffer=%d", offset, length, len(buf))
	}
	payload := buf[offset : offset+length]
	quarterStreamID := uint64(streamID / 4)
	var encoded [8]byte
	prefix := quicvarint.Append(encoded[:0], quarterStreamID)
	if offset < len(prefix) {
		// There is no safe in-place ownership path without headroom. The legacy
		// path copies synchronously, so release only after it accepts the copy.
		err := c.sendDatagram(streamID, payload)
		if err == nil && owner != nil {
			owner.Release()
		}
		return err
	}
	start := offset - len(prefix)
	copy(buf[start:offset], prefix)
	data := buf[start : offset+length]
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuarterStreamID: quarterStreamID,
			Raw:             qlog.RawInfo{Length: len(data), PayloadLength: len(payload)},
		})
	}
	return c.conn.SendDatagramOwned(data, owner)
}

func (c *rawConn) receiveDatagrams() error {
	for {
		b, err := c.conn.ReceiveDatagramBuffer(context.Background())
		if err != nil {
			return err
		}
		if err := c.routeDatagram(b); err != nil {
			return err
		}
	}
}

func (c *rawConn) routeDatagram(b *quic.DatagramBuffer) error {
	quarterStreamID, n, err := quicvarint.Parse(b.Data)
	if err != nil {
		b.Release()
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
		return fmt.Errorf("could not read quarter stream id: %w", err)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramParsed{
			QuarterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(b.Data),
				PayloadLength: len(b.Data) - n,
			},
		})
	}
	if quarterStreamID > maxQuarterStreamID {
		b.Release()
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
		return fmt.Errorf("invalid quarter stream id: %w", err)
	}
	streamID := quic.StreamID(4 * quarterStreamID)
	c.streamMx.Lock()
	dg, ok := c.streams[streamID]
	if !ok {
		retained := c.retainEarlyDatagramLocked(streamID, n, b)
		c.streamMx.Unlock()
		if !retained {
			b.Release()
		}
		return nil
	}
	c.streamMx.Unlock()
	b.Data = b.Data[n:]
	dg.enqueueDatagramBuffer(b)
	return nil
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *rawConn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *rawConn) Settings() *Settings { return c.settings }

// closeQlogger waits for all goroutines that may produce qlog events to finish,
// then closes the qlogger.
func (c *rawConn) closeQlogger() {
	if c.qlogger == nil {
		return
	}
	c.qloggerWG.Wait()
	c.qlogger.Close()
}
