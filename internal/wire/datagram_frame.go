package wire

import (
	"io"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/quicvarint"
)

// MaxDatagramSize is the maximum size of a DATAGRAM frame (RFC 9221).
// By setting it to a large value, we allow all datagrams that fit into a QUIC packet.
// The value is chosen such that it can still be encoded as a 2 byte varint.
// This is a var and not a const so it can be set in tests.
var MaxDatagramSize protocol.ByteCount = 16383

// A DatagramFrame is a DATAGRAM frame
type DatagramFrame struct {
	DataLenPresent bool
	Data           []byte
	// release, when non-nil, is the ownership handle for Data. It is invoked EXACTLY ONCE, after
	// the frame will never be read again -- see Release.
	//
	// It is set only for frames enqueued through the owned-datagram API. A frame built by the
	// copying path leaves it nil and Release is a no-op.
	release func()
}

// Release hands back the frame's payload ownership, if it holds any.
//
// # Why the handle is cleared before it is invoked
//
// A frame can leave the send queue in three ways: it is serialized into a packet, it is discarded
// because it does not fit, or it is discarded after too many peeks. Exactly one of those happens to
// any given frame, but the frame is also reachable afterwards -- it is carried in the packet's
// frame list for qlog and ack-handler bookkeeping. Clearing the handle first makes a second Release
// a harmless no-op instead of a double free, so a future change that adds another release path
// cannot turn into memory corruption.
func (f *DatagramFrame) Release() {
	if f == nil || f.release == nil {
		return
	}
	release := f.release
	f.release = nil
	release()
}

// SetRelease installs the ownership handle for this frame's payload.
func (f *DatagramFrame) SetRelease(release func()) {
	f.release = release
}

func parseDatagramFrame(b []byte, typ FrameType, _ protocol.Version) (*DatagramFrame, int, error) {
	startLen := len(b)
	f := &DatagramFrame{}
	f.DataLenPresent = uint64(typ)&0x1 > 0

	var length uint64
	if f.DataLenPresent {
		var err error
		var l int
		length, l, err = quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		if length > uint64(len(b)) {
			return nil, 0, io.EOF
		}
	} else {
		length = uint64(len(b))
	}
	f.Data = make([]byte, length)
	copy(f.Data, b)
	return f, startLen - len(b) + int(length), nil
}

func (f *DatagramFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	typ := uint8(0x30)
	if f.DataLenPresent {
		typ ^= 0b1
	}
	b = append(b, typ)
	if f.DataLenPresent {
		b = quicvarint.Append(b, uint64(len(f.Data)))
	}
	b = append(b, f.Data...)
	// THE release point, and the reason it is here rather than wherever the frame was queued.
	//
	// The append above is the LAST read of f.Data on the send path: the bytes are now in the
	// caller's packet buffer and nothing downstream ever looks at the frame's slice again. The
	// frame itself outlives this call -- it is carried in the packet's frame list for qlog and
	// ack-handler bookkeeping -- but its payload does not, so ownership can be handed back now.
	//
	// Releasing earlier would be wrong: Pop() only unlinks the frame, and two of its three call
	// sites discard a frame without ever serializing it. Releasing later would be wrong too:
	// DATAGRAM frames are not retransmitted (RFC 9221), so there is no ACK to wait for, and a
	// 32-entry queue holding buffers until connection close is a pool-starvation bug.
	f.Release()
	return b, nil
}

// MaxDataLen returns the maximum data length
func (f *DatagramFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.Version) protocol.ByteCount {
	headerLen := protocol.ByteCount(1)
	if f.DataLenPresent {
		// pretend that the data size will be 1 bytes
		// if it turns out that varint encoding the length will consume 2 bytes, we need to adjust the data length afterwards
		headerLen++
	}
	if headerLen > maxSize {
		return 0
	}
	maxDataLen := maxSize - headerLen
	if f.DataLenPresent && quicvarint.Len(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}

// Length of a written frame
func (f *DatagramFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := 1 + protocol.ByteCount(len(f.Data))
	if f.DataLenPresent {
		length += protocol.ByteCount(quicvarint.Len(uint64(len(f.Data))))
	}
	return length
}
