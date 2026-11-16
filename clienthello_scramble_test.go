package quic

// This fork ships a DPI countermeasure: the client splits its ClientHello at
// semantically chosen offsets (the middle of the SNI host name, and the ECH
// extension) and sends those parts in CRYPTO frames with explicit offsets, out
// of order. The peer reassembles them, so the wire bytes are reordered but
// never lost.
//
// The feature parses the ClientHello byte for byte, which makes it sensitive to
// the exact shape of the message crypto/tls produces. Go 1.27 made that message
// 6 bytes longer (ML-DSA signature schemes in the default list) and it was
// already over a single Initial packet because the post-quantum key share alone
// is more than a kilobyte. Nothing in this repository tested the split against a
// ClientHello the current toolchain actually produces, so a change in the
// message layout could have turned the split into silent byte loss.
//
// These tests build a real ClientHello with crypto/tls, push it through the
// stream the way the handshake does (in more than one Write, since it spans
// several packets), and then reassemble what the packet packer would put on the
// wire. The invariant is exact: the union of the emitted frames is the original
// ClientHello, byte for byte, with no gaps and no duplicates, in whatever order
// the frames were produced.

import (
	"bytes"
	"context"
	"crypto/tls"
	"sort"
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
)

// realClientHello returns the ClientHello crypto/tls produces for a QUIC client,
// exactly as the handshake would receive it from the TLS stack.
func realClientHello(t *testing.T) []byte {
	t.Helper()
	conn := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h3"},
		// Go 1.25 rejects a QUIC config without a TLS 1.3 floor; Go 1.27 derives the
		// floor itself. Setting it explicitly keeps this test valid on both.
		MinVersion: tls.VersionTLS13,
	}})
	conn.SetTransportParameters(nil)
	if err := conn.Start(context.Background()); err != nil {
		t.Fatalf("failed to start the QUIC TLS client: %s", err)
	}
	var hello []byte
	for {
		event := conn.NextEvent()
		if event.Kind == tls.QUICNoEvent {
			break
		}
		if event.Kind == tls.QUICWriteData {
			hello = append(hello, event.Data...)
		}
	}
	_ = conn.Close()
	if len(hello) < 4 || hello[0] != 1 {
		t.Fatalf("crypto/tls did not produce a ClientHello (got %d bytes starting with %#x)", len(hello), hello[:min(4, len(hello))])
	}
	return hello
}

type emittedFrame struct {
	offset protocol.ByteCount
	data   []byte
}

// drainCryptoFrames pulls frames until the stream has nothing left to send.
func drainCryptoFrames(t *testing.T, stream *initialCryptoStream) []emittedFrame {
	t.Helper()
	var frames []emittedFrame
	for i := 0; i < 1000; i++ {
		frame := stream.PopCryptoFrame(1200)
		if frame == nil {
			return frames
		}
		if len(frame.Data) == 0 {
			t.Fatalf("PopCryptoFrame returned a frame without data (offset %d)", frame.Offset)
		}
		frames = append(frames, emittedFrame{offset: frame.Offset, data: bytes.Clone(frame.Data)})
	}
	t.Fatal("PopCryptoFrame did not terminate")
	return nil
}

// reassemble rebuilds a byte stream from frames that may arrive in any order.
func reassemble(t *testing.T, frames []emittedFrame) []byte {
	t.Helper()
	if len(frames) == 0 {
		t.Fatal("no CRYPTO frames were emitted")
	}
	ordered := append([]emittedFrame(nil), frames...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].offset < ordered[j].offset })
	var out []byte
	var next protocol.ByteCount
	for i, frame := range ordered {
		if frame.offset < next {
			t.Fatalf("frame %d at offset %d overlaps the previous frame (which ended at %d): "+
				"the split duplicated bytes", i, frame.offset, next)
		}
		if frame.offset > next {
			t.Fatalf("gap before frame %d: expected offset %d, got %d: the split dropped bytes", i, next, frame.offset)
		}
		out = append(out, frame.data...)
		next += protocol.ByteCount(len(frame.data))
	}
	return out
}

func TestInitialCryptoStreamSplitsARealClientHelloWithoutLosingBytes(t *testing.T) {
	hello := realClientHello(t)

	sniPos, sniLen, _, err := findSNIAndECH(hello)
	if err != nil {
		t.Fatalf("the ClientHello this toolchain produces is not parseable by the scrambling code: %s", err)
	}
	if sniPos < 0 || sniLen <= 1 {
		t.Fatalf("no usable SNI host name in the ClientHello (pos %d, len %d)", sniPos, sniLen)
	}

	// The handshake writes the ClientHello as crypto/tls produces it, which can be more
	// than one Write call. Feed it in two halves to exercise that path.
	stream := newInitialCryptoStream(true, false)
	if !stream.scramble {
		t.Fatal("client-side ClientHello scrambling is unexpectedly disabled")
	}
	split := len(hello) / 2
	if _, err := stream.Write(hello[:split]); err != nil {
		t.Fatalf("writing the first half of the ClientHello failed: %s", err)
	}
	if stream.HasData() {
		t.Fatal("the stream offered data before the whole ClientHello was queued: " +
			"the packet packer would send a partially parsed ClientHello")
	}
	if stream.cuts[0].start != protocol.InvalidByteCount {
		t.Fatalf("a cut was computed from a truncated ClientHello: %+v", stream.cuts)
	}
	if _, err := stream.Write(hello[split:]); err != nil {
		t.Fatalf("writing the second half of the ClientHello failed: %s", err)
	}
	if !stream.HasData() {
		t.Fatal("the stream still offers no data after the whole ClientHello was queued")
	}

	wantStart := protocol.ByteCount(sniPos + sniLen/2)
	wantEnd := protocol.ByteCount(sniPos + sniLen)
	if stream.cuts[0].start != wantStart || stream.cuts[0].end != wantEnd {
		t.Fatalf("SNI cut is %+v, want %d..%d (middle of the host name at %d, length %d)",
			stream.cuts[0], wantStart, wantEnd, sniPos, sniLen)
	}

	frames := drainCryptoFrames(t, stream)
	gets := reassemble(t, frames)
	if got := bytes.Compare(gets, hello); got != 0 {
		t.Fatalf("reassembled ClientHello differs from the original (%d bytes vs %d bytes); "+
			"first difference at %d", len(gets), len(hello), firstDifference(gets, hello))
	}

	// The point of the feature is that the bytes go out of order. If every frame were in
	// ascending offset order, the split would be a no-op with extra frames.
	ascending := true
	for i := 1; i < len(frames); i++ {
		if frames[i].offset < frames[i-1].offset {
			ascending = false
			break
		}
	}
	if ascending {
		t.Fatalf("CRYPTO frames were emitted in strictly ascending order (%d frames): "+
			"the ClientHello was not split at all", len(frames))
	}
}

func TestInitialCryptoStreamDoesNotSplitBeforeTheClientHelloIsComplete(t *testing.T) {
	hello := realClientHello(t)

	stream := newInitialCryptoStream(true, false)
	// Feed everything except the last byte: the parser reports ErrUnexpectedEOF, which must
	// be tolerated (the rest is still in flight), and nothing may be emitted yet.
	if _, err := stream.Write(hello[:len(hello)-1]); err != nil {
		t.Fatalf("a truncated ClientHello must be tolerated, got: %s", err)
	}
	if stream.HasData() {
		t.Fatal("data was offered for a truncated ClientHello")
	}
	if frames := drainCryptoFrames(t, stream); len(frames) != 0 {
		t.Fatalf("frames were emitted for a truncated ClientHello: %+v", frames)
	}

	// A stream that does not even start with a ClientHello must be rejected, not silently
	// treated as unsplittable.
	stream = newInitialCryptoStream(true, false)
	if _, err := stream.Write([]byte{0x02, 0x00, 0x00, 0x00}); err == nil {
		t.Fatal("a non-ClientHello byte stream was accepted by the scrambling code")
	}
}

func firstDifference(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
