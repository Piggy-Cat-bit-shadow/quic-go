package quic

import (
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
)

// Application-limited is decided from whether any active stream can actually produce data.
// A stream parked behind flow control stays in activeStreams but must not make the connection
// look application-limited (upstream v0.61.0-sing-box-mod.12).
func TestHasUnblockedStreamDataDistinguishesBlockedStreams(t *testing.T) {
	f := newFramer(nil)
	if f.HasUnblockedStreamData() {
		t.Fatal("an empty framer reports unblocked stream data")
	}

	blocked := protocol.StreamID(4)
	f.activeStreams[blocked] = nil
	if !f.HasUnblockedStreamData() {
		t.Fatal("an active stream with no recorded block reports no unblocked data")
	}

	f.blockedStreams[blocked] = struct{}{}
	if f.HasUnblockedStreamData() {
		t.Fatal("a stream parked behind flow control was reported as unblocked")
	}

	ready := protocol.StreamID(8)
	f.activeStreams[ready] = nil
	if !f.HasUnblockedStreamData() {
		t.Fatal("a second, unblocked stream was not counted")
	}

	delete(f.activeStreams, ready)
	f.RemoveActiveStream(blocked)
	if f.HasUnblockedStreamData() {
		t.Fatal("removed streams still count as unblocked data")
	}
}
