//go:build linux || darwin

package quic

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// A connected UDP socket surfaces an ICMP Fragmentation Needed / Packet Too Big for one of
// its datagrams as EMSGSIZE on a later read. Treating that as a fatal receive error killed the
// transport after a path-MTU event that was already being handled by the PMTUD probe; the read
// loop must skip the datagram instead (upstream v0.61.0-sing-box-mod.10).
func TestRecvMsgSizeErrorIsRecoverable(t *testing.T) {
	if !isRecvMsgSizeErr(unix.EMSGSIZE) {
		t.Fatal("EMSGSIZE from a connected socket read must be recoverable")
	}
	if isRecvMsgSizeErr(errors.New("unrelated")) {
		t.Fatal("an unrelated read error must not be treated as a recoverable size error")
	}
	if isRecvMsgSizeErr(nil) {
		t.Fatal("a nil error must not be reported as a size error")
	}
}
