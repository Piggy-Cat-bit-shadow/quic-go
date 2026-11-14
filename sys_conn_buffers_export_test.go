package quic

import (
	"net"
	"syscall"
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
)

func rawConnOf(t *testing.T, socket interface {
	SyscallConn() (syscall.RawConn, error)
}) syscall.RawConn {
	t.Helper()
	rawConn, err := socket.SyscallConn()
	if err != nil {
		t.Fatalf("failed to reach the socket file descriptor: %s", err)
	}
	return rawConn
}

// SetDesiredBufferSizes is called by the owner of a socket that a conn handed to the QUIC
// transport hides behind a wrapper. The obfuscation layers of the hysteria family do that, and
// so does the TCP socket under a UDP-over-TCP detour: growing SO_RCVBUF of that TCP socket to
// the QUIC datagram size would hand the kernel megabytes per connection for a stream socket that
// never carries datagrams. The type check must therefore reject a non-datagram socket, and this
// test pins that the buffers of a TCP socket are left exactly as they were.
func TestSetDesiredBufferSizesIgnoresNonDatagramSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer listener.Close()
	rawConn := rawConnOf(t, listener.(*net.TCPListener))
	beforeRead, err := inspectReadBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the receive buffer: %s", err)
	}
	if beforeRead == 0 {
		t.Skip("this platform does not expose the socket buffers")
	}
	if isDatagramSocket(rawConn) {
		t.Fatal("a TCP socket must not be detected as a datagram socket")
	}
	beforeWrite, err := inspectWriteBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the send buffer: %s", err)
	}
	SetDesiredBufferSizes(rawConn)
	afterRead, err := inspectReadBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the receive buffer: %s", err)
	}
	afterWrite, err := inspectWriteBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the send buffer: %s", err)
	}
	if afterRead != beforeRead {
		t.Fatalf("the receive buffer of a TCP socket changed from %d to %d", beforeRead, afterRead)
	}
	if afterWrite != beforeWrite {
		t.Fatalf("the send buffer of a TCP socket changed from %d to %d", beforeWrite, afterWrite)
	}
}

// The datagram path must still size the socket. A restricted host can clamp the request (an
// unprivileged Linux process cannot exceed net.core.rmem_max even through SO_RCVBUFFORCE), so
// the assertions are "the request was made and never shrank the buffer" rather than "the full
// 8 MiB was granted"; only a platform that refuses to grow at all is skipped, with the reason
// logged, because that is a property of the host and not of this function.
func TestSetDesiredBufferSizesSizesDatagramSocket(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer conn.Close()
	rawConn := rawConnOf(t, conn)
	beforeRead, err := inspectReadBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the receive buffer: %s", err)
	}
	if beforeRead == 0 {
		t.Skip("this platform does not expose the socket buffers")
	}
	if !isDatagramSocket(rawConn) {
		t.Fatal("a UDP socket must be detected as a datagram socket")
	}
	beforeWrite, err := inspectWriteBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the send buffer: %s", err)
	}
	SetDesiredBufferSizes(rawConn)
	afterRead, err := inspectReadBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the receive buffer: %s", err)
	}
	afterWrite, err := inspectWriteBuffer(rawConn)
	if err != nil {
		t.Fatalf("failed to inspect the send buffer: %s", err)
	}
	if afterRead < beforeRead {
		t.Fatalf("the receive buffer shrank from %d to %d", beforeRead, afterRead)
	}
	if afterWrite < beforeWrite {
		t.Fatalf("the send buffer shrank from %d to %d", beforeWrite, afterWrite)
	}
	if afterRead < protocol.DesiredReceiveBufferSize && afterRead == beforeRead {
		t.Skipf("this host refuses to grow the receive buffer beyond %d bytes", beforeRead)
	}
	if afterWrite < protocol.DesiredSendBufferSize && afterWrite == beforeWrite {
		t.Skipf("this host refuses to grow the send buffer beyond %d bytes", beforeWrite)
	}
	if afterRead < protocol.DesiredReceiveBufferSize {
		t.Logf("the receive buffer was capped at %d bytes by the host", afterRead)
	}
	if afterWrite < protocol.DesiredSendBufferSize {
		t.Logf("the send buffer was capped at %d bytes by the host", afterWrite)
	}
}
