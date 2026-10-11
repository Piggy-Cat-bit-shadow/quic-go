package quic

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

// The first-datagram measurement for the hard ceiling.
//
// The config-level tests next to config.go establish the ORDER the ceiling is
// applied in. They cannot establish that the clamped value is what leaves the
// socket, and the difference matters: a future change could clamp a local
// variable that the packet packer never reads. This test measures the datagram
// instead of the field.
//
// # What makes the number observable
//
// A client pads its Initial packet to the connection's maximum packet size
// (packet_packer.go initialPaddingLen pads to maxPacketSize, and connection.go
// maxPacketSize returns config.InitialPacketSize on the client while
// mtuDiscoverer is nil, i.e. before any server transport parameters have been
// processed). The first datagram handed to the socket is therefore a single
// Initial packet padded to exactly that size. The peer is deliberately silent -
// nothing answers, no handshake completes - so no later packet can be mistaken
// for the first.
//
// recordingPacketConn implements only net.PacketConn. With no SyscallConn method
// quic-go cannot take the OOB/GSO path, so every packet goes through WriteTo and
// len(p) is the real UDP payload length.

const (
	ceilingFirstWriteWatchdog = 10 * time.Second
	ceilingDialExitWatchdog   = 10 * time.Second
)

type ceilingPacketRecorder struct {
	conn net.PacketConn

	once       sync.Once
	firstWrite chan struct{}

	mu      sync.Mutex
	sizes   []int
	initial []byte
}

func newCeilingPacketRecorder(conn net.PacketConn) *ceilingPacketRecorder {
	return &ceilingPacketRecorder{conn: conn, firstWrite: make(chan struct{})}
}

func (c *ceilingPacketRecorder) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	first := len(c.sizes) == 0
	c.sizes = append(c.sizes, len(p))
	if first {
		head := len(p)
		if head > 64 {
			head = 64
		}
		c.initial = append([]byte(nil), p[:head]...)
	}
	c.mu.Unlock()
	if first {
		c.once.Do(func() { close(c.firstWrite) })
	}
	return c.conn.WriteTo(p, addr)
}

func (c *ceilingPacketRecorder) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.conn.ReadFrom(p)
}

func (c *ceilingPacketRecorder) Close() error                      { return c.conn.Close() }
func (c *ceilingPacketRecorder) LocalAddr() net.Addr               { return c.conn.LocalAddr() }
func (c *ceilingPacketRecorder) SetDeadline(t time.Time) error     { return c.conn.SetDeadline(t) }
func (c *ceilingPacketRecorder) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }
func (c *ceilingPacketRecorder) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *ceilingPacketRecorder) snapshot() (sizes []int, initial []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.sizes...), append([]byte(nil), c.initial...)
}

// measureFirstDatagramWithCeiling dials once and returns the length of the first
// datagram, plus its first bytes so the caller can check that the datagram really
// is one client Initial packet.
func measureFirstDatagramWithCeiling(t *testing.T, config *Config) (int, []byte, []int) {
	t.Helper()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "listen loopback UDP")
	recorder := newCeilingPacketRecorder(udpConn)

	ctx, cancel := context.WithCancel(context.Background())
	dialDone := make(chan error, 1)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // no peer certificate exists to verify
		NextProtos:         []string{"h3"},
	}
	config.HandshakeIdleTimeout = 500 * time.Millisecond

	go func() {
		conn, dialErr := DialEarly(ctx, recorder, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, tlsConfig, config)
		if conn != nil {
			_ = conn.CloseWithError(0, "")
		}
		dialDone <- dialErr
	}()

	select {
	case <-recorder.firstWrite:
	case <-time.After(ceilingFirstWriteWatchdog):
		cancel()
		_ = udpConn.Close()
		t.Fatal("no datagram reached WriteTo within the watchdog; the measurement never happened")
	}

	cancel()
	_ = udpConn.Close()
	select {
	case <-dialDone:
	case <-time.After(ceilingDialExitWatchdog):
		t.Error("the DialEarly goroutine did not exit after the context was cancelled and the socket closed")
	}

	sizes, initial := recorder.snapshot()
	if len(sizes) == 0 {
		t.Fatal("the first write was signalled but no write was recorded")
	}
	t.Logf("config: InitialPacketSize=%d ceiling=%d ChromeParrot=%v -> first datagram %d bytes; all datagrams: %v",
		config.InitialPacketSize, config.InitialPacketSizeCeiling, config.ChromeParrot, sizes[0], sizes)
	return sizes[0], initial, sizes
}

// TestCeilingReachesTheWire is the measurement the feature is judged by: the
// ceiling is what leaves the socket, with ChromeParrot on - the configuration
// hysteria2 uses by default, and the one where the previous design could not
// reach the wire at all.
func TestCeilingReachesTheWire(t *testing.T) {
	size, head, _ := measureFirstDatagramWithCeiling(t, &Config{
		InitialPacketSize:        1232,
		InitialPacketSizeCeiling: 1232,
		ChromeParrot:             true,
	})
	require.Equal(t, 1232, size,
		"a 1232-byte ceiling with ChromeParrot on must put 1232-byte datagrams on the wire, not "+
			"%d: the ceiling is applied after the fingerprint override", chromeInitialPacketSize)

	// Independent corroboration that the ChromeParrot branch itself still ran,
	// rather than something else happening to produce 1232: that branch also fixes
	// the initial destination connection ID at 8 bytes and the source connection ID
	// at 0. If the ceiling had been implemented by turning ChromeParrot off, these
	// would be wrong - and the fingerprint would have been silently traded away.
	dcidLen, scidLen, ok := parseInitialConnectionIDLengths(head)
	require.True(t, ok, "could not parse the connection ID lengths of the first datagram: % x", head)
	require.Equal(t, 8, dcidLen, "the ceiling must not cost the Chrome fingerprint: destination connection ID")
	require.Equal(t, 0, scidLen, "the ceiling must not cost the Chrome fingerprint: source connection ID")
}

// TestCeilingAboveTheFingerprintSizeLeavesItAlone is the other direction, and it
// is what makes the field a ceiling rather than a target: a path proven to carry
// 1252 bytes must not push a 1250-byte fingerprint up to 1252.
func TestCeilingAboveTheFingerprintSizeLeavesItAlone(t *testing.T) {
	size, _, _ := measureFirstDatagramWithCeiling(t, &Config{
		InitialPacketSize:        1232,
		InitialPacketSizeCeiling: 1252,
		ChromeParrot:             true,
	})
	require.Equal(t, chromeInitialPacketSize, size,
		"a ceiling above the fingerprint size is a maximum, not a target")
}

// TestCeilingBelowTheMinimumWouldBeUnusable documents the boundary instead of
// leaving it to be discovered: an Initial packet cannot be smaller than 1200
// bytes, so a ceiling below that cannot be honoured, and the library must not
// pretend otherwise by silently raising it. The caller is responsible for
// refusing such a path - sing-box does, with an error that names the tunnel MTU.
func TestCeilingBelowTheMinimumWouldBeUnusable(t *testing.T) {
	config := populateConfig(&Config{
		InitialPacketSize:        1232,
		InitialPacketSizeCeiling: 1100,
	})
	require.Equal(t, uint16(1100), config.InitialPacketSize,
		"populateConfig applies the ceiling as written and does not invent capacity; raising it to "+
			"the 1200 minimum here would send a packet the caller proved the path cannot carry")
	require.Less(t, config.InitialPacketSize, uint16(protocol.MinInitialPacketSize),
		"this fixture must actually be below the minimum, or the boundary it documents is not the one under test")
}

// parseInitialConnectionIDLengths reads the destination and source connection ID
// lengths out of the start of a long header packet.
func parseInitialConnectionIDLengths(head []byte) (dcidLen, scidLen int, ok bool) {
	if len(head) < 7 || head[0]&0x80 == 0 || head[0]&0x40 == 0 {
		return 0, 0, false
	}
	dcidLen = int(head[5])
	offset := 6 + dcidLen
	if offset >= len(head) {
		return 0, 0, false
	}
	return dcidLen, int(head[offset]), true
}
