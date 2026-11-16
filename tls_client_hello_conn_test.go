package quic_test

// The server-side TLS callbacks that receive a *tls.ClientHelloInfo are the only place a
// server can see per-connection facts — above all the peer address — while it is still
// choosing which certificate to present, so sing-box's certificate providers and its TLS
// ClientHello sniffer are built on GetConfigForClient and GetCertificate.
//
// crypto/tls does not fill ClientHelloInfo.Conn for QUIC: it is nil there unless the QUIC
// implementation supplies it. quic-go supplies it in two different ways depending on the
// toolchain in force:
//
//   - up to Go 1.26 (internal/handshake/tls_config_go126.go) quic-go replaces both callbacks
//     with wrappers that inject a fake net.Conn carrying the addresses, and re-applies those
//     wrappers recursively to any config returned by GetConfigForClient;
//   - Go 1.27 added tls.QUICConfig.ClientHelloInfoConn, so tls_config_go127.go hands crypto/tls
//     one address holder and wraps nothing.
//
// The two mechanisms are invisible from the outside, which is exactly why they need a test:
// the toolchain in force silently selects one of them, and the failure mode of the newer one
// is a nil Conn rather than a compile error. If ClientHelloInfoConn were dropped from the
// Go 1.27 path, every callback below would receive Conn == nil while the build and the rest
// of the suite stayed green.

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

const clientHelloConnTestALPN = "clienthello-conn-test"

// helloSnapshot is everything this test needs from a ClientHelloInfo. The values are copied
// out inside the callback: a ClientHelloInfo must not be retained past it.
type helloSnapshot struct {
	connNil    bool
	localAddr  string
	remoteAddr string
	serverName string
}

func snapshotHello(info *tls.ClientHelloInfo) helloSnapshot {
	snapshot := helloSnapshot{connNil: info.Conn == nil, serverName: info.ServerName}
	if info.Conn == nil {
		return snapshot
	}
	if addr := info.Conn.LocalAddr(); addr != nil {
		snapshot.localAddr = addr.String()
	}
	if addr := info.Conn.RemoteAddr(); addr != nil {
		snapshot.remoteAddr = addr.String()
	}
	return snapshot
}

func TestServerClientHelloInfoCarriesTheConnection(t *testing.T) {
	certificate := testCertificate(t)

	var (
		mu                     sync.Mutex
		sawConfigCallback      bool
		sawCertificateCallback bool
		configCallbackSnapshot helloSnapshot
		certCallbackSnapshot   helloSnapshot
	)
	serverTLS := &tls.Config{
		NextProtos: []string{clientHelloConnTestALPN},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			configCallbackSnapshot = snapshotHello(info)
			sawConfigCallback = true
			mu.Unlock()
			// The config this callback returns has its own certificate callback. On the
			// pre-1.27 path quic-go has to re-wrap this new config for the fake Conn to
			// reach the second callback; on the 1.27 path crypto/tls does it for every
			// ClientHelloInfo. Either way both callbacks must see the connection.
			return &tls.Config{
				NextProtos: []string{clientHelloConnTestALPN},
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					mu.Lock()
					certCallbackSnapshot = snapshotHello(info)
					sawCertificateCallback = true
					mu.Unlock()
					return &certificate, nil
				},
			}, nil
		},
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type acceptResult struct {
		conn *quic.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		accepted <- acceptResult{conn: conn, err: err}
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{clientHelloConnTestALPN},
		ServerName:         "localhost",
	}
	// Dial through a socket the test owns, so that the client's local address is a concrete
	// 127.0.0.1:port rather than the wildcard [::]:port a DialAddr-created dual-stack socket
	// reports. That makes the server-side RemoteAddr comparable byte for byte.
	clientSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open the client socket: %s", err)
	}
	defer clientSocket.Close()
	transport := &quic.Transport{Conn: clientSocket}
	defer transport.Close()
	clientConn, err := transport.Dial(ctx, listener.Addr(), clientTLS, nil)
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer clientConn.CloseWithError(0, "")

	var serverConn *quic.Conn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("the server never accepted the connection: %s", result.err)
		}
		serverConn = result.conn
	case <-ctx.Done():
		t.Fatal("the server never accepted the connection")
	}
	defer serverConn.CloseWithError(0, "")

	mu.Lock()
	defer mu.Unlock()
	if !sawConfigCallback {
		t.Fatal("GetConfigForClient was never called")
	}
	if !sawCertificateCallback {
		t.Fatal("GetCertificate was never called")
	}
	for _, callback := range []struct {
		name     string
		snapshot helloSnapshot
	}{
		{"GetConfigForClient", configCallbackSnapshot},
		{"GetCertificate", certCallbackSnapshot},
	} {
		name, snapshot := callback.name, callback.snapshot
		if snapshot.connNil {
			t.Fatalf("%s received a ClientHelloInfo with a nil Conn: the toolchain's QUIC "+
				"ClientHelloInfo.Conn plumbing (Go 1.27 tls.QUICConfig.ClientHelloInfoConn, or "+
				"the pre-1.27 callback wrappers) is not reaching this build", name)
		}
		if snapshot.remoteAddr != clientConn.LocalAddr().String() {
			t.Fatalf("%s saw remote address %q, want the client's local address %q",
				name, snapshot.remoteAddr, clientConn.LocalAddr().String())
		}
		if snapshot.localAddr != listener.Addr().String() {
			t.Fatalf("%s saw local address %q, want the server's listening address %q",
				name, snapshot.localAddr, listener.Addr().String())
		}
		if snapshot.serverName != "localhost" {
			t.Fatalf("%s saw ServerName %q, want %q", name, snapshot.serverName, "localhost")
		}
	}
}
