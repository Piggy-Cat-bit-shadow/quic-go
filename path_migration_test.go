package quic_test

// Acceptance test for client-initiated path migration on this fork.
//
// It exercises the two things this change is about, end to end on real loopback sockets:
//
//  1. a candidate path on a second socket can be validated. This needs AddPath to initialize
//     the path transport with the connection's own connection ID length: a single-use dial
//     transport uses zero-length source connection IDs, and a path transport that assumes
//     the default length parses the first payload bytes as a destination connection ID and
//     drops every packet on that path as unknown - so Path.Probe never sees its response.
//  2. after Switch, ONE connection and ONE already-open stream keep carrying data: no new
//     handshake, no new stream, sequence unbroken.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func testTLSConfig(certificate tls.Certificate, server bool) *tls.Config {
	config := &tls.Config{NextProtos: []string{"path-migration-test"}}
	if server {
		config.Certificates = []tls.Certificate{certificate}
	} else {
		config.InsecureSkipVerify = true
	}
	return config
}

func readMessage(stream *quic.Stream) ([]byte, error) {
	header := make([]byte, 1)
	if _, err := io.ReadFull(stream, header); err != nil {
		return nil, err
	}
	payload := make([]byte, header[0])
	if _, err := io.ReadFull(stream, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeMessage(stream *quic.Stream, payload []byte) error {
	_, err := stream.Write(append([]byte{byte(len(payload))}, payload...))
	return err
}

func TestMigrateKeepsOneConnectionAndOneStream(t *testing.T) {
	certificate := testCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", testTLSConfig(certificate, true), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var connections atomic.Int32
	accepted := make(chan *quic.Conn, 1)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			connections.Add(1)
			select {
			case accepted <- conn:
			default:
			}
		}
	}()

	primary, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := quic.Dial(ctx, primary, listener.Addr(), testTLSConfig(certificate, false), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	var serverConn *quic.Conn
	select {
	case serverConn = <-accepted:
	case <-ctx.Done():
		t.Fatal("the endpoint never accepted the connection")
	}
	defer serverConn.CloseWithError(0, "")

	// One stream, read by the endpoint in order.
	received := make(chan []byte, 8)
	go func() {
		stream, err := serverConn.AcceptStream(ctx)
		if err != nil {
			return
		}
		for {
			message, err := readMessage(stream)
			if err != nil {
				return
			}
			received <- message
		}
	}()

	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	expect := func(want string) {
		t.Helper()
		select {
		case got := <-received:
			if string(got) != want {
				t.Fatalf("endpoint received %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("endpoint never received %q", want)
		}
	}

	if err = writeMessage(stream, []byte("before")); err != nil {
		t.Fatal(err)
	}
	expect("before")

	// The second real path: its own socket and transport, the same connection.
	candidate, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()
	path, err := conn.AddPath(&quic.Transport{Conn: candidate})
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if err = path.Probe(ctx); err != nil {
		t.Fatalf("probe: %v (a zero-length-connection-ID dial transport must be usable as a path)", err)
	}
	if err = path.Switch(); err != nil {
		t.Fatalf("switch: %v", err)
	}

	// The same connection and the same stream carry on.
	if err = writeMessage(stream, []byte("after-switch")); err != nil {
		t.Fatalf("write on the migrated stream: %v", err)
	}
	expect("after-switch")
	if err = writeMessage(stream, []byte("still-here")); err != nil {
		t.Fatal(err)
	}
	expect("still-here")

	if got := connections.Load(); got != 1 {
		t.Fatalf("the endpoint saw %d connections, want 1: the switch must not reconnect", got)
	}
	if conn.Context().Err() != nil {
		t.Fatalf("the connection ended: %v", conn.Context().Err())
	}
}
