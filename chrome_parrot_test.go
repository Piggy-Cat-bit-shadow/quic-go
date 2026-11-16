package quic_test

// ChromeParrot is this fork's ability to emit a Chrome-like ClientHello through uTLS instead
// of crypto/tls. Two independent things have to stay true for it to be worth having:
//
//  1. the flag has to reach the TLS layer at all, and
//  2. the handshake built on that ClientHello has to work under the Go version in force.
//
// (2) is what Go 1.27 made non-obvious: the Go 1.27 TLS setup path
// (internal/handshake/tls_config_go127.go) stops forcing tls.Config.MinVersion = TLS 1.3,
// because crypto/tls now filters QUIC down to TLS 1.3 itself. The uTLS path never goes
// through crypto/tls, so it only keeps speaking TLS 1.3 because utlsConfigFromStd pins
// MinVersion and MaxVersion, and because uTLS's own QUIC code refuses a lower config.
//
// (1) is the subtle half, and it is why this test makes TWO handshakes. The Chrome QUIC
// ClientHello deliberately carries the same three TLS 1.3 cipher suites as crypto/tls and
// no GREASE (see internal/handshake/chrome_client_hello.go), so a client that silently fell
// back to crypto/tls would still produce TLS 1.3, the same ALPN and a working stream: every
// assertion a naive version of this test makes would stay green while the fingerprint was
// gone. The discriminator used here is an extension only the fork's Chrome spec sends, the
// trust_anchors extension (0xca34), compared against a plain client dialing the same server.
// If Config.ChromeParrot ever stops reaching the TLS layer - for example because
// populateConfig stops copying it - the parrot ClientHello becomes identical to the plain
// one and this test fails.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

const chromeParrotTestALPN = "chrome-parrot-test"

// chromeOnlyExtensionIDs are extension IDs that the fork's Chrome QUIC ClientHello sends and
// that a plain crypto/tls ClientHello does not: trust_anchors (0xca34, sent as a raw generic
// extension in internal/handshake/chrome_client_hello.go), application_settings / ALPS
// (0x44cd), compress_certificate (0x1b) and encrypted_client_hello (0xfe0d). The test accepts
// any one of them as proof that the Chrome spec produced this ClientHello, and it re-derives
// that proof per run by checking the same ID is absent from the plain client, so a future
// stdlib that starts parsing or sending one of them cannot turn this into a false positive.
var chromeOnlyExtensionIDs = []uint16{0xca34, 0x44cd, 0x1b, 0xfe0d}

func TestChromeParrotClientCompletesAHandshake(t *testing.T) {
	certificate := testCertificate(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// newServer starts a server that records the extension IDs of every ClientHello it sees.
	newServer := func() (*quic.Listener, <-chan []uint16) {
		t.Helper()
		hellos := make(chan []uint16, 4)
		listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{chromeParrotTestALPN},
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				hellos <- slices.Clone(info.Extensions)
				return nil, nil
			},
		}, nil)
		if err != nil {
			t.Fatalf("failed to listen: %s", err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener, hellos
	}

	dial := func(addr net.Addr, chromeParrot bool) *quic.Conn {
		t.Helper()
		var config *quic.Config
		if chromeParrot {
			config = &quic.Config{ChromeParrot: true}
		}
		conn, err := quic.DialAddr(ctx, addr.String(), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{chromeParrotTestALPN},
			ServerName:         "localhost",
		}, config)
		if err != nil {
			t.Fatalf("handshake failed (chromeParrot=%v): %s", chromeParrot, err)
		}
		t.Cleanup(func() { conn.CloseWithError(0, "") })
		return conn
	}

	waitForHello := func(hellos <-chan []uint16, what string) []uint16 {
		t.Helper()
		select {
		case extensions := <-hellos:
			return extensions
		case <-ctx.Done():
			t.Fatalf("the server never saw the %s ClientHello", what)
			return nil
		}
	}

	// 1. Baseline: the same library without the flag. Only the ClientHello is needed.
	plainListener, plainHellos := newServer()
	go func() {
		if conn, err := plainListener.Accept(ctx); err == nil {
			conn.CloseWithError(0, "")
		}
	}()
	dial(plainListener.Addr(), false)
	plainExtensions := waitForHello(plainHellos, "plain")

	// 2. ChromeParrot: handshake, TLS parameters and a stream round trip.
	parrotListener, parrotHellos := newServer()

	// The server must keep the connection open until the client has actually read the reply:
	// closing it right after stream.Close() discards the in-flight "pong" and turns the test
	// into a race against the network (observed as "Application error 0x0 (remote)").
	releaseServer := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := parrotListener.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.CloseWithError(0, "")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		payload := make([]byte, 4)
		if _, err := io.ReadFull(stream, payload); err != nil {
			serverDone <- err
			return
		}
		if _, err := stream.Write([]byte("pong")); err != nil {
			serverDone <- err
			return
		}
		if err := stream.Close(); err != nil {
			serverDone <- err
			return
		}
		select {
		case <-releaseServer:
		case <-ctx.Done():
		}
		serverDone <- nil
	}()

	client := dial(parrotListener.Addr(), true)
	parrotExtensions := waitForHello(parrotHellos, "ChromeParrot")

	// The flag must have changed the ClientHello, not just the connection settings. Every
	// marker is checked against the plain client in the same run, so a marker that crypto/tls
	// also sends is simply not counted instead of becoming a false positive.
	var provenBy []uint16
	for _, marker := range chromeOnlyExtensionIDs {
		if slices.Contains(parrotExtensions, marker) && !slices.Contains(plainExtensions, marker) {
			provenBy = append(provenBy, marker)
		}
	}
	if len(provenBy) == 0 {
		t.Fatalf("nothing in the ChromeParrot ClientHello distinguishes it from the plain crypto/tls one "+
			"(parrot extensions: %#v, plain extensions: %#v): the Chrome fingerprint is missing, which "+
			"means the ChromeParrot flag is not reaching the TLS layer", parrotExtensions, plainExtensions)
	}
	if slices.Equal(plainExtensions, parrotExtensions) {
		t.Fatalf("the ChromeParrot and plain ClientHellos are identical (%#v): "+
			"ChromeParrot fell back to crypto/tls silently", parrotExtensions)
	}
	t.Logf("ChromeParrot ClientHello proven by extensions %#v", provenBy)

	state := client.ConnectionState().TLS
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("the ChromeParrot client negotiated TLS version %#x, want TLS 1.3 (%#x): "+
			"QUIC requires TLS 1.3, and the version floor now has to be enforced by the uTLS "+
			"adapter rather than by quic-go's crypto/tls setup", state.Version, tls.VersionTLS13)
	}
	if state.NegotiatedProtocol != chromeParrotTestALPN {
		t.Fatalf("negotiated ALPN %q, want %q", state.NegotiatedProtocol, chromeParrotTestALPN)
	}

	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("failed to open a stream: %s", err)
	}
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("failed to write: %s", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("failed to read the echo: %s", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("echo mismatch: got %q, want %q", reply, "pong")
	}
	close(releaseServer)
	if err := <-serverDone; err != nil {
		t.Fatalf("server side failed: %s", err)
	}
}
