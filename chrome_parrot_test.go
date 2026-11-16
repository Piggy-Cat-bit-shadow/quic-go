package quic_test

// ChromeParrot is this fork's ability to emit a Chrome-like ClientHello through uTLS instead
// of crypto/tls. Go 1.27 changed the ground under it in a way that is easy to miss: quic-go's
// Go 1.27 TLS setup path (internal/handshake/tls_config_go127.go) stops forcing
// tls.Config.MinVersion = TLS 1.3, because crypto/tls now filters QUIC down to TLS 1.3 inside
// supportedVersions. The uTLS path does not go through crypto/tls at all, so it only keeps
// speaking TLS 1.3 because utlsConfigFromStd pins MinVersion and MaxVersion itself, and because
// uTLS's QUIC implementation refuses a config below TLS 1.3.
//
// Nothing else in the suite dials with ChromeParrot enabled: the existing ChromeParrot tests
// only check that the flag reaches populateConfig and the wire sizing. A regression in the uTLS
// adapter or a loosened TLS version floor would therefore only surface in production, as a
// handshake failure rather than a build error. This test dials for real.

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

const chromeParrotTestALPN = "chrome-parrot-test"

func TestChromeParrotClientCompletesAHandshake(t *testing.T) {
	certificate := testCertificate(t)

	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{chromeParrotTestALPN},
	}, nil)
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The server must keep the connection open until the client has actually read the reply:
	// closing it right after stream.Close() discards the "pong" that is still in flight and
	// turns the test into a race against the network (observed as "Application error 0x0
	// (remote)" in the client's read).
	releaseServer := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
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

	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{chromeParrotTestALPN},
		ServerName:         "localhost",
	}, &quic.Config{ChromeParrot: true})
	if err != nil {
		t.Fatalf("the ChromeParrot client could not complete a handshake: %s", err)
	}
	defer client.CloseWithError(0, "")

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
