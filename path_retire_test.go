package quic_test

// Retirement and repeated migration on this fork.
//
// A migrated connection does not only have to survive one switch: a phone changes networks more
// than once, so path A -> B -> C has to leave exactly one live transport (C), with A and B
// physically closed by their owner, and the already-open stream still carrying data.
//
// The properties pinned here are the ones the production wiring depends on:
//
//   - retirement waits for the switch the run loop actually installed, and it is compared with
//     THIS transport: a stale or different applied path can neither satisfy the wait nor be
//     mistaken for the candidate the call is about;
//   - the transport the connection is sending on cannot be retired (ErrPathActive when nothing
//     migrated, deadline when the wait outlives the caller's bound);
//   - retirement is idempotent and the socket owner closes each socket exactly once;
//   - concurrent retirements, while the run loop keeps rotating connection IDs for new paths,
//     are race-free (this is what the runner-table lock is for);
//   - a candidate that never validates (black hole) and a candidate abandoned late disturb
//     neither the live path nor the stream.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
)

// countingPacketConn counts Close calls so "the socket is closed exactly once" is observable.
type countingPacketConn struct {
	net.PacketConn
	closes atomic.Int32
}

func (c *countingPacketConn) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// silentPacketConn swallows writes: a candidate path on it can never be validated.
type silentPacketConn struct {
	net.PacketConn
}

func (c *silentPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

// retireServer echoes every framed message back on the same stream and counts connections.
type retireServer struct {
	listener *quic.Listener
	addr     net.Addr
	accepted atomic.Int32
	streams  atomic.Int32
}

func startRetireServer(t *testing.T) *retireServer {
	t.Helper()
	listener, err := quic.ListenAddr("127.0.0.1:0", testTLSConfig(testCertificate(t), true), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := &retireServer{listener: listener, addr: listener.Addr()}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept(context.Background())
			if acceptErr != nil {
				return
			}
			server.accepted.Add(1)
			go func() {
				for {
					stream, streamErr := conn.AcceptStream(context.Background())
					if streamErr != nil {
						return
					}
					server.streams.Add(1)
					go func() {
						for {
							message, readErr := readMessage(stream)
							if readErr != nil {
								return
							}
							if writeErr := writeMessage(stream, message); writeErr != nil {
								return
							}
						}
					}()
				}
			}()
		}
	}()
	return server
}

// echo sends one message on the stream and requires the endpoint to echo it back. It proves the
// stream still carries both directions, not merely that a write was accepted locally.
func echo(t *testing.T, stream *quic.Stream, message string) {
	t.Helper()
	if err := writeMessage(stream, []byte(message)); err != nil {
		t.Fatalf("write %q: %v", message, err)
	}
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := readMessage(stream)
	if err != nil {
		t.Fatalf("the endpoint never echoed %q: %v", message, err)
	}
	if string(got) != message {
		t.Fatalf("echoed %q, want %q", got, message)
	}
}

// dialThroughTransport dials through a Transport the test keeps, because that object is what
// RetireTransport takes: the owner of the handshake socket retires it by name.
func dialThroughTransport(t *testing.T, ctx context.Context, server net.Addr) (*quic.Conn, *countingPacketConn, *quic.Transport) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingPacketConn{PacketConn: socket}
	transport := &quic.Transport{Conn: counting}
	conn, err := transport.Dial(ctx, server, testTLSConfig(testCertificate(t), false), &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn.HandshakeTransport() != transport {
		t.Fatal("the connection does not report the transport it was dialed on")
	}
	return conn, counting, transport
}

// addRealPath creates a second real socket, attaches it as a path and validates it.
func addRealPath(t *testing.T, ctx context.Context, conn *quic.Conn) (*quic.Path, *countingPacketConn, *quic.Transport) {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingPacketConn{PacketConn: socket}
	transport := &quic.Transport{Conn: counting}
	path, err := conn.AddPath(transport)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	if err := path.Probe(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
	return path, counting, transport
}

// TestMigratingTwiceClosesEveryRetiredSocketExactlyOnce is path A -> B -> C on one connection
// and one already-open stream. Each retired socket is closed by its owner exactly once, the
// retirement is a wait on the applied state, and the stream keeps carrying both directions.
func TestMigratingTwiceClosesEveryRetiredSocketExactlyOnce(t *testing.T) {
	server := startRetireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, primaryCloses, primaryTransport := dialThroughTransport(t, ctx, server.addr)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "before-any-migration")

	// A -> B
	pathB, pathBCloses, pathBTransport := addRealPath(t, ctx, conn)
	if err := pathB.Switch(); err != nil {
		t.Fatalf("switch to B: %v", err)
	}
	if err := conn.RetireTransport(ctx, primaryTransport); err != nil {
		t.Fatalf("retire A: %v", err)
	}
	if conn.Context().Err() != nil {
		t.Fatalf("retiring A ended the connection: %v", conn.Context().Err())
	}
	if err := primaryCloses.Close(); err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "after-retiring-A")

	// B -> C
	pathC, pathCCloses, pathCTransport := addRealPath(t, ctx, conn)
	if err := pathC.Switch(); err != nil {
		t.Fatalf("switch to C: %v", err)
	}
	if err := conn.RetireTransport(ctx, pathBTransport); err != nil {
		t.Fatalf("retire B: %v", err)
	}
	echo(t, stream, "after-retiring-B")

	// Now really close B's socket: the connection must not notice.
	if err := pathBCloses.Close(); err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "after-closing-B")

	// Every socket that was retired is closed exactly once by its owner, and the applied one is
	// still open and untouched.
	if got := primaryCloses.closes.Load(); got != 1 {
		t.Fatalf("the handshake socket was closed %d times, want 1", got)
	}
	if got := pathBCloses.closes.Load(); got != 1 {
		t.Fatalf("the first path socket was closed %d times, want 1", got)
	}
	if got := pathCCloses.closes.Load(); got != 0 {
		t.Fatalf("the applied path socket was closed %d times, want 0", got)
	}

	// The connection never reconnected and never opened a second stream.
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("the endpoint saw %d connections, want 1", got)
	}
	if got := server.streams.Load(); got != 1 {
		t.Fatalf("the endpoint saw %d streams, want 1", got)
	}
	// Retiring an already retired transport is a no-op, not a second detach.
	if err := conn.RetireTransport(ctx, primaryTransport); err != nil {
		t.Fatalf("repeated retirement: %v", err)
	}

	// The applied path is refused by its own bound: this is the comparison against THIS
	// transport, not against "some switch is applied".
	bounded, boundedCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer boundedCancel()
	if err := conn.RetireTransport(bounded, pathCTransport); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retiring the applied path returned %v, want the caller's deadline", err)
	}
	echo(t, stream, "after-the-refused-retirement-of-C")

	// C's socket is closed last, by its owner, and the already-closed A and B sockets stay at
	// one close each.
	if err := pathCCloses.Close(); err != nil {
		t.Fatal(err)
	}
	if got := pathCCloses.closes.Load(); got != 1 {
		t.Fatalf("the applied path socket was closed %d times after the final close, want 1", got)
	}
}

// TestRetireRefusesTheTransportTheConnectionStillSendsOn pins the confirmation the retirement
// wait performs: it compares against THIS transport, not against "some switch has been applied".
//
// The negative half matters because a naive wait on "appliedPath != 0" would let a caller retire
// the path it just switched TO, tearing down the live send path while every earlier assertion
// (one connection, one stream) still passed.
func TestRetireRefusesTheTransportTheConnectionStillSendsOn(t *testing.T) {
	server := startRetireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, primaryCloses, primaryTransport := dialThroughTransport(t, ctx, server.addr)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "before")

	// No migration yet: the handshake transport IS the send path.
	if err := conn.RetireTransport(ctx, primaryTransport); !errors.Is(err, quic.ErrPathActive) {
		t.Fatalf("retiring the send path without a migration returned %v, want ErrPathActive", err)
	}
	echo(t, stream, "still-on-the-handshake-path")

	pathB, _, pathBTransport := addRealPath(t, ctx, conn)
	if err := pathB.Switch(); err != nil {
		t.Fatalf("switch to B: %v", err)
	}
	if err := conn.RetireTransport(ctx, primaryTransport); err != nil {
		t.Fatalf("retire the handshake transport: %v", err)
	}

	// B is applied. Retiring it must time out instead of detaching, and the bound is the caller's.
	bounded, boundedCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer boundedCancel()
	if err := conn.RetireTransport(bounded, pathBTransport); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retiring the applied path returned %v, want its own deadline", err)
	}
	echo(t, stream, "after-the-refused-retirement")

	// The refused call changed nothing: A is still retired, B still carries the connection.
	if err := conn.RetireTransport(ctx, primaryTransport); err != nil {
		t.Fatalf("repeated retirement of A: %v", err)
	}
	if err := primaryCloses.Close(); err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "after-closing-A")
}

// TestRepeatedMigrationStopsAtTheConnectionIDBudget characterises how many times one connection
// can be moved with this pin's default connection-ID budget, and pins that running out is a
// bounded, local failure.
//
// Every migration consumes one connection ID from each peer's advertised pool, and the budget is
// what the peer advertises (protocol.MaxActiveConnectionIDs, 4) capped by what this side issues
// (protocol.MaxIssuedConnectionIDs, 6). With the default budget two migrations validate and the
// third candidate cannot be validated: the endpoint has no connection ID left to probe the new
// path with, so it never answers, the probe ends at its own deadline, and the connection keeps
// working on the last path that was applied.
//
// A -> B -> C therefore works, which is what the window's acceptance asks for, and a further move
// degrades to "stay where you are" instead of breaking the connection. Raising the advertised
// budget moves the boundary (eight active IDs validate five moves), so this test asserts the floor
// the production policy relies on rather than an exact number.
func TestRepeatedMigrationStopsAtTheConnectionIDBudget(t *testing.T) {
	server := startRetireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, primaryCloses, primaryTransport := dialThroughTransport(t, ctx, server.addr)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "before-the-migrations")

	previousTransport := primaryTransport
	previousSocket := primaryCloses
	var previousPath *quic.Path // nil: the handshake path has no Path object
	applied := 0
	const attempts = 6
	for round := 0; round < attempts; round++ {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		counting := &countingPacketConn{PacketConn: socket}
		candidateTransport := &quic.Transport{Conn: counting}
		path, err := conn.AddPath(candidateTransport)
		if err != nil {
			t.Fatalf("round %d: AddPath: %v", round, err)
		}
		probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
		err = path.Probe(probeCtx)
		probeCancel()
		if err != nil {
			// The budget is spent: the endpoint cannot answer a probe for this path. Closing the
			// path detaches the candidate and the socket can be released.
			if closeErr := path.Close(); closeErr != nil {
				t.Fatalf("round %d: closing the abandoned candidate: %v", round, closeErr)
			}
			if closeErr := counting.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			t.Logf("migration %d could not be validated (%v) after %d applied moves", round+1, err, applied)
			break
		}
		if err := path.Switch(); err != nil {
			t.Fatalf("round %d: switch: %v", round, err)
		}
		if err := conn.RetireTransport(ctx, previousTransport); err != nil {
			t.Fatalf("round %d: retire the previous transport: %v", round, err)
		}
		if err := previousSocket.Close(); err != nil {
			t.Fatal(err)
		}
		if previousPath != nil {
			// Closing the path object gives the path's connection ID back.
			if err := previousPath.Close(); err != nil {
				t.Fatalf("round %d: close the previous path: %v", round, err)
			}
		}
		previousTransport = candidateTransport
		previousSocket = counting
		previousPath = path
		applied++
		echo(t, stream, fmt.Sprintf("after-move-%d", applied))
	}

	if applied < 2 {
		t.Fatalf("only %d migrations validated: A -> B -> C must be available on this pin", applied)
	}
	// Whatever the budget was, the connection is still one connection and the stream still carries
	// bytes on the last applied path.
	echo(t, stream, "after-the-last-applied-path")
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("the endpoint saw %d connections, want 1: repeated migration must not reconnect", got)
	}
}

// TestConcurrentRetireWithCIDRotationIsRaceFree drives the runner-table access from both sides at
// once: migrations attach runners and rotate connection IDs on the run loop while several
// goroutines retire the handshake transport. Run under -race.
func TestConcurrentRetireWithCIDRotationIsRaceFree(t *testing.T) {
	server := startRetireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, primaryCloses, primaryTransport := dialThroughTransport(t, ctx, server.addr)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "before")

	// One real path is applied first, so the retirement is allowed to proceed.
	pathB, _, _ := addRealPath(t, ctx, conn)
	if err := pathB.Switch(); err != nil {
		t.Fatalf("switch to B: %v", err)
	}

	var waitGroup sync.WaitGroup
	var streamAccess sync.Mutex
	start := make(chan struct{})
	retireErrors := make(chan error, 8)
	for index := 0; index < 6; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			switch index % 3 {
			case 0:
				retireErrors <- conn.RetireTransport(ctx, primaryTransport)
			case 1:
				// Attach a candidate and let the run loop issue a connection ID for it: that
				// adds the runner and rotates the connection ID table, which is the other
				// writer the retirement removes from. The candidate is a black hole, so the
				// probe is expected to end at its own bound; what this iteration must prove is
				// that the retirement and the rotation do not corrupt each other.
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					retireErrors <- err
					return
				}
				counting := &countingPacketConn{PacketConn: &silentPacketConn{PacketConn: socket}}
				path, err := conn.AddPath(&quic.Transport{Conn: counting})
				if err != nil {
					retireErrors <- err
					return
				}
				probeCtx, probeCancel := context.WithTimeout(ctx, 400*time.Millisecond)
				defer probeCancel()
				if err := path.Probe(probeCtx); !errors.Is(err, context.DeadlineExceeded) {
					retireErrors <- fmt.Errorf("probe of a black-hole candidate returned %w, want its deadline", err)
					return
				}
				if err := path.Close(); err != nil {
					retireErrors <- err
					return
				}
				_ = counting.Close()
				retireErrors <- nil
			case 2:
				// A plain reader: a retirement that detached the live transport would show up
				// here as a dead stream. One stream, so the echo helper is serialized.
				streamAccess.Lock()
				echo(t, stream, fmt.Sprintf("during-the-concurrent-retirements-%d", index))
				streamAccess.Unlock()
				retireErrors <- nil
			}
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(retireErrors)
	for err := range retireErrors {
		if err != nil {
			t.Fatalf("concurrent migration/retirement failed: %v", err)
		}
	}

	if err := primaryCloses.Close(); err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "after-the-concurrent-retirements")
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("the endpoint saw %d connections, want 1", got)
	}
}

// TestBlackholeCandidateLeavesTheLivePathAlone is the candidate-failure side: a path whose socket
// swallows every packet can never validate, and its failure must not disturb the connection, the
// stream, or the path the connection is using.
func TestBlackholeCandidateLeavesTheLivePathAlone(t *testing.T) {
	server := startRetireServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, _, _ := dialThroughTransport(t, ctx, server.addr)
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	echo(t, stream, "before-the-candidate")

	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	path, err := conn.AddPath(&quic.Transport{Conn: &silentPacketConn{PacketConn: socket}})
	if err != nil {
		t.Fatalf("AddPath on a black hole: %v", err)
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer probeCancel()
	if err := path.Probe(probeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("probe on a black hole returned %v, want its deadline", err)
	}
	echo(t, stream, "after-the-failed-candidate")
	if err := path.Close(); err != nil {
		t.Fatalf("closing the failed candidate: %v", err)
	}
	echo(t, stream, "after-closing-the-candidate")
	if got := server.accepted.Load(); got != 1 {
		t.Fatalf("the endpoint saw %d connections, want 1", got)
	}
}
