package quic

// The connection-ID runner table belongs to two goroutines: the run loop (attach on a path
// probe, rotate on every new connection ID, expire retired ones, replace all on close) and the
// network-change owner (remove the runner of the transport it is retiring).
//
// This test drives those operations at the level they are implemented, without a connection or a
// socket, so the data race they used to have is reproduced deterministically under -race instead
// of depending on the scheduler happening to interleave a real migration. It is the red/green
// proof for the lock: with RemoveConnRunner deleting outside the lock, -race reports the
// concurrent map access; with it, the test passes.

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/wire"
)

type recordingConnRunner struct {
	adds     int
	removes  int
	replaced int
}

func (r *recordingConnRunner) Add(protocol.ConnectionID, packetHandler) bool {
	r.adds++
	return true
}

func (r *recordingConnRunner) Remove(protocol.ConnectionID) { r.removes++ }

func (r *recordingConnRunner) ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration) {
	r.replaced++
}

func (r *recordingConnRunner) AddResetToken(protocol.StatelessResetToken, packetHandler) {}

func (r *recordingConnRunner) RemoveResetToken(protocol.StatelessResetToken) {}

func newTestConnIDGenerator() *connIDGenerator {
	initial := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	return &connIDGenerator{
		generator:         &protocol.DefaultConnectionIDGenerator{ConnLen: 4},
		activeSrcConnIDs:  map[uint64]protocol.ConnectionID{0: initial},
		connRunners:       make(connRunners),
		statelessResetter: newStatelessResetter(nil),
		queueControlFrame: func(wire.Frame) {},
	}
}

func runnerCallbacks(runner connRunner) connRunnerCallbacks {
	return connRunnerCallbacks{
		AddConnectionID:    func(protocol.ConnectionID) {},
		RemoveConnectionID: func(protocol.ConnectionID) {},
		ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
	}
}

func TestTheConnIDRunnerTableIsSafeToAttachRotateAndRetireConcurrently(t *testing.T) {
	generator := newTestConnIDGenerator()
	// One runner is attached from the start, like the transport a connection is dialed on.
	generator.AddConnRunner(&recordingConnRunner{}, runnerCallbacks(nil))

	const iterations = 300
	var waitGroup sync.WaitGroup
	start := make(chan struct{})

	// The run loop: rotate a connection ID and expire a retired one.
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				generator.addConnectionID(protocol.ParseConnectionID([]byte{1, 2, 3, 4}))
				generator.removeConnectionID(protocol.ParseConnectionID([]byte{4, 3, 2, 1}))
			}
		}()
	}

	// A second path probe: attach a runner and let the connection IDs reach it.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		<-start
		for iteration := 0; iteration < iterations; iteration++ {
			runner := &recordingConnRunner{}
			generator.AddConnRunner(runner, runnerCallbacks(runner))
			generator.addConnectionID(protocol.ParseConnectionID([]byte{5, 5, 5, 5}))
		}
	}()

	// The network-change owner: retire a transport while all of the above runs.
	for index := 0; index < 2; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				retired := &recordingConnRunner{}
				generator.AddConnRunner(retired, runnerCallbacks(retired))
				generator.RemoveConnRunner(retired)
			}
		}()
	}

	close(start)
	waitGroup.Wait()

	// A retired runner must not be in the table afterwards: that is the property that keeps a
	// rotation from re-registering the connection on a socket that is about to be closed.
	retired := &recordingConnRunner{}
	generator.AddConnRunner(retired, runnerCallbacks(retired))
	generator.RemoveConnRunner(retired)
	generator.runnerMu.Lock()
	_, stillRegistered := generator.connRunners[retired]
	generator.runnerMu.Unlock()
	if stillRegistered {
		t.Fatal("a retired runner was left in the table")
	}
}

func TestRemovingAnUnknownRunnerIsANoOp(t *testing.T) {
	generator := newTestConnIDGenerator()
	generator.RemoveConnRunner(&recordingConnRunner{})
	if len(generator.connRunners) != 0 {
		t.Fatalf("the table has %d entries after removing an unknown runner", len(generator.connRunners))
	}
}
