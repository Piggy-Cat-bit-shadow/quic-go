package quic

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/qerr"
	"github.com/sagernet/quic-go/internal/wire"
)

type connRunnerCallbacks struct {
	AddConnectionID    func(protocol.ConnectionID)
	RemoveConnectionID func(protocol.ConnectionID)
	ReplaceWithClosed  func([]protocol.ConnectionID, []byte, time.Duration)
}

// The memory address of the Transport is used as the key.
type connRunners map[connRunner]connRunnerCallbacks

func (cr connRunners) AddConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.AddConnectionID(id)
	}
}

func (cr connRunners) RemoveConnectionID(id protocol.ConnectionID) {
	for _, c := range cr {
		c.RemoveConnectionID(id)
	}
}

func (cr connRunners) ReplaceWithClosed(ids []protocol.ConnectionID, b []byte, expiry time.Duration) {
	for _, c := range cr {
		c.ReplaceWithClosed(ids, b, expiry)
	}
}

type connIDToRetire struct {
	t      monotime.Time
	connID protocol.ConnectionID
}

type connIDGenerator struct {
	generator   ConnectionIDGenerator
	highestSeq  uint64
	connRunners connRunners

	// runnerMu guards connRunners. Every other field of this generator is owned by the
	// connection's run loop, but the runner table is not: a migration attaches a runner from
	// the run loop, and Conn.RetireTransport removes one from the goroutine that noticed the
	// network change. Rotation (issueNewConnID) and final removal (RemoveAll) run on the run
	// loop and read or write the same map, so every access goes through this lock.
	//
	// Lock order: runnerMu is taken before a transport's mutex, never after. The runner
	// callbacks below enter the transport (Transport.Add / Remove / ReplaceWithClosed), so a
	// retirement must release runnerMu before it takes t.mutex to clear the handler table.
	runnerMu sync.Mutex

	activeSrcConnIDs        map[uint64]protocol.ConnectionID
	connIDsToRetire         []connIDToRetire       // sorted by t
	initialClientDestConnID *protocol.ConnectionID // nil for the client

	statelessResetter *statelessResetter

	queueControlFrame func(wire.Frame)
}

func newConnIDGenerator(
	runner connRunner,
	initialConnectionID protocol.ConnectionID,
	initialClientDestConnID *protocol.ConnectionID, // nil for the client
	statelessResetter *statelessResetter,
	callbacks connRunnerCallbacks,
	queueControlFrame func(wire.Frame),
	generator ConnectionIDGenerator,
) *connIDGenerator {
	m := &connIDGenerator{
		generator:         generator,
		activeSrcConnIDs:  make(map[uint64]protocol.ConnectionID),
		statelessResetter: statelessResetter,
		connRunners:       map[connRunner]connRunnerCallbacks{runner: callbacks},
		queueControlFrame: queueControlFrame,
	}
	m.activeSrcConnIDs[0] = initialConnectionID
	m.initialClientDestConnID = initialClientDestConnID
	return m
}

func (m *connIDGenerator) SetMaxActiveConnIDs(limit uint64) error {
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	// The active_connection_id_limit transport parameter is the number of
	// connection IDs the peer will store. This limit includes the connection ID
	// used during the handshake, and the one sent in the preferred_address
	// transport parameter.
	// We currently don't send the preferred_address transport parameter,
	// so we can issue (limit - 1) connection IDs.
	for i := uint64(len(m.activeSrcConnIDs)); i < min(limit, protocol.MaxIssuedConnectionIDs); i++ {
		if err := m.issueNewConnID(); err != nil {
			return err
		}
	}
	return nil
}

func (m *connIDGenerator) Retire(seq uint64, sentWithDestConnID protocol.ConnectionID, expiry monotime.Time) error {
	if seq > m.highestSeq {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (highest issued: %d)", seq, m.highestSeq),
		}
	}
	connID, ok := m.activeSrcConnIDs[seq]
	// We might already have deleted this connection ID, if this is a duplicate frame.
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", seq, connID),
		}
	}
	m.queueConnIDForRetiring(connID, expiry)

	delete(m.activeSrcConnIDs, seq)
	// Don't issue a replacement for the initial connection ID.
	if seq == 0 {
		return nil
	}
	return m.issueNewConnID()
}

func (m *connIDGenerator) queueConnIDForRetiring(connID protocol.ConnectionID, expiry monotime.Time) {
	idx := slices.IndexFunc(m.connIDsToRetire, func(c connIDToRetire) bool {
		return c.t.After(expiry)
	})
	if idx == -1 {
		idx = len(m.connIDsToRetire)
	}
	m.connIDsToRetire = slices.Insert(m.connIDsToRetire, idx, connIDToRetire{t: expiry, connID: connID})
}

func (m *connIDGenerator) issueNewConnID() error {
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return err
	}
	m.activeSrcConnIDs[m.highestSeq+1] = connID
	m.addConnectionID(connID)
	m.queueControlFrame(&wire.NewConnectionIDFrame{
		SequenceNumber:      m.highestSeq + 1,
		ConnectionID:        connID,
		StatelessResetToken: m.statelessResetter.GetStatelessResetToken(connID),
	})
	m.highestSeq++
	return nil
}

func (m *connIDGenerator) SetHandshakeComplete(connIDExpiry monotime.Time) {
	if m.initialClientDestConnID != nil {
		m.queueConnIDForRetiring(*m.initialClientDestConnID, connIDExpiry)
		m.initialClientDestConnID = nil
	}
}

func (m *connIDGenerator) RemoveRetiredConnIDs(now monotime.Time) {
	if len(m.connIDsToRetire) == 0 {
		return
	}
	for _, c := range m.connIDsToRetire {
		if c.t.After(now) {
			break
		}
		m.removeConnectionID(c.connID)
		m.connIDsToRetire = m.connIDsToRetire[1:]
	}
}

func (m *connIDGenerator) RemoveAll() {
	m.runnerMu.Lock()
	defer m.runnerMu.Unlock()

	if m.initialClientDestConnID != nil {
		m.connRunners.RemoveConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		m.connRunners.RemoveConnectionID(connID)
	}
	for _, c := range m.connIDsToRetire {
		m.connRunners.RemoveConnectionID(c.connID)
	}
}

func (m *connIDGenerator) ReplaceWithClosed(connClose []byte, expiry time.Duration) {
	m.runnerMu.Lock()
	defer m.runnerMu.Unlock()

	connIDs := make([]protocol.ConnectionID, 0, len(m.activeSrcConnIDs)+len(m.connIDsToRetire)+1)
	if m.initialClientDestConnID != nil {
		connIDs = append(connIDs, *m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		connIDs = append(connIDs, connID)
	}
	for _, c := range m.connIDsToRetire {
		connIDs = append(connIDs, c.connID)
	}
	m.connRunners.ReplaceWithClosed(connIDs, connClose, expiry)
}

// addConnectionID and removeConnectionID are the locked forms of the runner-table calls the
// run loop makes while rotating or expiring connection IDs.
func (m *connIDGenerator) addConnectionID(id protocol.ConnectionID) {
	m.runnerMu.Lock()
	defer m.runnerMu.Unlock()
	m.connRunners.AddConnectionID(id)
}

func (m *connIDGenerator) removeConnectionID(id protocol.ConnectionID) {
	m.runnerMu.Lock()
	defer m.runnerMu.Unlock()
	m.connRunners.RemoveConnectionID(id)
}

// RemoveConnRunner stops routing this connection's connection IDs to runner. It is used when
// a transport is retired after a migration, so that later connection ID rotations cannot add
// the connection back to a socket that is about to be closed.
func (m *connIDGenerator) RemoveConnRunner(runner connRunner) {
	m.runnerMu.Lock()
	defer m.runnerMu.Unlock()

	delete(m.connRunners, runner)
}

func (m *connIDGenerator) AddConnRunner(runner connRunner, r connRunnerCallbacks) {
	m.runnerMu.Lock()
	defer m.runnerMu.Unlock()

	// The transport might have already been added earlier.
	// This happens if the application migrates back to and old path.
	if _, ok := m.connRunners[runner]; ok {
		return
	}
	m.connRunners[runner] = r
	if m.initialClientDestConnID != nil {
		r.AddConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		r.AddConnectionID(connID)
	}
}
