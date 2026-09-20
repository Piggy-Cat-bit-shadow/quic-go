package quic

import (
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go/internal/ackhandler"
)

// RuntimeStats is a bounded, identity-free diagnostic snapshot. It contains
// aggregate transport state only; it never contains addresses, packet numbers,
// payloads, or packet-level events.
type RuntimeStats struct {
	CongestionController         string
	CongestionState              string
	CongestionWindow             uint64
	BytesInFlight                uint64
	PacingRate                   uint64
	MinRTT                       time.Duration
	LatestRTT                    time.Duration
	SmoothedRTT                  time.Duration
	PacketsLost                  uint64
	BytesLost                    uint64
	SpuriousLosses               uint64
	MaxPacketReordering          uint64
	MaxTimeReordering            time.Duration
	DatagramSendQueueDepth       uint64
	DatagramSendQueueHighWater   uint64
	DatagramSendBlocked          uint64
	DatagramSendBlockedDuration  time.Duration
	SendQueueDepth               uint64
	SendQueueHighWater           uint64
	SendQueueHardBlocks          uint64
	SendQueueHardBlockedDuration time.Duration
	ReceivedPacketQueueDrops     uint64
	ReceivedDatagramQueueDrops   uint64
	CurrentPMTU                  uint64
	GSO                          bool
}

func updateAtomicMax(dst *atomic.Uint64, value uint64) {
	for {
		old := dst.Load()
		if value <= old || dst.CompareAndSwap(old, value) {
			return
		}
	}
}

// updateRuntimeStats must be called by the connection event loop. Keeping the
// mutable QUIC state on that side of the lock avoids racing a public snapshot
// reader with ACK/loss processing.
func (c *Conn) updateRuntimeStats() {
	var out RuntimeStats
	if h, ok := c.sentPacketHandler.(interface {
		RuntimeStats() ackhandler.RuntimeStats
	}); ok {
		h := h.RuntimeStats()
		out.CongestionController = h.CongestionController
		out.CongestionState = h.CongestionState
		out.CongestionWindow = uint64(h.CongestionWindow)
		out.BytesInFlight = uint64(h.BytesInFlight)
		out.PacingRate = h.PacingRate
		out.MinRTT = h.MinRTT
		out.LatestRTT = h.LatestRTT
		out.SmoothedRTT = h.SmoothedRTT
		out.PacketsLost = h.PacketsLost
		out.BytesLost = h.BytesLost
		out.SpuriousLosses = h.SpuriousLosses
		out.MaxPacketReordering = uint64(h.MaxPacketReordering)
		out.MaxTimeReordering = h.MaxTimeReordering
	}
	if c.datagramQueue != nil {
		q := c.datagramQueue.runtimeStats()
		out.DatagramSendQueueDepth = q.SendDepth
		out.DatagramSendQueueHighWater = q.SendHighWater
		out.DatagramSendBlocked = q.SendBlocked
		out.DatagramSendBlockedDuration = time.Duration(q.SendBlockedDurationNS)
		out.ReceivedDatagramQueueDrops = q.ReceiveDrops
	}
	if q, ok := c.sendQueue.(*sendQueue); ok {
		s := q.runtimeStats()
		out.SendQueueDepth = s.Depth
		out.SendQueueHighWater = s.HighWater
		out.SendQueueHardBlocks = s.HardBlocks
		out.SendQueueHardBlockedDuration = time.Duration(s.HardBlockedDurationNS)
	}
	out.ReceivedPacketQueueDrops = c.receivedPacketQueueDrops.Load()
	out.GSO = c.conn.capabilities().GSO
	if c.mtuDiscoverer != nil {
		out.CurrentPMTU = uint64(c.mtuDiscoverer.CurrentSize())
	} else {
		out.CurrentPMTU = uint64(c.maxPacketSize())
	}
	c.runtimeStatsMu.Lock()
	c.runtimeStats = out
	c.runtimeStatsMu.Unlock()
}

// RuntimeStats returns a bounded diagnostic snapshot of this connection.
// The snapshot is copied from an event-loop-owned cache and is safe to read
// concurrently with packet processing.
func (c *Conn) RuntimeStats() RuntimeStats {
	c.runtimeStatsMu.RLock()
	defer c.runtimeStatsMu.RUnlock()
	return c.runtimeStats
}
