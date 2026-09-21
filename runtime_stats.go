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
	CongestionController          string
	CongestionState               string
	BBRMode                       string
	BBRBandwidthEstimate          uint64 // bits per second
	BBRMinRTT                     time.Duration
	BBRPacingGain                 float64
	BBRCwndGain                   float64
	BBRTargetCwnd                 uint64
	BBRRoundTripCount             int64
	BBRFullBandwidthReached       bool
	BBRRecoveryState              string
	BBRAppLimited                 bool
	BBRAckAggregationHeight       uint64
	BBRProbeBWCycleIndex          int
	BBRRecoveryWindow             uint64
	CongestionWindow              uint64
	BytesInFlight                 uint64
	PacingRate                    uint64
	MinRTT                        time.Duration
	LatestRTT                     time.Duration
	SmoothedRTT                   time.Duration
	PacketsLost                   uint64
	BytesLost                     uint64
	SpuriousLosses                uint64
	MaxPacketReordering           uint64
	MaxTimeReordering             time.Duration
	ReorderingEvents              uint64
	LossEvents                    uint64
	LossByPacketThreshold         uint64
	LossByTimeThreshold           uint64
	SpuriousAfterPacketThreshold  uint64
	SpuriousAfterTimeThreshold    uint64
	CwndCutbacks                  uint64
	CutbackDueToLossEvent         uint64
	RecoveryEnter                 uint64
	RecoveryExit                  uint64
	RecoveryDuration              time.Duration
	ApplicationLimitedTransitions uint64
	CubicEpochResets              uint64
	AdaptivePacketThreshold       uint64
	AdaptiveTimeThreshold         time.Duration
	DatagramSendQueueDepth        uint64
	DatagramSendQueueHighWater    uint64
	DatagramSendBlocked           uint64
	DatagramSendBlockedDuration   time.Duration
	DatagramSendEnqueue           uint64
	DatagramSendDequeue           uint64
	DatagramSendEnqueueBytes      uint64
	DatagramSendDequeueBytes      uint64
	DatagramQueueNonEmptyDuration time.Duration
	SendQueueDepth                uint64
	SendQueueHighWater            uint64
	SendQueueHardBlocks           uint64
	SendQueueHardBlockedDuration  time.Duration
	SendQueueEnqueue              uint64
	SendQueueDequeue              uint64
	SendQueueEnqueueBytes         uint64
	SendQueueDequeueBytes         uint64
	UDPWrites                     uint64
	UDPWireBytes                  uint64
	GSOBytes                      uint64
	GSOWrites                     uint64
	NonGSOWrites                  uint64
	GSOSegments                   uint64
	GSOAttempts                   uint64
	SingleSegmentGSOAttempts      uint64
	GSOMultiSegmentWrites         uint64
	GSOKernelFallbacks            uint64
	GSOSendErrors                 uint64
	GSOSegmentsTotal              uint64
	FullPMTUPackets               uint64
	ShortPackets                  uint64
	CandidateGSOBatchPackets      uint64
	PackedPacketSizeBuckets       [8]uint64
	SegmentsPerWriteAverage       float64
	SegmentsPerWriteP50           uint64
	SegmentsPerWriteP90           uint64
	SegmentsPerWriteP99           uint64
	SegmentsPerWriteMax           uint64
	SegmentsPerWriteBuckets       [65]uint64
	PacketsPacked                 uint64
	PackedBytes                   uint64
	PacingWakeups                 uint64
	SendScheduleRequests          uint64
	SendScheduleCoalesced         uint64
	ReceivedPacketQueueDrops      uint64
	ReceivedPackets               uint64
	ReceivedBytes                 uint64
	ReceivedDatagramQueueDrops    uint64
	CurrentPMTU                   uint64
	GSO                           bool
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
		out.BBRMode = h.BBRMode
		out.BBRBandwidthEstimate = h.BBRBandwidthEstimate
		out.BBRMinRTT = h.BBRMinRTT
		out.BBRPacingGain = h.BBRPacingGain
		out.BBRCwndGain = h.BBRCwndGain
		out.BBRTargetCwnd = uint64(h.BBRTargetCwnd)
		out.BBRRoundTripCount = h.BBRRoundTripCount
		out.BBRFullBandwidthReached = h.BBRFullBandwidthReached
		out.BBRRecoveryState = h.BBRRecoveryState
		out.BBRAppLimited = h.BBRAppLimited
		out.BBRAckAggregationHeight = uint64(h.BBRAckAggregationHeight)
		out.BBRProbeBWCycleIndex = h.BBRProbeBWCycleIndex
		out.BBRRecoveryWindow = uint64(h.BBRRecoveryWindow)
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
		out.ReorderingEvents = h.ReorderingEvents
		out.LossEvents = h.LossEvents
		out.LossByPacketThreshold = h.LossByPacketThreshold
		out.LossByTimeThreshold = h.LossByTimeThreshold
		out.SpuriousAfterPacketThreshold = h.SpuriousAfterPacketThreshold
		out.SpuriousAfterTimeThreshold = h.SpuriousAfterTimeThreshold
		out.CwndCutbacks = h.CwndCutbacks
		out.CutbackDueToLossEvent = h.CutbackDueToLossEvent
		out.RecoveryEnter = h.RecoveryEnter
		out.RecoveryExit = h.RecoveryExit
		out.RecoveryDuration = h.RecoveryDuration
		out.ApplicationLimitedTransitions = h.ApplicationLimitedTransitions
		out.CubicEpochResets = h.CubicEpochResets
		out.AdaptivePacketThreshold = h.AdaptivePacketThreshold
		out.AdaptiveTimeThreshold = h.AdaptiveTimeThreshold
	}
	if c.datagramQueue != nil {
		q := c.datagramQueue.runtimeStats()
		out.DatagramSendQueueDepth = q.SendDepth
		out.DatagramSendQueueHighWater = q.SendHighWater
		out.DatagramSendBlocked = q.SendBlocked
		out.DatagramSendBlockedDuration = time.Duration(q.SendBlockedDurationNS)
		out.DatagramSendEnqueue = q.SendEnqueue
		out.DatagramSendDequeue = q.SendDequeue
		out.DatagramSendEnqueueBytes = q.SendEnqueueBytes
		out.DatagramSendDequeueBytes = q.SendDequeueBytes
		out.DatagramQueueNonEmptyDuration = time.Duration(q.NonEmptyDurationNS)
		out.ReceivedDatagramQueueDrops = q.ReceiveDrops
	}
	out.ReceivedPackets = c.receivedPacketsTotal.Load()
	out.ReceivedBytes = c.receivedBytes.Load()
	if q, ok := c.sendQueue.(*sendQueue); ok {
		s := q.runtimeStats()
		out.SendQueueDepth = s.Depth
		out.SendQueueHighWater = s.HighWater
		out.SendQueueHardBlocks = s.HardBlocks
		out.SendQueueHardBlockedDuration = time.Duration(s.HardBlockedDurationNS)
		out.SendQueueEnqueue = s.Enqueued
		out.SendQueueDequeue = s.Sent
		out.SendQueueEnqueueBytes = s.EnqueuedBytes
		out.SendQueueDequeueBytes = s.SentBytes
		out.UDPWrites = s.Writes
		out.UDPWireBytes = s.SentBytes
		out.GSOBytes = s.GSOBytes
		out.GSOWrites = s.GSOWrites
		out.NonGSOWrites = s.NonGSOWrites
		out.GSOSegments = s.GSOSegments
		out.GSOAttempts = s.GSOAttempts
		out.SingleSegmentGSOAttempts = s.SingleSegmentAttempts
		out.GSOMultiSegmentWrites = s.GSOMultiSegmentWrites
		out.GSOKernelFallbacks = s.GSOKernelFallbacks
		out.GSOSendErrors = s.GSOSendErrors
		out.GSOSegmentsTotal = s.GSOSegmentsTotal
		if s.Writes > 0 {
			out.SegmentsPerWriteAverage = float64(s.GSOSegments+s.NonGSOWrites) / float64(s.Writes)
		}
		out.SegmentsPerWriteP50 = s.SegmentsPerWriteP50
		out.SegmentsPerWriteP90 = s.SegmentsPerWriteP90
		out.SegmentsPerWriteP99 = s.SegmentsPerWriteP99
		out.SegmentsPerWriteMax = s.SegmentsPerWriteMax
		out.SegmentsPerWriteBuckets = s.SegmentsPerWriteBuckets
	}
	out.ReceivedPacketQueueDrops = c.receivedPacketQueueDrops.Load()
	out.FullPMTUPackets = c.fullPMTUPackets
	out.ShortPackets = c.shortPackets
	out.CandidateGSOBatchPackets = c.candidateGSOBatchPackets
	out.PackedPacketSizeBuckets = c.packedPacketSizeBuckets
	out.GSO = c.conn.capabilities().GSO
	out.PacketsPacked = c.packetsPacked.Load()
	out.PackedBytes = c.packedBytes.Load()
	out.PacingWakeups = c.pacingWakeups.Load()
	out.SendScheduleRequests = c.sendScheduleRequests.Load()
	out.SendScheduleCoalesced = c.sendScheduleCoalesced.Load()
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
