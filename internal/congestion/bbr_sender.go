package congestion

// src from https://quiche.googlesource.com/quiche.git/+/66dea072431f94095dfc3dd2743cb94ef365f7ef/quic/core/congestion_control/bbr_sender.cc
// Go port/adaptation derived from tdragoun/quic-go bbr_v1 commit
// a07eb48492755adb24d4f278a92f5e054f1eccad (MIT); adapted for this fork's
// shared RTT state, packet-number spaces, telemetry, and pacing interfaces.

import (
	"math"
	"math/rand/v2"
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/utils"
	"github.com/metacubex/quic-go/qlog"
	"github.com/metacubex/quic-go/qlogwriter"
)

var (
	// The maximum outgoing packet size allowed.
	// The maximum packet size of any QUIC packet over IPv6, based on ethernet's max
	// size, minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
	// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 48 = 1452.
	MaxOutgoingPacketSize = protocol.ByteCount(1452)

	// Default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	MaxSegmentSize = protocol.ByteCount(protocol.InitialPacketSize)

	// Default initial rtt used before any samples are received.
	InitialRtt = 100 * time.Millisecond

	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.
	DefaultMinimumCongestionWindow = 4 * protocol.ByteCount(protocol.InitialPacketSize)

	// The gain used for the STARTUP, equal to 2/ln(2).
	DefaultHighGain = 2.885

	// The gain used in STARTUP after loss has been detected.
	// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
	// in measured bandwidth.
	StartupAfterLossGain = 1.5

	// The cycle of gains used during the PROBE_BW stage.
	PacingGain = []float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

	// The length of the gain cycle.
	GainCycleLength = len(PacingGain)

	// The size of the bandwidth filter window, in round-trips.
	BandwidthWindowSize = GainCycleLength + 2

	// The time after which the current min_rtt value expires.
	MinRttExpiry = 10 * time.Second

	// The minimum time the connection can spend in PROBE_RTT mode.
	ProbeRttTime = time.Millisecond * 200

	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	StartupGrowthTarget                         = 1.25
	RoundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
	ModerateProbeRttMultiplier = 0.75

	// Coefficient to determine if a new RTT is sufficiently similar to min_rtt that
	// we don't need to enter PROBE_RTT.
	SimilarMinRttThreshold = 1.125

	// Congestion window gain for QUIC BBR during PROBE_BW phase.
	DefaultCongestionWindowGainConst = 2.0
)

type bbrMode int

const (
	// Startup phase of the connection.
	STARTUP = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	DRAIN
	// Cruising mode.
	PROBE_BW
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	PROBE_RTT
)

type bbrRecoveryState int

const (
	// Do not limit.
	NOT_IN_RECOVERY = iota

	// Allow an extra outstanding byte for each byte acknowledged.
	CONSERVATION

	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	GROWTH
)

type bbrSender struct {
	mode      bbrMode
	clock     Clock
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	qlogger   qlogwriter.Recorder
	// Pacer for pacing packets
	pacer *pacer
	// Maximum datagram size
	maxDatagramSize protocol.ByteCount
	// Track bytes in flight (passed as parameter in interface methods)
	bytesInFlight protocol.ByteCount
	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *BandwidthSampler
	// The number of the round trips that have occurred during the connection.
	roundTripCount int64
	// The packet number of the most recently sent packet.
	lastSendPacket protocol.PacketNumber
	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber
	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *WindowedFilter
	// Tracks the maximum number of bytes acked faster than the sending rate.
	maxAckHeight *WindowedFilter
	// The time this aggregation started and the number of bytes acked during it.
	aggregationEpochStartTime monotime.Time
	aggregationEpochBytes     protocol.ByteCount
	// Minimum RTT estimate.  Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp monotime.Time
	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount
	// The initial value of the |congestion_window_|.
	initialCongestionWindow protocol.ByteCount
	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow protocol.ByteCount
	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow protocol.ByteCount
	// The pacing gain applied during the STARTUP phase.
	highGain float64
	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64
	// The pacing gain applied during the DRAIN phase.
	drainGain float64
	// The current pacing rate of the connection.
	pacingRate Bandwidth
	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64
	// The gain used for the congestion window during PROBE_BW.  Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConst float64
	// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
	numStartupRtts int64
	// If true, exit startup if 1RTT has passed with no bandwidth increase and
	// the connection is in recovery.
	exitStartupOnLoss bool
	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart monotime.Time
	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth
	// Set to true upon exiting quiescence.
	exitingQuiescence bool
	// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt monotime.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool
	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool
	// Indicates whether any non app-limited samples have been recorded.
	hasNoAppLimitedSample bool
	// Indicates app-limited calls should be ignored as long as there's
	// enough data inflight to see more bandwidth when necessary.
	flexibleAppLimited bool
	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode.  A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount
	// If true, consider all samples in recovery app-limited.
	isAppLimitedRecovery bool
	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool
	// When true, disables packet conservation in STARTUP.
	rateBasedStartup bool
	// When non-zero, decreases the rate in STARTUP by the total number of bytes
	// lost in STARTUP divided by CWND.
	startupRateReductionMultiplier int64
	// Sum of bytes lost in STARTUP.
	startupBytesLost protocol.ByteCount
	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool
	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool
	// If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.
	probeRttBasedOnBdp bool
	// If true, skip probe_rtt and update the timestamp of the existing min_rtt to
	// now if min_rtt over the last cycle is within 12.5% of the current min_rtt.
	// Even if the min_rtt is 12.5% too low, the 25% gain cycling and 2x CWND gain
	// should overcome an overly small min_rtt.
	probeRttSkippedIfSimilarRtt bool
	// If true, disable PROBE_RTT entirely as long as the connection was recently
	// app limited.
	probeRttDisabledIfAppLimited  bool
	appLimitedSinceLastProbeRtt   bool
	minRttSinceLastProbeRtt       time.Duration
	applicationDataPending        bool
	applicationLimited            bool
	applicationLimitedTransitions uint64
	cycleOffsetSource             func(int) int
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

func NewBBRSender(clock Clock, rttStats *utils.RTTStats, connStats *utils.ConnectionStats, initialMaxDatagramSize protocol.ByteCount, qlogger qlogwriter.Recorder) *bbrSender {
	initialCongestionWindow := 32 * initialMaxDatagramSize
	maxCongestionWindow := protocol.MaxCongestionWindowPackets * initialMaxDatagramSize

	b := &bbrSender{
		rttStats:                  rttStats,
		connStats:                 connStats,
		qlogger:                   qlogger,
		mode:                      STARTUP,
		clock:                     clock,
		sampler:                   NewBandwidthSampler(),
		maxBandwidth:              NewWindowedFilter(int64(BandwidthWindowSize), MaxFilter),
		maxAckHeight:              NewWindowedFilter(int64(BandwidthWindowSize), MaxFilter),
		congestionWindow:          initialCongestionWindow,
		initialCongestionWindow:   initialCongestionWindow,
		maxCongestionWindow:       maxCongestionWindow,
		minCongestionWindow:       DefaultMinimumCongestionWindow,
		highGain:                  DefaultHighGain,
		highCwndGain:              DefaultHighGain,
		drainGain:                 1.0 / DefaultHighGain,
		pacingGain:                DefaultHighGain,
		congestionWindowGain:      DefaultHighGain,
		congestionWindowGainConst: DefaultCongestionWindowGainConst,
		numStartupRtts:            RoundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:             NOT_IN_RECOVERY,
		recoveryWindow:            maxCongestionWindow,
		minRttSinceLastProbeRtt:   InfiniteRTT,
		maxDatagramSize:           initialMaxDatagramSize,
	}

	// Initialize pacer with pacing rate function (not raw bandwidth estimate)
	// The pacing rate includes the pacing gain and handles startup properly
	b.pacer = newPacerWithAdjustment(func() Bandwidth {
		if b.pacingRate > 0 {
			return b.pacingRate
		}
		// Fallback to bandwidth estimate if pacing rate not set yet
		return b.BandwidthEstimate()
	}, 1, 1)
	if b.qlogger != nil {
		b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	}

	return b
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	b.bytesInFlight = bytesInFlight
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) AvailablePacingBudget(now monotime.Time, bytesInFlight protocol.ByteCount) protocol.ByteCount {
	return min(b.pacer.Budget(now), max(protocol.ByteCount(0), b.GetCongestionWindow()-bytesInFlight))
}

func (b *bbrSender) GetPacingRate() uint64               { return uint64(b.pacingRate / BytesPerSecond) }
func (b *bbrSender) GetCongestionControllerName() string { return "bbr" }

func (b *bbrSender) SetApplicationDataPending(pending bool) {
	if b.applicationDataPending == pending {
		return
	}
	b.applicationDataPending = pending
	if !pending && !b.applicationLimited && b.bytesInFlight < b.GetCongestionWindow() {
		b.sampler.OnAppLimited()
		b.applicationLimited = true
		b.applicationLimitedTransitions++
	} else if pending && b.applicationLimited {
		b.applicationLimited = false
	}
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.lastSendPacket = packetNumber
	b.bytesInFlight = bytesInFlight
	if isRetransmittable {
		b.bytesInFlight += bytes
	}

	if bytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	if b.aggregationEpochStartTime.IsZero() {
		b.aggregationEpochStartTime = sentTime
	}

	// Initialize pacing rate on first packet if not already set
	if b.pacingRate == 0 {
		b.CalculatePacingRate()
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *bbrSender) OnPacketSentWithEncryptionLevel(level protocol.EncryptionLevel, sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	// The sampler is keyed by packet number, while QUIC packet number spaces
	// reuse values. The BBR model therefore samples only application (1-RTT)
	// packets. Still charge other levels to the shared pacer without tracking
	// their packet-number state.
	if level != protocol.Encryption1RTT {
		b.bytesInFlight = bytesInFlight
		if isRetransmittable {
			b.bytesInFlight += bytes
		}
		b.pacer.SentPacket(sentTime, bytes)
		return
	}
	b.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytes, isRetransmittable)
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	b.bytesInFlight = bytesInFlight
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == PROBE_RTT {
		return b.ProbeRttCongestionWindow()
	}

	if b.InRecovery() && (!b.rateBasedStartup || b.mode != STARTUP) {
		return min(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

// SetBytesInFlight seeds accounting when a controller is selected or
// reconstructed while transport packets from another packet-number space are
// still outstanding.
func (b *bbrSender) SetBytesInFlight(bytes protocol.ByteCount) { b.bytesInFlight = bytes }

func (b *bbrSender) MaybeExitSlowStart() {
	// BBR does not use traditional slow start exit
}

func (b *bbrSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	if _, ok := b.sampler.connectionStats.Get(number); !ok {
		return
	}
	b.bytesInFlight = max(protocol.ByteCount(0), b.bytesInFlight-ackedBytes)
	totalBytesAckedBefore := b.sampler.totalBytesAcked

	// Get bandwidth sample
	bandwidthSample := b.sampler.OnPacketAcked(eventTime, number)
	if !bandwidthSample.stateAtSend.isValid {
		// Packet was never sent or already processed
		return
	}
	// Debug logging for startup performance issues
	if b.mode == STARTUP && b.roundTripCount < 20 {
		_ = bandwidthSample // Placeholder for potential debug logging
		// In production, you could log: RTT=%d, BW=%d Mbps, CWND=%d, Round=%d, Mode=%d
		// eventTime, bandwidthSample.bandwidth/125000, b.congestionWindow, b.roundTripCount, b.mode
	}

	b.lastSampleIsAppLimited = bandwidthSample.stateAtSend.isAppLimited
	if !bandwidthSample.stateAtSend.isAppLimited {
		b.hasNoAppLimitedSample = true
	}

	// Update bandwidth estimate
	if !bandwidthSample.stateAtSend.isAppLimited || bandwidthSample.bandwidth > b.BandwidthEstimate() {
		b.maxBandwidth.Update(int64(bandwidthSample.bandwidth), b.roundTripCount)
	}

	// Update min RTT
	minRttExpired := false
	if bandwidthSample.rtt > 0 {
		minRttExpired = b.updateMinRtt(eventTime, bandwidthSample.rtt)
	}

	// Check for round trip advancement
	isRoundStart := b.UpdateRoundTripCounter(number)

	// Update state machine
	b.UpdateRecoveryState(number, false, isRoundStart)

	bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore
	excessAcked := b.UpdateAckAggregationBytes(eventTime, bytesAcked)

	// Phase-specific updates
	if b.mode == PROBE_BW {
		b.UpdateGainCyclePhase(eventTime, priorInFlight, false)
	}

	if isRoundStart && !b.isAtFullBandwidth {
		b.CheckIfFullBandwidthReached()
	}

	b.MaybeExitStartupOrDrain(eventTime)
	b.MaybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// Recalculate windows
	b.CalculatePacingRate()
	b.CalculateCongestionWindow(bytesAcked, excessAcked)
	b.CalculateRecoveryWindow(bytesAcked, 0)
}

func (b *bbrSender) OnPacketAckedWithEncryptionLevel(level protocol.EncryptionLevel, number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	if level == protocol.Encryption1RTT {
		if _, ok := b.sampler.connectionStats.Get(number); !ok {
			// The packet predates this controller (or was processed already). Keep
			// its transport bytes-in-flight accounting balanced without feeding a
			// synthetic sample into the new model.
			b.bytesInFlight = max(protocol.ByteCount(0), b.bytesInFlight-ackedBytes)
			return
		}
		b.OnPacketAcked(number, ackedBytes, priorInFlight, eventTime)
		return
	}
	b.bytesInFlight = max(protocol.ByteCount(0), b.bytesInFlight-ackedBytes)
}

func (b *bbrSender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	b.bytesInFlight = max(protocol.ByteCount(0), b.bytesInFlight-lostBytes)
	if b.connStats != nil {
		b.connStats.PacketsLost.Add(1)
		b.connStats.BytesLost.Add(uint64(lostBytes))
	}
	// Handle packet loss
	b.sampler.OnPacketLost(number)

	if b.mode == STARTUP && b.startupRateReductionMultiplier != 0 {
		b.startupBytesLost += lostBytes
	}

	// Update recovery state with loss indication
	b.UpdateRecoveryState(number, true, false)

	// Recalculate recovery window
	b.CalculateRecoveryWindow(0, lostBytes)
}

func (b *bbrSender) OnCongestionEventWithEncryptionLevel(level protocol.EncryptionLevel, number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	if level == protocol.Encryption1RTT {
		b.OnCongestionEvent(number, lostBytes, priorInFlight)
		return
	}
	b.bytesInFlight = max(protocol.ByteCount(0), b.bytesInFlight-lostBytes)
	// Preserve transport-wide loss accounting for old packet-number spaces, but
	// do not let their reused packet numbers mutate the 1-RTT recovery model.
	if b.connStats != nil {
		b.connStats.PacketsLost.Add(1)
		b.connStats.BytesLost.Add(uint64(lostBytes))
	}
}

func (b *bbrSender) SetMaxDatagramSize(size protocol.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// BBR does not react to retransmission timeouts
}

// Debug interface methods
func (b *bbrSender) InSlowStart() bool {
	return b.mode == STARTUP
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != NOT_IN_RECOVERY
}

func (b *bbrSender) BandwidthEstimate() Bandwidth {
	return Bandwidth(b.maxBandwidth.GetBest())
}

func (b *bbrSender) ShouldSendProbingPacket() bool {
	if b.pacingGain <= 1 {
		return false
	}
	if b.flexibleAppLimited {
		return !b.IsPipeSufficientlyFull()
	}
	return true
}

func (b *bbrSender) IsPipeSufficientlyFull() bool {
	if b.mode == STARTUP {
		return b.bytesInFlight >= b.GetTargetCongestionWindow(1.5)
	}
	if b.pacingGain > 1 {
		return b.bytesInFlight >= b.GetTargetCongestionWindow(b.pacingGain)
	}
	return b.bytesInFlight >= b.GetTargetCongestionWindow(1.1)
}

func (b *bbrSender) UpdateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if b.currentRoundTripEnd == 0 || lastAckedPacket > b.currentRoundTripEnd {
		b.currentRoundTripEnd = b.lastSendPacket
		b.roundTripCount++
		return true
	}
	return false
}

func (b *bbrSender) updateMinRtt(now monotime.Time, sampleRtt time.Duration) bool {
	b.minRttSinceLastProbeRtt = minRtt(b.minRttSinceLastProbeRtt, sampleRtt)

	// Do not expire min_rtt if none was ever available.
	minRttExpired := b.minRtt > 0 && (now.Sub(b.minRttTimestamp) > MinRttExpiry)

	if minRttExpired || sampleRtt < b.minRtt || b.minRtt == 0 {
		if minRttExpired && b.ShouldExtendMinRttExpiry() {
			minRttExpired = false
		} else {
			b.minRtt = sampleRtt
		}
		b.minRttTimestamp = now
		// Reset since_last_probe_rtt fields.
		b.minRttSinceLastProbeRtt = InfiniteRTT
		b.appLimitedSinceLastProbeRtt = false
	}

	return minRttExpired
}

func (b *bbrSender) ShouldExtendMinRttExpiry() bool {
	if b.probeRttDisabledIfAppLimited && b.appLimitedSinceLastProbeRtt {
		return true
	}

	minRttIncreasedSinceLastProbe := b.minRttSinceLastProbeRtt > time.Duration(float64(b.minRtt)*SimilarMinRttThreshold)
	if b.probeRttSkippedIfSimilarRtt && b.appLimitedSinceLastProbeRtt && !minRttIncreasedSinceLastProbe {
		return true
	}

	return false
}

func (b *bbrSender) UpdateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	switch b.recoveryState {
	case NOT_IN_RECOVERY:
		if hasLosses {
			b.recoveryState = CONSERVATION
			b.endRecoveryAt = b.lastSendPacket
			b.recoveryWindow = 0
			b.currentRoundTripEnd = b.lastSendPacket
			// The referenced QUICHE revision gated this optional behavior behind
			// quic_bbr_app_limited_recovery, disabled by default. Keep that default.
		}
	case CONSERVATION:
		if isRoundStart {
			b.recoveryState = GROWTH
		}
		fallthrough
	case GROWTH:
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = NOT_IN_RECOVERY
			b.isAppLimitedRecovery = false
		}
	}

	if b.recoveryState != NOT_IN_RECOVERY && b.isAppLimitedRecovery {
		b.sampler.OnAppLimited()
	}
}

func (b *bbrSender) UpdateAckAggregationBytes(ackTime monotime.Time, ackedBytes protocol.ByteCount) protocol.ByteCount {
	// Compute how many bytes are expected to be delivered, assuming max bandwidth is correct.
	// maxBandwidth.GetBest() is in bits/second; divide by BytesPerSecond (8) to get bytes/second.
	timeDelta := ackTime.Sub(b.aggregationEpochStartTime)
	var expectedAckedBytes protocol.ByteCount
	if timeDelta > 0 {
		expectedAckedBytes = saturatingMulDiv(uint64(b.maxBandwidth.GetBest()/int64(BytesPerSecond)), uint64(timeDelta), uint64(time.Second))
	}

	// Reset the current aggregation epoch as soon as the ack arrival rate is less
	// than or equal to the max bandwidth.
	if b.aggregationEpochBytes <= expectedAckedBytes {
		b.aggregationEpochBytes = ackedBytes
		b.aggregationEpochStartTime = ackTime
		return 0
	}

	// Compute how many extra bytes were delivered vs max bandwidth.
	b.aggregationEpochBytes += ackedBytes
	b.maxAckHeight.Update(int64(b.aggregationEpochBytes-expectedAckedBytes), b.roundTripCount)
	return b.aggregationEpochBytes - expectedAckedBytes
}

func (b *bbrSender) UpdateGainCyclePhase(now monotime.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	bytesInFlight := b.bytesInFlight
	shouldAdvanceGainCycling := now.Sub(b.lastCycleStart) > b.GetMinRtt()

	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.GetTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	if b.pacingGain < 1.0 && bytesInFlight <= b.GetTargetCongestionWindow(1.0) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % GainCycleLength
		b.lastCycleStart = now
		if b.drainToTarget && b.pacingGain < 1.0 && PacingGain[b.cycleCurrentOffset] == 1.0 &&
			bytesInFlight > b.GetTargetCongestionWindow(1.0) {
			return
		}
		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) GetTargetCongestionWindow(gain float64) protocol.ByteCount {
	// BandwidthEstimate() is in bits/second; divide by 8 to get bytes/second.
	// Compute RTT × rate / second with saturation to avoid signed overflow.
	bdp := saturatingMulDiv(uint64(b.GetMinRtt()), uint64(b.BandwidthEstimate()/BytesPerSecond), uint64(time.Second))
	if gain <= 0 || math.IsNaN(gain) {
		return b.minCongestionWindow
	}
	window := float64(bdp) * gain
	congestionWindow := protocol.MaxByteCount
	if !math.IsInf(window, 0) && window < float64(protocol.MaxByteCount) {
		congestionWindow = protocol.ByteCount(window)
	}

	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return max(congestionWindow, b.minCongestionWindow)
}

// saturatingMulDiv returns a*b/divisor without overflowing uint64 intermediates.
// Inputs are non-negative and divisor must be non-zero.
func saturatingMulDiv(a, b, divisor uint64) protocol.ByteCount {
	if divisor == 0 {
		return protocol.MaxByteCount
	}
	maxValue := uint64(protocol.MaxByteCount)
	whole := a / divisor
	remainder := a % divisor
	if b != 0 && whole > maxValue/b {
		return protocol.MaxByteCount
	}
	result := whole * b
	if b != 0 && remainder > maxValue/b {
		return protocol.MaxByteCount
	}
	fraction := remainder * b / divisor
	if fraction > maxValue-result {
		return protocol.MaxByteCount
	}
	return protocol.ByteCount(result + fraction)
}

func (b *bbrSender) CheckIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * StartupGrowthTarget)
	if b.BandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.BandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			b.maxAckHeight.Reset(0, b.roundTripCount)
		}
		return
	}
	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts || (b.exitStartupOnLoss && b.InRecovery()) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) MaybeExitStartupOrDrain(now monotime.Time) {
	if b.mode == STARTUP && b.isAtFullBandwidth {
		b.OnExitStartup(now)
		b.mode = DRAIN
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}
	if b.mode == DRAIN && b.bytesInFlight <= b.GetTargetCongestionWindow(1) {
		b.EnterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) EnterProbeBandwidthMode(now monotime.Time) {
	b.mode = PROBE_BW
	b.congestionWindowGain = b.congestionWindowGainConst

	if b.cycleOffsetSource != nil {
		b.cycleCurrentOffset = b.cycleOffsetSource(GainCycleLength)
	} else {
		b.cycleCurrentOffset = rand.IntN(GainCycleLength - 1)
	}
	if b.cycleCurrentOffset < 0 || b.cycleCurrentOffset >= GainCycleLength {
		b.cycleCurrentOffset = 1
	}
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = PacingGain[b.cycleCurrentOffset]
}

func (b *bbrSender) MaybeEnterOrExitProbeRtt(now monotime.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != PROBE_RTT {
		if b.InSlowStart() {
			b.OnExitStartup(now)
		}
		b.mode = PROBE_RTT
		b.pacingGain = 1.0
		b.exitProbeRttAt = monotime.Time(0)
	}

	if b.mode == PROBE_RTT {
		b.sampler.OnAppLimited()
		if b.exitProbeRttAt.IsZero() {
			if b.bytesInFlight < b.ProbeRttCongestionWindow()+MaxOutgoingPacketSize {
				b.exitProbeRttAt = now.Add(ProbeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.After(b.exitProbeRttAt) && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.EnterStartupMode(now)
				} else {
					b.EnterProbeBandwidthMode(now)
				}
			}
		}
	}
	b.exitingQuiescence = false
}

func (b *bbrSender) ProbeRttCongestionWindow() protocol.ByteCount {
	if b.probeRttBasedOnBdp {
		return b.GetTargetCongestionWindow(ModerateProbeRttMultiplier)
	}
	return b.minCongestionWindow
}

func (b *bbrSender) EnterStartupMode(now monotime.Time) {
	b.mode = STARTUP
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *bbrSender) OnExitStartup(now monotime.Time) {
	// Could add statistics tracking here
}

func (b *bbrSender) CalculatePacingRate() {
	bwEstimate := b.BandwidthEstimate()

	// Initialize pacing rate early in the connection
	if b.pacingRate == 0 {
		rtt := b.rttStats.MinRTT()
		if rtt == 0 {
			// Use initial RTT estimate if no samples yet
			rtt = InitialRtt
		}
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, rtt)
		// Apply startup gain to initial pacing rate
		b.pacingRate = Bandwidth(b.pacingGain * float64(b.pacingRate))
		return
	}

	if bwEstimate == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(bwEstimate))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	hasEverDetectedLoss := b.endRecoveryAt > 0
	if b.slowerStartup && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth(StartupAfterLossGain * float64(b.BandwidthEstimate()))
		return
	}

	if b.startupRateReductionMultiplier != 0 && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth((1.0 - (float64(b.startupBytesLost) * float64(b.startupRateReductionMultiplier) / float64(b.congestionWindow))) * float64(targetRate))
		b.pacingRate = max(b.pacingRate, Bandwidth(StartupGrowthTarget*float64(b.BandwidthEstimate())))
		return
	}

	b.pacingRate = max(b.pacingRate, targetRate)
}

func (b *bbrSender) CalculateCongestionWindow(ackedBytes, excessAcked protocol.ByteCount) {
	if b.mode == PROBE_RTT {
		return
	}

	targetWindow := b.GetTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		targetWindow += protocol.ByteCount(b.maxAckHeight.GetBest())
	} else if b.enableAckAggregationDuringStartup {
		targetWindow += excessAcked
	}

	if b.isAtFullBandwidth {
		b.congestionWindow = min(targetWindow, b.congestionWindow+ackedBytes)
		// At the referenced QUICHE revision, the no-bytes-acked-in-startup-recovery
		// flag defaults to false, so the default permits ACK growth during recovery.
	} else if b.congestionWindow < targetWindow || b.sampler.totalBytesAcked < b.initialCongestionWindow {
		b.congestionWindow += ackedBytes
	}

	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) CalculateRecoveryWindow(ackedBytes, lostBytes protocol.ByteCount) {
	if b.rateBasedStartup && b.mode == STARTUP {
		return
	}

	if b.recoveryState == NOT_IN_RECOVERY {
		return
	}

	if b.recoveryWindow == 0 {
		b.recoveryWindow = max(b.bytesInFlight+ackedBytes, b.minCongestionWindow)
		return
	}

	if b.recoveryWindow >= lostBytes {
		b.recoveryWindow -= lostBytes
	} else {
		b.recoveryWindow = MaxSegmentSize
	}

	if b.recoveryState == GROWTH {
		b.recoveryWindow += ackedBytes
	}

	b.recoveryWindow = max(b.recoveryWindow, b.bytesInFlight+ackedBytes)
	b.recoveryWindow = max(b.recoveryWindow, b.minCongestionWindow)
}

func (b *bbrSender) GetMinRtt() time.Duration {
	if b.minRtt > 0 {
		return b.minRtt
	}
	if b.rttStats != nil && b.rttStats.MinRTT() > 0 {
		return b.rttStats.MinRTT()
	}
	return InitialRtt
}

func minRtt(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

var InfiniteRTT = time.Duration(math.MaxInt64)

func (b *bbrSender) GetBBRMode() string {
	switch b.mode {
	case STARTUP:
		return "startup"
	case DRAIN:
		return "drain"
	case PROBE_BW:
		return "probe_bw"
	case PROBE_RTT:
		return "probe_rtt"
	default:
		return "unknown"
	}
}
func (b *bbrSender) GetBandwidthEstimate() uint64 { return uint64(b.BandwidthEstimate()) }
func (b *bbrSender) GetMinRTT() time.Duration     { return b.GetMinRtt() }
func (b *bbrSender) GetPacingGain() float64       { return b.pacingGain }
func (b *bbrSender) GetCwndGain() float64         { return b.congestionWindowGain }
func (b *bbrSender) GetTargetCwnd() protocol.ByteCount {
	return b.GetTargetCongestionWindow(b.congestionWindowGain)
}
func (b *bbrSender) GetRoundTripCount() int64      { return b.roundTripCount }
func (b *bbrSender) GetFullBandwidthReached() bool { return b.isAtFullBandwidth }
func (b *bbrSender) GetRecoveryState() string {
	switch b.recoveryState {
	case NOT_IN_RECOVERY:
		return "not_in_recovery"
	case CONSERVATION:
		return "conservation"
	case GROWTH:
		return "growth"
	default:
		return "unknown"
	}
}
func (b *bbrSender) GetAppLimited() bool { return b.sampler.isAppLimited }
func (b *bbrSender) GetAckAggregationHeight() protocol.ByteCount {
	return protocol.ByteCount(b.maxAckHeight.GetBest())
}
func (b *bbrSender) GetProbeBWCycleIndex() int             { return b.cycleCurrentOffset }
func (b *bbrSender) GetRecoveryWindow() protocol.ByteCount { return b.recoveryWindow }

var (
	_ SendAlgorithmRuntimeStats           = (*bbrSender)(nil)
	_ SendAlgorithmAvailablePacingBudget  = (*bbrSender)(nil)
	_ SendAlgorithmApplicationDataPending = (*bbrSender)(nil)
	_ SendAlgorithmBBRRuntimeStats        = (*bbrSender)(nil)
	_ SendAlgorithmEncryptionLevelAware   = (*bbrSender)(nil)
)
