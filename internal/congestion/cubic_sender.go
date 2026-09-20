package congestion

import (
	"fmt"
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/utils"
	"github.com/metacubex/quic-go/qlog"
	"github.com/metacubex/quic-go/qlogwriter"
)

const (
	// maxDatagramSize is the default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	initialMaxDatagramSize     = protocol.ByteCount(protocol.InitialPacketSize)
	maxBurstPackets            = 3
	renoBeta                   = 0.7 // Reno backoff factor.
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32
)

type cubicSender struct {
	hybridSlowStart HybridSlowStart
	rttStats        *utils.RTTStats
	connStats       *utils.ConnectionStats
	cubic           *Cubic
	pacer           *pacer
	clock           Clock

	reno bool

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Whether the last loss event caused us to exit slowstart.
	// Used for stats collection of slowstartPacketsLost
	lastCutbackExitedSlowstart    bool
	applicationDataPending        bool
	applicationLimited            bool
	applicationLimitedTransitions uint64
	cubicEpochResets              uint64
	cwndCutbacks                  uint64
	recoveryEnterCount            uint64
	recoveryExitCount             uint64
	recoveryDuration              time.Duration
	recoveryStartedAt             monotime.Time

	// Congestion window in bytes.
	congestionWindow protocol.ByteCount

	// Slow start congestion window in bytes, aka ssthresh.
	slowStartThreshold protocol.ByteCount

	// ACK counter for the Reno implementation.
	numAckedPackets uint64

	initialCongestionWindow    protocol.ByteCount
	initialMaxCongestionWindow protocol.ByteCount

	maxDatagramSize protocol.ByteCount

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder
}

var (
	_ SendAlgorithm               = &cubicSender{}
	_ SendAlgorithmWithDebugInfos = &cubicSender{}
)

// NewCubicSender makes a new cubic sender
func NewCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	reno bool,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	return newCubicSender(
		clock,
		rttStats,
		connStats,
		reno,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		qlogger,
	)
}

func newCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	reno bool,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *cubicSender {
	c := &cubicSender{
		rttStats:                   rttStats,
		connStats:                  connStats,
		largestSentPacketNumber:    protocol.InvalidPacketNumber,
		largestAckedPacketNumber:   protocol.InvalidPacketNumber,
		largestSentAtLastCutback:   protocol.InvalidPacketNumber,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		slowStartThreshold:         protocol.MaxByteCount,
		cubic:                      NewCubic(clock),
		clock:                      clock,
		reno:                       reno,
		qlogger:                    qlogger,
		maxDatagramSize:            initialMaxDatagramSize,
	}
	c.pacer = newPacer(c.BandwidthEstimate)
	if c.qlogger != nil {
		c.lastState = qlog.CongestionStateSlowStart
		c.qlogger.RecordEvent(qlog.CongestionStateUpdated{
			State: qlog.CongestionStateSlowStart,
		})
	}
	return c
}

// TimeUntilSend returns when the next packet should be sent.
func (c *cubicSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return c.pacer.TimeUntilSend()
}

func (c *cubicSender) HasPacingBudget(now monotime.Time) bool {
	return c.pacer.Budget(now) >= c.maxDatagramSize
}

func (c *cubicSender) AvailablePacingBudget(now monotime.Time, bytesInFlight protocol.ByteCount) protocol.ByteCount {
	return min(c.pacer.Budget(now), max(protocol.ByteCount(0), c.GetCongestionWindow()-bytesInFlight))
}

func (c *cubicSender) maxCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (c *cubicSender) minCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * minCongestionWindowPackets
}

func (c *cubicSender) OnPacketSent(
	sentTime monotime.Time,
	_ protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	c.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	c.largestSentPacketNumber = packetNumber
	c.hybridSlowStart.OnPacketSent(packetNumber)
}

func (c *cubicSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < c.GetCongestionWindow()
}

func (c *cubicSender) InRecovery() bool {
	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
}

func (c *cubicSender) InSlowStart() bool {
	return c.GetCongestionWindow() < c.slowStartThreshold
}

func (c *cubicSender) GetCongestionWindow() protocol.ByteCount {
	return c.congestionWindow
}

func (c *cubicSender) GetPacingRate() uint64 {
	return c.pacer.PacingRate()
}

func (c *cubicSender) GetCongestionControllerName() string {
	return "cubic"
}

func (c *cubicSender) MaybeExitSlowStart() {
	if c.InSlowStart() &&
		c.hybridSlowStart.ShouldExitSlowStart(c.rttStats.LatestRTT(), c.rttStats.MinRTT(), c.GetCongestionWindow()/c.maxDatagramSize) {
		// exit slow start
		c.slowStartThreshold = c.congestionWindow
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

func (c *cubicSender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	wasInRecovery := c.InRecovery()
	c.largestAckedPacketNumber = max(ackedPacketNumber, c.largestAckedPacketNumber)
	if wasInRecovery && !c.InRecovery() {
		c.finishRecovery(eventTime)
	}
	if c.InRecovery() {
		return
	}
	c.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
	if c.InSlowStart() {
		c.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

func (c *cubicSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	c.connStats.PacketsLost.Add(1)
	c.connStats.BytesLost.Add(uint64(lostBytes))

	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= c.largestSentAtLastCutback {
		return
	}
	wasInRecovery := c.InRecovery()
	c.lastCutbackExitedSlowstart = c.InSlowStart()
	c.maybeQlogStateChange(qlog.CongestionStateRecovery)

	if c.reno {
		c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
	} else {
		c.congestionWindow = c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
	}
	if minCwnd := c.minCongestionWindow(); c.congestionWindow < minCwnd {
		c.congestionWindow = minCwnd
	}
	c.slowStartThreshold = c.congestionWindow
	c.largestSentAtLastCutback = c.largestSentPacketNumber
	c.cwndCutbacks++
	if !wasInRecovery {
		c.recoveryEnterCount++
		c.recoveryStartedAt = c.clock.Now()
	}
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	c.numAckedPackets = 0
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
func (c *cubicSender) maybeIncreaseCwnd(
	_ protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !c.isCwndLimited(priorInFlight) {
		if !c.applicationDataPending {
			if !c.applicationLimited {
				c.applicationLimitedTransitions++
				c.applicationLimited = true
			}
			c.cubicEpochResets++
			c.cubic.OnApplicationLimited()
			c.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
		}
		return
	}
	c.applicationLimited = false
	if c.congestionWindow >= c.maxCongestionWindow() {
		return
	}
	if c.InSlowStart() {
		// TCP slow start, exponential growth, increase by one for each ACK.
		c.congestionWindow += c.maxDatagramSize
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
		return
	}
	// Congestion avoidance
	c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	if c.reno {
		// Classic Reno congestion avoidance.
		c.numAckedPackets++
		if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
			c.congestionWindow += c.maxDatagramSize
			c.numAckedPackets = 0
		}
	} else {
		c.congestionWindow = min(
			c.maxCongestionWindow(),
			c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime),
		)
	}
}

func (c *cubicSender) SetApplicationDataPending(pending bool) {
	c.applicationDataPending = pending
	if pending {
		c.applicationLimited = false
	}
}

func (c *cubicSender) GetApplicationLimitedTransitions() uint64 {
	return c.applicationLimitedTransitions
}

func (c *cubicSender) GetCubicEpochResets() uint64 { return c.cubicEpochResets }

func (c *cubicSender) GetCwndCutbacks() uint64  { return c.cwndCutbacks }
func (c *cubicSender) GetRecoveryEnter() uint64 { return c.recoveryEnterCount }
func (c *cubicSender) GetRecoveryExit() uint64  { return c.recoveryExitCount }
func (c *cubicSender) GetRecoveryDuration() time.Duration {
	duration := c.recoveryDuration
	if !c.recoveryStartedAt.IsZero() {
		now := c.clock.Now()
		if now.After(c.recoveryStartedAt) {
			duration += now.Sub(c.recoveryStartedAt)
		}
	}
	return duration
}

func (c *cubicSender) finishRecovery(now monotime.Time) {
	c.recoveryExitCount++
	if !c.recoveryStartedAt.IsZero() && now.After(c.recoveryStartedAt) {
		c.recoveryDuration += now.Sub(c.recoveryStartedAt)
	}
	c.recoveryStartedAt = 0
}

func (c *cubicSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := c.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := c.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstPackets*c.maxDatagramSize
}

// BandwidthEstimate returns the current bandwidth estimate
func (c *cubicSender) BandwidthEstimate() Bandwidth {
	srtt := c.rttStats.SmoothedRTT()
	if srtt == 0 {
		// This should never happen, but if it does, avoid division by zero.
		srtt = protocol.TimerGranularity
	}
	return BandwidthFromDelta(c.GetCongestionWindow(), srtt)
}

// OnRetransmissionTimeout is called on an retransmission timeout
func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if c.InRecovery() {
		c.finishRecovery(c.clock.Now())
	}
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	c.hybridSlowStart.Restart()
	c.cubic.Reset()
	c.slowStartThreshold = c.congestionWindow / 2
	c.congestionWindow = c.minCongestionWindow()
}

// OnConnectionMigration is called when the connection is migrated (?)
func (c *cubicSender) OnConnectionMigration() {
	if c.InRecovery() {
		c.finishRecovery(c.clock.Now())
	}
	c.hybridSlowStart.Restart()
	c.largestSentPacketNumber = protocol.InvalidPacketNumber
	c.largestAckedPacketNumber = protocol.InvalidPacketNumber
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	c.lastCutbackExitedSlowstart = false
	c.cubic.Reset()
	c.numAckedPackets = 0
	c.congestionWindow = c.initialCongestionWindow
	c.slowStartThreshold = c.initialMaxCongestionWindow
}

func (c *cubicSender) maybeQlogStateChange(new qlog.CongestionState) {
	if c.qlogger == nil || new == c.lastState {
		return
	}
	c.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: new})
	c.lastState = new
}

func (c *cubicSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < c.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", c.maxDatagramSize, s))
	}
	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
	c.maxDatagramSize = s
	if cwndIsMinCwnd {
		c.congestionWindow = c.minCongestionWindow()
	}
	c.pacer.SetMaxDatagramSize(s)
}
