package congestion

import (
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(protocol.ByteCount)
}

// A SendAlgorithmWithDebugInfos is a SendAlgorithm that exposes some debug infos
type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() protocol.ByteCount
}

// SendAlgorithmRuntimeStats is optional so existing congestion-controller
// implementations and test doubles remain source-compatible.
type SendAlgorithmRuntimeStats interface {
	GetPacingRate() uint64
	GetCongestionControllerName() string
}

type SendAlgorithmCubicRuntimeStats interface {
	GetApplicationLimitedTransitions() uint64
	GetCubicEpochResets() uint64
	GetCwndCutbacks() uint64
	GetRecoveryEnter() uint64
	GetRecoveryExit() uint64
	GetRecoveryDuration() time.Duration
}

// SendAlgorithmAvailablePacingBudget reports the current pacing token budget
// capped by remaining congestion-window bytes.
type SendAlgorithmAvailablePacingBudget interface {
	AvailablePacingBudget(now monotime.Time, bytesInFlight protocol.ByteCount) protocol.ByteCount
}

// SendAlgorithmApplicationDataPending is implemented by controllers whose
// epoch logic distinguishes an idle application from a transport-limited one.
type SendAlgorithmApplicationDataPending interface {
	SetApplicationDataPending(bool)
}
