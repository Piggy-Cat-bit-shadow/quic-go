package congestion

import (
	"testing"
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func newTestBBRSender() *bbrSender {
	return NewBBRSender(DefaultClock{}, utils.NewRTTStats(), &utils.ConnectionStats{}, protocol.ByteCount(protocol.InitialPacketSize), nil)
}

func TestBBRRecoveryBoundaryDoesNotFollowEveryACK(t *testing.T) {
	b := newTestBBRSender()
	b.lastSendPacket = 100
	b.UpdateRecoveryState(1, true, false)
	require.Equal(t, protocol.PacketNumber(100), b.endRecoveryAt)
	require.Equal(t, bbrRecoveryState(CONSERVATION), b.recoveryState)

	// Ordinary ACKs must not move the recovery boundary to each latest send.
	b.lastSendPacket = 120
	b.UpdateRecoveryState(100, false, true)
	require.Equal(t, bbrRecoveryState(GROWTH), b.recoveryState)
	require.Equal(t, protocol.PacketNumber(100), b.endRecoveryAt)
	b.UpdateRecoveryState(101, false, false)
	require.Equal(t, bbrRecoveryState(NOT_IN_RECOVERY), b.recoveryState)
}

func TestBBRPacerUsesAlreadyGainAdjustedRate(t *testing.T) {
	b := newTestBBRSender()
	b.pacingRate = Bandwidth(800_000) // bits/s, 100 kB/s
	require.Equal(t, uint64(100_000), b.pacer.PacingRate())
	require.Equal(t, uint64(100_000), b.GetPacingRate()) // runtime API is bytes/s
}

func TestBBRInitialWindowAndApplicationLimitedTransitions(t *testing.T) {
	b := newTestBBRSender()
	require.Equal(t, protocol.ByteCount(32*protocol.InitialPacketSize), b.GetCongestionWindow())
	b.SetApplicationDataPending(true)
	require.False(t, b.GetAppLimited())
	b.SetApplicationDataPending(false)
	require.True(t, b.GetAppLimited())
	require.Equal(t, uint64(1), b.applicationLimitedTransitions)
	b.SetApplicationDataPending(false)
	require.Equal(t, uint64(1), b.applicationLimitedTransitions)
	b.SetApplicationDataPending(true)
	b.SetApplicationDataPending(false)
	require.Equal(t, uint64(2), b.applicationLimitedTransitions)
}

func TestBBRUnknownSamplerPacketIsSafe(t *testing.T) {
	b := newTestBBRSender()
	before := b.congestionWindow
	b.OnPacketAcked(10, 1200, 1200, monotime.Time(time.Second))
	require.Equal(t, before, b.congestionWindow)
	b.OnCongestionEvent(10, 1200, 1200)
	require.Equal(t, uint64(1), b.connStats.PacketsLost.Load())
	require.Equal(t, uint64(1200), b.connStats.BytesLost.Load())
}

func TestBBRPacketNumberSpacesDoNotAliasSamplerState(t *testing.T) {
	b := newTestBBRSender()
	when := monotime.Time(time.Second)
	b.OnPacketSentWithEncryptionLevel(protocol.EncryptionHandshake, when, 0, 7, 1200, true)
	b.OnPacketSentWithEncryptionLevel(protocol.Encryption1RTT, when.Add(time.Millisecond), 1200, 7, 1200, true)
	require.Len(t, b.sampler.connectionStats.stats, 1)
	require.Equal(t, protocol.ByteCount(2400), b.bytesInFlight)
	b.OnPacketAckedWithEncryptionLevel(protocol.EncryptionHandshake, 7, 1200, 1200, when.Add(2*time.Millisecond))
	require.Len(t, b.sampler.connectionStats.stats, 1)
	require.Equal(t, protocol.ByteCount(1200), b.bytesInFlight)
	b.OnPacketAckedWithEncryptionLevel(protocol.Encryption1RTT, 7, 1200, 1200, when.Add(3*time.Millisecond))
	require.Empty(t, b.sampler.connectionStats.stats)
	require.Zero(t, b.bytesInFlight)
}

func TestBandwidthSamplerReleasesACKedAndLostPacketState(t *testing.T) {
	s := NewBandwidthSampler()
	const packetCount = 100_000
	for i := 1; i <= packetCount; i++ {
		s.OnPacketSent(monotime.Time(i), protocol.PacketNumber(i), 1200, 1200, true)
	}
	for i := 1; i <= packetCount; i++ {
		if i%2 == 0 {
			s.OnPacketAcked(monotime.Time(packetCount+i), protocol.PacketNumber(i))
		} else {
			s.OnPacketLost(protocol.PacketNumber(i))
		}
	}
	require.Empty(t, s.connectionStats.stats)
}

func TestBBRAvailablePacingBudgetHonorsEffectiveWindow(t *testing.T) {
	b := newTestBBRSender()
	b.pacingRate = Bandwidth(10_000_000)
	b.pacer.budgetAtLastSent = 100_000
	b.pacer.lastSentTime = monotime.Time(1)
	cwnd := b.GetCongestionWindow()
	require.Equal(t, protocol.ByteCount(500), b.AvailablePacingBudget(monotime.Time(1), cwnd-500))
	require.Zero(t, b.AvailablePacingBudget(monotime.Time(1), cwnd+1))
}

func TestBBRHighBDPNumericalBounds(t *testing.T) {
	for _, rate := range []uint64{1_000_000_000, 10_000_000_000} {
		b := newTestBBRSender()
		b.maxBandwidth.Update(int64(rate), 1)
		b.minRtt = 200 * time.Millisecond
		got := b.GetTargetCongestionWindow(2)
		require.Greater(t, got, protocol.ByteCount(0))
		require.Less(t, got, protocol.MaxByteCount)
	}
	b := newTestBBRSender()
	b.maxBandwidth.Update(int64(10_000_000_000), 1)
	b.minRtt = time.Duration(1<<63 - 1)
	require.Equal(t, protocol.MaxByteCount, b.GetTargetCongestionWindow(2))
	require.Equal(t, protocol.MaxByteCount, saturatingMulDiv(^uint64(0), ^uint64(0), 1))
}

func TestBBRSetMaxDatagramSizePreservesModel(t *testing.T) {
	b := newTestBBRSender()
	b.maxBandwidth.Update(8_000_000, 1)
	b.minRtt = 80 * time.Millisecond
	before := b.BandwidthEstimate()
	b.SetMaxDatagramSize(1441)
	require.Equal(t, protocol.ByteCount(1441), b.maxDatagramSize)
	require.Equal(t, protocol.ByteCount(1441), b.pacer.maxDatagramSize)
	require.Equal(t, before, b.BandwidthEstimate())
	require.Equal(t, uint64(1_000_000), b.pacer.PacingRate())
}

func BenchmarkBBRPacketAck(b *testing.B) {
	sender := NewBBRSender(DefaultClock{}, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, nil)
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		pn := protocol.PacketNumber(i)
		at := monotime.Time(i * int(time.Millisecond))
		sender.OnPacketSent(at, 0, pn, 1200, true)
		sender.OnPacketAcked(pn, 1200, 1200, at.Add(time.Millisecond))
	}
}

func BenchmarkCubicPacketAck(b *testing.B) {
	sender := NewCubicSender(DefaultClock{}, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, false, nil)
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		pn := protocol.PacketNumber(i)
		at := monotime.Time(i * int(time.Millisecond))
		sender.OnPacketSent(at, 0, pn, 1200, true)
		sender.OnPacketAcked(pn, 1200, 1200, at.Add(time.Millisecond))
	}
}

func BenchmarkBBRPacketLoss(b *testing.B) {
	sender := NewBBRSender(DefaultClock{}, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, nil)
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		pn := protocol.PacketNumber(i)
		sender.OnPacketSent(monotime.Time(i*int(time.Millisecond)), 0, pn, 1200, true)
		sender.OnCongestionEvent(pn, 1200, 1200)
	}
}

func BenchmarkBandwidthSampler(b *testing.B) {
	sampler := NewBandwidthSampler()
	b.ResetTimer()
	for i := 1; i <= b.N; i++ {
		pn := protocol.PacketNumber(i)
		at := monotime.Time(i * int(time.Millisecond))
		sampler.OnPacketSent(at, pn, 1200, 0, true)
		sampler.OnPacketAcked(at.Add(time.Millisecond), pn)
	}
}
