package congestion

import (
	"testing"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
)

// An ACK-only packet carries no retransmittable data, so it must not consume
// the pacer's token budget. The pre-merge code called pacer.SentPacket before
// checking isRetransmittable and therefore paced ACK-only packets as if they
// were data.
func TestCubicACKOnlyDoesNotConsumePacer(t *testing.T) {
	sender := NewCubicSender(
		DefaultClock{},
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		1200,
		false,
		nil,
	)
	now := monotime.Now()
	initialBudget := sender.pacer.budgetAtLastSent

	sender.OnPacketSent(now, 0, 1, 1200, false)
	if !sender.pacer.lastSentTime.IsZero() {
		t.Fatal("ACK-only packet updated the pacer's last-sent time")
	}
	if sender.pacer.budgetAtLastSent != initialBudget {
		t.Fatalf("ACK-only packet consumed pacing budget: %d -> %d", initialBudget, sender.pacer.budgetAtLastSent)
	}
	if sender.largestSentPacketNumber == 1 {
		t.Fatal("ACK-only packet advanced largestSentPacketNumber")
	}

	sender.OnPacketSent(now, 0, 2, 1200, true)
	if sender.pacer.lastSentTime.IsZero() {
		t.Fatal("retransmittable packet did not update the pacer's last-sent time")
	}
	if sender.pacer.budgetAtLastSent >= initialBudget {
		t.Fatalf("retransmittable packet did not consume pacing budget: %d -> %d", initialBudget, sender.pacer.budgetAtLastSent)
	}
	if sender.largestSentPacketNumber != protocol.PacketNumber(2) {
		t.Fatalf("largestSentPacketNumber = %d, want 2", sender.largestSentPacketNumber)
	}
}
