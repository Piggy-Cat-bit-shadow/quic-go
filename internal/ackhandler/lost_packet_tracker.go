package ackhandler

import (
	"iter"
	"slices"
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
)

type lostPacket struct {
	PacketNumber    protocol.PacketNumber
	SendTime        monotime.Time
	EncryptionLevel protocol.EncryptionLevel
	Trigger         lossTrigger
	LossDelay       time.Duration
	RTTAtLoss       time.Duration
	PacketThreshold uint64
}

type lossTrigger uint8

const (
	lossTriggerTime lossTrigger = iota + 1
	lossTriggerPacket
)

type lostPacketMetadata struct {
	trigger         lossTrigger
	lossDelay       time.Duration
	rttAtLoss       time.Duration
	packetThreshold uint64
	encryptionLevel protocol.EncryptionLevel
}

type lostPacketTracker struct {
	maxLength   int
	lostPackets []lostPacket
}

func newLostPacketTracker(maxLength int) *lostPacketTracker {
	return &lostPacketTracker{
		maxLength: maxLength,
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, metadata ...lostPacketMetadata) {
	var meta lostPacketMetadata
	if len(metadata) > 0 {
		meta = metadata[0]
	}
	if len(t.lostPackets) == t.maxLength {
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber:    p,
		SendTime:        sendTime,
		EncryptionLevel: meta.encryptionLevel,
		Trigger:         meta.trigger,
		LossDelay:       meta.lossDelay,
		RTTAtLoss:       meta.rttAtLoss,
		PacketThreshold: meta.packetThreshold,
	})
}

func (t *lostPacketTracker) Get(pn protocol.PacketNumber) (lostPacket, bool) {
	for _, p := range t.lostPackets {
		if p.PacketNumber == pn {
			return p, true
		}
	}
	return lostPacket{}, false
}

func (t *lostPacketTracker) Trigger(pn protocol.PacketNumber) lossTrigger {
	for _, p := range t.lostPackets {
		if p.PacketNumber == pn {
			return p.Trigger
		}
	}
	return 0
}

// Delete deletes a packet from the lost packet tracker.
// This function is not optimized for performance if many packets are lost,
// but it is only used when a spurious loss is detected, which is rare.
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) {
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		return p.PacketNumber == pn
	})
}

func (t *lostPacketTracker) All() iter.Seq2[protocol.PacketNumber, monotime.Time] {
	return func(yield func(protocol.PacketNumber, monotime.Time) bool) {
		for _, p := range t.lostPackets {
			if !yield(p.PacketNumber, p.SendTime) {
				return
			}
		}
	}
}

func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) {
	if len(t.lostPackets) == 0 {
		return
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
}
