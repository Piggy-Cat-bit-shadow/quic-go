package self_test

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/testutils/simnet"
	"github.com/stretchr/testify/require"
)

// deterministicWANRouter impairs only full-sized short-header traffic. Every
// Nth such packet is dropped; groups of eight are reordered by holding the
// first packet for one RTT while the following seven are delivered normally.
// The router never reads packet contents or uses wall-clock randomness.
type deterministicWANRouter struct {
	simnet.PerfectRouter
	rtt         time.Duration
	bandwidth   uint64
	lossEvery   int
	reorderSize int
	mu          sync.Mutex
	seq         map[string]int
	reorder     map[string]int
	held        map[string]simnet.Packet
	nextWrite   map[string]time.Time
	dropped     atomic.Uint64
	reordered   atomic.Uint64
	reorderOps  atomic.Uint64
}

const deterministicReorderOperations = 12

func (r *deterministicWANRouter) deliver(p simnet.Packet, direction string) error {
	if r.bandwidth == 0 {
		return r.PerfectRouter.SendPacket(p)
	}
	delay := r.reserveSerialization(p, direction)
	if delay <= 0 {
		return r.PerfectRouter.SendPacket(p)
	}
	time.AfterFunc(delay, func() { _ = r.PerfectRouter.SendPacket(p) })
	return nil
}

func (r *deterministicWANRouter) reserveSerialization(p simnet.Packet, direction string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nextWrite == nil {
		r.nextWrite = make(map[string]time.Time)
	}
	now := time.Now()
	start := r.nextWrite[direction]
	if start.Before(now) {
		start = now
	}
	serialization := time.Duration(uint64(len(p.Data)) * 8 * uint64(time.Second) / r.bandwidth)
	r.nextWrite[direction] = start.Add(serialization)
	return r.nextWrite[direction].Sub(now)
}

func (r *deterministicWANRouter) SendPacket(p simnet.Packet) error {
	fromIP, toIP := "", ""
	if addr, ok := p.From.(*net.UDPAddr); ok {
		fromIP = addr.IP.String()
	}
	if addr, ok := p.To.(*net.UDPAddr); ok {
		toIP = addr.IP.String()
	}
	direction := fromIP + "->" + toIP // all flows share the same directional bottleneck
	if len(p.Data) < 1100 {
		return r.deliver(p, direction)
	}
	r.mu.Lock()
	if r.seq == nil {
		r.seq = make(map[string]int)
		r.reorder = make(map[string]int)
		r.held = make(map[string]simnet.Packet)
	}
	r.seq[direction]++
	seq := r.seq[direction]
	if r.lossEvery > 0 && seq%r.lossEvery == 0 {
		r.dropped.Add(1)
		r.mu.Unlock()
		if r.bandwidth > 0 {
			_ = r.reserveSerialization(p, direction)
		}
		return nil
	}
	if r.reorderSize <= 0 {
		r.mu.Unlock()
		return r.deliver(p, direction)
	}
	count := r.reorder[direction]
	if count == 0 && (seq%128 != 1 || r.reorderOps.Load() >= deterministicReorderOperations) {
		r.mu.Unlock()
		return r.deliver(p, direction)
	}
	if count == 0 {
		r.held[direction] = p
		r.reorder[direction] = 1
		r.mu.Unlock()
		return nil
	}
	r.reorder[direction] = count + 1
	if count+1 < r.reorderSize+1 {
		r.mu.Unlock()
		return r.deliver(p, direction)
	}
	held := r.held[direction]
	delete(r.held, direction)
	r.reorder[direction] = 0
	r.reordered.Add(uint64(r.reorderSize))
	r.reorderOps.Add(1)
	r.mu.Unlock()
	if err := r.deliver(p, direction); err != nil {
		return err
	}
	time.AfterFunc(r.rtt, func() { _ = r.deliver(held, direction) })
	return nil
}

type deterministicWANCase struct {
	rtt         time.Duration
	lossEvery   int
	reorderSize int
}

func TestDeterministicWANPerformanceHarness(t *testing.T) {
	var cases []deterministicWANCase
	for _, rtt := range []time.Duration{20 * time.Millisecond, 80 * time.Millisecond, 170 * time.Millisecond} {
		for _, lossEvery := range []int{0, 200} { // 0 and 0.5%, fixed every-200th full-size datagram.
			for _, reorderSize := range []int{0, 7} {
				cases = append(cases, deterministicWANCase{rtt: rtt, lossEvery: lossEvery, reorderSize: reorderSize})
			}
		}
	}
	for _, controller := range []string{"cubic", "bbr"} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("cc=%s/rtt=%s/lossEvery=%d/reorder=%d", controller, tc.rtt, tc.lossEvery, tc.reorderSize), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					const (
						payloadSize = 1200
						duration    = 10 * time.Second
					)
					clientAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9001}
					serverAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9002}
					router := &deterministicWANRouter{rtt: tc.rtt, bandwidth: 10_000_000, lossEvery: tc.lossEvery, reorderSize: tc.reorderSize}
					network := &simnet.Simnet{Router: router}
					settings := simnet.NodeBiDiLinkSettings{Latency: tc.rtt / 2}
					clientPacketConn := network.NewEndpoint(clientAddr, settings)
					serverPacketConn := network.NewEndpoint(serverAddr, settings)
					require.NoError(t, network.Start())
					defer network.Close()
					defer clientPacketConn.Close()
					defer serverPacketConn.Close()

					server, err := quic.Listen(serverPacketConn, getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
					require.NoError(t, err)
					defer server.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					client, err := quic.Dial(ctx, clientPacketConn, serverPacketConn.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
					require.NoError(t, err)
					defer client.CloseWithError(0, "")
					serverConn, err := server.Accept(ctx)
					require.NoError(t, err)
					defer serverConn.CloseWithError(0, "")
					if controller == "bbr" {
						serverConn.SetBBRCongestionControl()
					} else {
						serverConn.SetCubicCongestionControl()
					}

					sampleCtx, stopSamples := context.WithCancel(ctx)
					type senderSample struct {
						cwnd, pacing, datagramDepth, bbrBandwidth uint64
						latestRTT                                 time.Duration
						bbrMode                                   string
					}
					var sampleMu sync.Mutex
					var samples []senderSample
					sampleDone := make(chan struct{})
					go func() {
						defer close(sampleDone)
						ticker := time.NewTicker(50 * time.Millisecond)
						defer ticker.Stop()
						for {
							select {
							case <-sampleCtx.Done():
								return
							case <-ticker.C:
								stats := serverConn.RuntimeStats()
								sampleMu.Lock()
								samples = append(samples, senderSample{cwnd: stats.CongestionWindow, pacing: stats.PacingRate, datagramDepth: stats.DatagramSendQueueDepth, latestRTT: stats.LatestRTT, bbrMode: stats.BBRMode, bbrBandwidth: stats.BBRBandwidthEstimate})
								sampleMu.Unlock()
							}
						}
					}()

					var receivedBytes atomic.Uint64
					go func() {
						for {
							p, readErr := client.ReceiveDatagram(ctx)
							if readErr != nil {
								return
							}
							receivedBytes.Add(uint64(len(p)))
						}
					}()
					payload := make([]byte, payloadSize)
					var enqueuedBytes atomic.Uint64
					go func() {
						for {
							if sendErr := serverConn.SendDatagram(payload); sendErr != nil {
								return
							}
							enqueuedBytes.Add(payloadSize)
						}
					}()

					time.Sleep(duration)
					stopSamples()
					<-sampleDone
					synctest.Wait()
					stats := serverConn.RuntimeStats()
					require.Equal(t, controller, stats.CongestionController)
					require.Equal(t, uint64(512), stats.DatagramSendQueueHighWater, "persistent app backlog should fill the bounded DATAGRAM queue")
					require.Greater(t, stats.DatagramSendBlocked, uint64(0))
					require.Greater(t, stats.PacketsPacked, uint64(0))
					require.Greater(t, stats.UDPWrites, uint64(0))
					require.Greater(t, receivedBytes.Load(), uint64(0))
					require.Greater(t, enqueuedBytes.Load(), receivedBytes.Load())
					if tc.lossEvery > 0 {
						require.Greater(t, router.dropped.Load(), uint64(0), "configured deterministic loss must actually drop packets")
					} else {
						require.Zero(t, router.dropped.Load(), "clean/reorder-only trace must not inject loss")
					}
					if tc.reorderSize > 0 {
						require.Greater(t, router.reordered.Load(), uint64(0), "configured deterministic reordering must actually be exercised")
						require.LessOrEqual(t, router.reorderOps.Load(), uint64(deterministicReorderOperations), "reorder schedule must stay within its fixed operation budget")
					} else {
						require.Zero(t, router.reordered.Load(), "no-reorder trace must not reorder packets")
					}
					sampleMu.Lock()
					cwndMin, cwndMax, pacingMin, pacingMax := ^uint64(0), uint64(0), ^uint64(0), uint64(0)
					var cwndTotal, pacingTotal, datagramFullSamples uint64
					loadedRTTs := make([]time.Duration, 0, len(samples))
					for _, sample := range samples {
						cwndMin, cwndMax = min(cwndMin, sample.cwnd), max(cwndMax, sample.cwnd)
						pacingMin, pacingMax = min(pacingMin, sample.pacing), max(pacingMax, sample.pacing)
						cwndTotal += sample.cwnd
						pacingTotal += sample.pacing
						if sample.datagramDepth >= 512 {
							datagramFullSamples++
						}
						if sample.latestRTT > 0 {
							loadedRTTs = append(loadedRTTs, sample.latestRTT)
						}
					}
					slices.Sort(loadedRTTs)
					percentile := func(p int) time.Duration {
						if len(loadedRTTs) == 0 {
							return 0
						}
						index := (p*len(loadedRTTs)+99)/100 - 1
						return loadedRTTs[max(0, index)]
					}
					sampleCount := uint64(len(samples))
					sampleMu.Unlock()
					var cwndAvg, pacingAvg float64
					if sampleCount > 0 {
						cwndAvg = float64(cwndTotal) / float64(sampleCount)
						pacingAvg = float64(pacingTotal) / float64(sampleCount)
					}
					blockedRatio := float64(stats.DatagramSendBlockedDuration) / float64(duration)
					if blockedRatio > 1 {
						blockedRatio = 1
					}
					datagramFullRatio := float64(0)
					if sampleCount > 0 {
						datagramFullRatio = float64(datagramFullSamples) / float64(sampleCount)
					}
					t.Logf("trace_seed=1 cc=%s schedule=drop-every-N/reorder-groups-every-128-full-size-packets capped-at-12 rtt=%s loss_every=%d reorder=%d goodput_mbps=%.3f loaded_rtt_p50=%s loaded_rtt_p95=%s loaded_rtt_p99=%s bbr_mode=%s bbr_bw_bps=%d cwnd_final=%d cwnd_avg=%0.f cwnd_min=%d cwnd_max=%d pacing_final_Bps=%d pacing_avg_Bps=%0.f pacing_min_Bps=%d pacing_max_Bps=%d adaptive_packet_threshold=%d adaptive_time_threshold=%s reported_losses=%d loss_events=%d loss_by_packet=%d loss_by_time=%d spurious=%d spurious_after_packet=%d spurious_after_time=%d cwnd_cutbacks=%d cutback_loss=%d recovery_enter=%d recovery_exit=%d recovery_duration=%s injected_drops=%d reorder_ops=%d reordered_packets=%d datagram_full_ratio=%.3f datagram_blocked_ratio=%.3f packets_per_wakeup=%.2f segments_per_write_avg=%.2f app_limited_transitions=%d cubic_epoch_resets=%d", controller, tc.rtt, tc.lossEvery, tc.reorderSize, float64(receivedBytes.Load())*8/duration.Seconds()/1e6, percentile(50), percentile(95), percentile(99), stats.BBRMode, stats.BBRBandwidthEstimate, stats.CongestionWindow, cwndAvg, cwndMin, cwndMax, stats.PacingRate, pacingAvg, pacingMin, pacingMax, stats.AdaptivePacketThreshold, stats.AdaptiveTimeThreshold, stats.PacketsLost, stats.LossEvents, stats.LossByPacketThreshold, stats.LossByTimeThreshold, stats.SpuriousLosses, stats.SpuriousAfterPacketThreshold, stats.SpuriousAfterTimeThreshold, stats.CwndCutbacks, stats.CutbackDueToLossEvent, stats.RecoveryEnter, stats.RecoveryExit, stats.RecoveryDuration, router.dropped.Load(), router.reorderOps.Load(), router.reordered.Load(), datagramFullRatio, blockedRatio, float64(stats.PacketsPacked)/float64(max(stats.PacingWakeups, 1)), stats.SegmentsPerWriteAverage, stats.ApplicationLimitedTransitions, stats.CubicEpochResets)
				})
			})
		}
	}
}

func TestDeterministicWANConnectionFairness(t *testing.T) {
	for _, controllers := range [][2]string{{"bbr", "bbr"}, {"bbr", "cubic"}} {
		name := controllers[0] + "+" + controllers[1]
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const duration = 5 * time.Second
				router := &deterministicWANRouter{rtt: 80 * time.Millisecond, bandwidth: 10_000_000}
				network := &simnet.Simnet{Router: router}
				clientPCs := make([]net.PacketConn, 2)
				serverPCs := make([]net.PacketConn, 2)
				for i := range 2 {
					basePort := 9100 + i*2
					settings := simnet.NodeBiDiLinkSettings{Latency: 40 * time.Millisecond}
					clientPCs[i] = network.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: basePort}, settings)
					serverPCs[i] = network.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: basePort + 1}, settings)
				}
				require.NoError(t, network.Start())
				type flow struct {
					server, client *quic.Conn
					listener       *quic.Listener
					cancel         context.CancelFunc
					bytes          atomic.Uint64
				}
				flows := make([]*flow, 2)
				for i, controller := range controllers {
					listener, err := quic.Listen(serverPCs[i], getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
					require.NoError(t, err)
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					clientConn, err := quic.Dial(ctx, clientPCs[i], serverPCs[i].LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true}))
					require.NoError(t, err)
					serverConn, err := listener.Accept(ctx)
					require.NoError(t, err)
					if controller == "bbr" {
						serverConn.SetBBRCongestionControl()
					} else {
						serverConn.SetCubicCongestionControl()
					}
					flows[i] = &flow{server: serverConn, client: clientConn, listener: listener, cancel: cancel}
					go func(f *flow) {
						for {
							p, readErr := f.client.ReceiveDatagram(ctx)
							if readErr != nil {
								return
							}
							f.bytes.Add(uint64(len(p)))
						}
					}(flows[i])
				}
				payload := make([]byte, 1200)
				for _, f := range flows {
					go func(f *flow) {
						for {
							if err := f.server.SendDatagram(payload); err != nil {
								return
							}
						}
					}(f)
				}
				time.Sleep(duration)
				for _, f := range flows {
					f.cancel()
					_ = f.server.CloseWithError(0, "fairness test complete")
					_ = f.client.CloseWithError(0, "fairness test complete")
					_ = f.listener.Close()
				}
				for i := range 2 {
					_ = clientPCs[i].Close()
					_ = serverPCs[i].Close()
				}
				_ = network.Close()
				synctest.Wait()
				first, second := flows[0].bytes.Load(), flows[1].bytes.Load()
				require.Greater(t, first, uint64(0), "flow 0 was starved")
				require.Greater(t, second, uint64(0), "flow 1 was starved")
				ratio := float64(min(first, second)) / float64(max(first, second))
				require.Greater(t, ratio, 0.01, "one controller received less than 1%% of shared-link delivery")
				t.Logf("fairness trace=clean rtt=80ms bandwidth_mbps=10 cc=%s/%s received_bytes=%d/%d ratio=%.4f", controllers[0], controllers[1], first, second, ratio)
			})
		})
	}
}
