# Deterministic WAN harness baseline

Run from the quic-go fork with:

```sh
go test ./integrationtests/self -run TestDeterministicWANPerformanceHarness -v -count=1
```

The test uses only in-memory simulated packet connections and Go's
`testing/synctest` clock. It requires no root, network namespace, `netem`, or
public host. The matrix covers RTT 20 / 80 / 170 ms, configured loss rates 0 /
0.1 / 0.5 / 1 percent, and maximum reorder depths 0 / 3 / 7 packets. A
deterministic 10 Mbps serialization rate bounds the link. The impaired profile
delays one packet by one RTT while allowing up to seven following packets to
arrive first. Bulk traffic is persistent 1200-byte QUIC DATAGRAM payloads.

## Baseline captured on 2026-09-20

Representative output from the current implementation (CUBIC, GSO unavailable
on the simulated connection):

| Profile | Useful Mbps | CWND | Pacing B/s | DATAGRAM queue | Blocked time | Packets lost / spurious | QUIC packets packed / UDP writes | Router drops / reordered |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20 ms, no loss, no reorder | 9.771 | 212,480 B | 1,578,818 | 512 / 512 | 9.998 s / 10 s | 0 / 0 | 10,376 / 10,632 | 0 / 0 |
| 170 ms, 0.5% configured loss, depth-7 reorder | 0.999 | 20,621 B | 149,902 | 512 / 512 | 9.934 s / 10 s | 9 / 6 | 1,105 / 1,110 | 5 / 63 |

This reproduces the target structure: with persistent application backlog, the
high-RTT reordered profile spends almost the whole interval blocked at the
bounded DATAGRAM queue while transport delivery and CUBIC window/pacing remain
far below the clean control. The impairment is intentionally deterministic;
it is not a prediction of public-Internet behavior.

The simulator does not advertise GSO, so these numbers do **not** validate
multi-segment UDP writes. Its sender emits one QUIC packet per UDP write. GSO
budget/segment behavior must be verified with focused sender tests and then on
the real deployment path. Counts can vary slightly with concurrent event-loop
interleaving; the fixed impairment schedule and broad invariants are stable.
