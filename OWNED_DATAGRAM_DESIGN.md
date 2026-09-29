# Owned DATAGRAM: design and release-point proof

Patch to `github.com/sagernet/quic-go` at `QUIC_BASE_SHA = 0cae1a7786ee290bd9ecce40b6782d4c227ef1d6`
(tag `v0.61.0-sing-box-mod.7`), verified byte-identical to the module sing-box compiles against.

## The two copies

| # | Site | Code |
|---|---|---|
| 1 | `http3/conn.go` `rawConn.sendDatagram` | `data := make([]byte, 0, len(b)+8)` … `data = append(data, b...)` |
| 2 | `connection.go` `Conn.SendDatagram` | `f.Data = make([]byte, len(p))` … `copy(f.Data, p)` |

Copy #1 even carries an upstream `// TODO: this creates a lot of garbage and an additional copy`.

## Release point: proved from source, not assumed

The question the task asks is *when* the payload may be released. The obvious answer — "when the
frame leaves the send queue" — is **wrong**, and the source shows why.

### `datagramQueue.Pop()` does not serialize

```go
func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	...
}
```

It unlinks. It does not touch `Data`.

### The payload is read much later, in the packet builder

`packet_packer.go` peeks the frame and puts it in the payload's frame list:

```go
if f := p.datagramQueue.Peek(); f != nil {
	size := f.Length(v)
	if size <= maxPayloadSize-pl.length {   // fits
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
		pl.length += size
		p.datagramQueue.Pop()
	} else if pl.ack == nil {
		p.datagramQueue.Pop()               // DISCARDED, never serialized
	}
	...
}
```

Serialization happens in a separate function, later still:

```go
for _, f := range pl.frames {
	raw, err = f.Frame.Append(raw, v)       // <- Data is copied HERE
}
```

and `DatagramFrame.Append` is what actually reads it:

```go
func (f *DatagramFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	...
	b = append(b, f.Data...)                // <- the only read of f.Data on the send path
	return b, nil
}
```

### Consequences that constrain the design

1. **Release cannot be tied to `Pop`.** Two of the three `Pop()` call sites discard the frame
   without ever serializing it, and the third only queues it for later serialization. A release at
   `Pop` would free memory that `Append` is about to read — or free a frame that was never sent.

2. **Release cannot be tied to "the packet was written to the socket" alone.** The frame is
   referenced by `pl.frames`, which is carried into `shortHeaderPacket.Frames` and used afterward
   for qlog and ack-handler bookkeeping (`connection_logging.go`, `connection.go`).

3. **`appendPacketPayload` can abort mid-loop.** Every `Append` returns an error, and the function
   returns early on the first failure — after some frames have been serialized and others have not.
   A release that only fires on the success path would leak the remaining frames.

### Therefore: release fires in `DatagramFrame.Append`, after the copy

That is the single point where the bytes are provably in the packet buffer and `Data` is dead for
send purposes. It is also naturally correct for the abort path: if `Append` returns an error before
its own copy, the frame was not serialized, and the owning packet builder releases it.

The ownership transfer is therefore: **queue holds a release callback; `Append` invokes it after
copying; discard paths invoke it without copying.**

### Why DATAGRAM needs no ACK lifetime

RFC 9221 DATAGRAM frames are not retransmitted and have no delivery confirmation. Once the payload
is in the packet buffer it will never be read again *by this connection*. Waiting for an ACK, a PTO
or connection close would retain the source buffer for no reason and — with a 32-entry queue — is
exactly the pool-starvation failure mode the task warns about. The release point above is
deliberately as early as is provable.

## API shape

### Layer 1: quic core (no sing-box types)

```go
// DatagramOwner is the ownership handle for a DATAGRAM payload whose bytes are borrowed.
type DatagramOwner interface {
	// Release is called EXACTLY ONCE, after the last read of the payload.
	Release()
}

// SendDatagramOwned enqueues p and takes ownership of it on success.
func (c *Conn) SendDatagramOwned(p []byte, owner DatagramOwner) error
```

Contract, stated in the doc comment:

- `err == nil` → ownership transferred. The caller MUST NOT modify, reuse or release `p`/`owner`.
- `err != nil` → ownership NOT transferred. The caller still owns the buffer and must release it.
- `Release` is invoked exactly once, after the transport no longer references the payload.

`*Conn` cannot import `sing/common/buf`, so the interface is deliberately minimal and lives in quic
core. The sing-box `*buf.Buffer` satisfies it through a two-line adapter.

### Layer 2: http3 (no sing-box types)

```go
// DatagramPayload is the ownership handle http3 needs: it must PREPEND the quarter stream ID
// without copying.
type DatagramPayload interface {
	DatagramOwner
	Bytes() []byte
	Prepend(n int) []byte   // may fail -> caller falls back
	Advance(n int)
}

func (s *RequestStream) SendDatagramOwned(payload DatagramPayload) error
```

`Prepend` returning `nil` means "no headroom"; the caller then takes the existing copying path.
`Advance(n)` is required so http3 can ROLL BACK its quarter-stream-ID prepend when the send fails,
restoring the buffer to the exact layout the caller handed over — which MASQUE needs for both the
PTB and the capsule-fallback paths.

### Why not change the existing methods

`SendDatagram([]byte)` keeps copy semantics. Third-party callers are entitled to modify or reuse
their slice after the call returns; changing that would be a silent memory-corruption bug for every
existing consumer. The owned path is strictly additive.
