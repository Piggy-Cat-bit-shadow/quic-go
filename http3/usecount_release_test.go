package http3

import (
	"context"
	"net/http"
	"testing"
)

// A request that joins another request's in-flight dial must not leak the pool reference it took.
//
// # The defect
//
// getClient increments useCount for every request that obtains a client, including a request that
// found an entry whose dial is still running. doRoundTripOpt then waits for that dial and, when the
// request's own context ends first, returns WITHOUT decrementing. The count never returns to zero,
// and CloseIdleConnections only closes entries whose count IS zero, so the connection - once the
// original dial succeeds - can never be reclaimed.
//
// # Why this test does not need a QUIC connection
//
// The reference accounting happens before any stream exists. A hand-built pool entry whose dialing
// channel stays open reproduces exactly the state a joining request sees: getClient returns the
// entry with one reference taken, doRoundTripOpt waits on the dial, and the cancelled context ends
// the wait.
func TestCancelledRequestReleasesTheReferenceItTookWhileJoiningADial(t *testing.T) {
	hostname := "example.org:443"
	client := &roundTripperWithCount{dialing: make(chan struct{})}
	transport := &Transport{clients: map[string]*roundTripperWithCount{hostname: client}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = transport.doRoundTripOpt(request, RoundTripOpt{}, false); err == nil {
		t.Fatal("a cancelled request cannot succeed")
	}
	if count := client.useCount.Load(); count != 0 {
		t.Fatalf("the pool reference must be released when the request leaves while waiting for "+
			"another request's dial; useCount is %d, so the connection can never be closed as idle", count)
	}
}
