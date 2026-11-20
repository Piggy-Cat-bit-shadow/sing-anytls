package anytls

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The reuse boundary at the pool (audit P04 / pairwise-a R-2).
//
// A session that carries one live stream while another of its streams has finished is listed for
// reuse: releaseSession pushes it back onto the idle list as soon as ANY of its streams finishes, and
// takeIdleSession hands it to the next flow. CloseIdleConnections skips it because hasStreams() is
// true, so before this boundary existed the only action available for such a session was to keep
// multiplexing onto it.
//
// That is wrong after a sleep: an open stream can be silent across one, so the session is unverified
// whatever its stream count says, and the next flow written onto it is the one that discovers the
// path is gone - three seconds later, via streamOpenTimeout, as a failed flow. RetireSuspect is the
// action in between: refuse new work, keep the stream that is already running.

// onlySession returns the single client session, failing the test if the pool holds a different
// number of them.
func onlySession(t *testing.T, client *Client) *session {
	t.Helper()
	client.access.Lock()
	defer client.access.Unlock()
	require.Len(t, client.sessions, 1)
	for held := range client.sessions {
		return held
	}
	return nil
}

// dialTwoCoalescedFlows opens two flows that share one session creation, which is how a session ends
// up carrying more than one stream at a time (the burst case the coalescing path exists for).
func dialTwoCoalescedFlows(t *testing.T, client *Client, dialer *blockingDialer) (net.Conn, net.Conn) {
	t.Helper()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	first := make(chan dialResult, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), coalescingDestination())
		first <- dialResult{conn: conn, err: err}
	}()
	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the first flow never started its creation")
	}
	second := make(chan dialResult, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), coalescingDestination())
		second <- dialResult{conn: conn, err: err}
	}()
	require.Eventually(t, func() bool { return client.PendingCreationWaiters() == 1 }, 2*time.Second, time.Millisecond,
		"the second flow did not join the in-flight creation")
	close(dialer.release)
	var opened []net.Conn
	for _, result := range []chan dialResult{first, second} {
		var dialed dialResult
		select {
		case dialed = <-result:
		case <-time.After(5 * time.Second):
			t.Fatal("a coalesced flow never returned")
		}
		require.NoError(t, dialed.err)
		opened = append(opened, dialed.conn)
	}
	require.EqualValues(t, 1, dialer.calls.Load(), "the two flows did not share one session")
	return opened[0], opened[1]
}

// TestRetireSuspectDrainsASessionWithALiveStream is the regression: after the boundary, a new flow
// must create a new session instead of multiplexing onto the one that predates it, and the stream the
// old session already carries must survive the boundary.
func TestRetireSuspectDrainsASessionWithALiveStream(t *testing.T) {
	t.Parallel()
	dialer := newBlockingDialer(true)
	client := newCoalescingClient(t, dialer.Dial, nil)

	finished, stillOpen := dialTwoCoalescedFlows(t, client, dialer)

	// One stream finishes: this is what puts a session that still carries a stream back on the idle
	// list in the first place.
	require.NoError(t, finished.Close())
	old := onlySession(t, client)
	require.False(t, old.IsClosed())
	require.NotNil(t, old.element, "the session was not listed for reuse after one of its streams finished")

	client.RetireSuspect()

	require.False(t, old.IsClosed(), "the boundary closed a session that still carries a stream")
	require.Nil(t, old.element, "the retired session is still listed for reuse")

	after, err := client.DialContext(context.Background(), coalescingDestination())
	require.NoError(t, err)
	require.EqualValues(t, 2, dialer.calls.Load(),
		"the flow after the boundary multiplexed onto a session that predates it")

	// The flow that was already running must still carry bytes: the boundary drains, it does not cut.
	_, err = stillOpen.Write([]byte("still carried"))
	require.NoError(t, err, "the boundary cut the stream that was already open")

	require.NoError(t, stillOpen.Close())
	require.Eventually(t, old.IsClosed, 2*time.Second, time.Millisecond,
		"the drained session did not close after its last stream finished")
	require.NoError(t, after.Close())
}

// TestRetireSuspectClosesASessionNobodyUses pins the other half of the action: a session with no
// stream is not worth draining, and a boundary that leaves it listed would hand it to the next flow.
func TestRetireSuspectClosesASessionNobodyUses(t *testing.T) {
	t.Parallel()
	dialer := newBlockingDialer(true)
	client := newCoalescingClient(t, dialer.Dial, nil)

	finished, alsoFinished := dialTwoCoalescedFlows(t, client, dialer)
	require.NoError(t, finished.Close())
	require.NoError(t, alsoFinished.Close())
	old := onlySession(t, client)
	require.False(t, old.hasStreams())

	client.RetireSuspect()

	require.True(t, old.IsClosed(), "an empty session was drained instead of closed")
	client.access.Lock()
	remaining := len(client.sessions)
	client.access.Unlock()
	require.Zero(t, remaining, "a closed session is still in the client's set")
}

// TestRetireSuspectOnAnEmptyPoolIsInert is the positive control: the boundary must not do anything
// when there is nothing to retire, and the next flow must behave exactly as before.
func TestRetireSuspectOnAnEmptyPoolIsInert(t *testing.T) {
	t.Parallel()
	dialer := newBlockingDialer(false)
	client := newCoalescingClient(t, dialer.Dial, nil)

	client.RetireSuspect()

	conn, err := client.DialContext(context.Background(), coalescingDestination())
	require.NoError(t, err)
	require.EqualValues(t, 1, dialer.calls.Load())
	require.NoError(t, conn.Close())
}
