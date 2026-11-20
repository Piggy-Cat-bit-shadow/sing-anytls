package anytls

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// A network change must take the IN-FLIGHT session creation with it.
//
// The generation gate calls Reset, which used to clear only the established sessions. A TLS
// handshake parked on the old path stayed in c.pending, so demand that arrived on the NEW network
// attached to it: it waited for a handshake that had already failed, or inherited its error, and the
// new path was never dialed. These tests pin the three halves of the fix at the client, where the
// pool lives:
//
//  1. Reset cancels the creation's context (a handshake that honours cancellation returns);
//  2. demand after Reset starts a NEW creation instead of joining the abandoned one;
//  3. a result that arrives after Reset is closed, never published, and never handed to a waiter.

// resetDialer blocks the first dial until ctx is cancelled (an obedient handshake), and returns a
// working pipe for every later call (the new network).
type resetDialer struct {
	calls        atomic.Int32
	firstStarted chan struct{}
}

func newResetDialer() *resetDialer {
	return &resetDialer{firstStarted: make(chan struct{})}
}

func (d *resetDialer) Dial(ctx context.Context) (net.Conn, error) {
	if d.calls.Add(1) == 1 {
		close(d.firstStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return newPipeConn()
}

func newPipeConn() (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
		_ = serverConn.Close()
	}()
	return clientConn, nil
}

func newResetClient(t *testing.T, dial DialOutFunc) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Password:           "test-password",
		DialOut:            dial,
		IdleSessionTimeout: time.Minute,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func resetDestination() M.Socksaddr {
	return M.Socksaddr{Fqdn: "reset.example", Port: 443}
}

// TestResetCancelsTheInFlightCreation is the cancellation half: a handshake parked on the old path
// sees its context cancelled, and the call returns instead of waiting out the creation timeout.
func TestResetCancelsTheInFlightCreation(t *testing.T) {
	dialer := newResetDialer()
	client := newResetClient(t, dialer.Dial)

	done := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), resetDestination())
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()

	select {
	case <-dialer.firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("the creation never started")
	}
	client.Reset()

	// The abandoned creation's own demand retries once on the new generation, so it returns a
	// working connection rather than the old path's cancellation: what matters here is that the
	// blocked handshake was released promptly and the retry dialed again.
	select {
	case err := <-done:
		require.NoError(t, err, "the abandoned demand must retry on the new generation")
	case <-time.After(2 * time.Second):
		t.Fatal("Reset did not cancel the in-flight creation: its dial is still blocked")
	}
	require.GreaterOrEqual(t, dialer.calls.Load(), int32(2))
	require.Zero(t, client.PendingCreationWaiters())
}

// TestDemandAfterResetStartsANewCreation is the defect itself: demand that arrives after the network
// change must not attach to the abandoned creation.
func TestDemandAfterResetStartsANewCreation(t *testing.T) {
	dialer := newResetDialer()
	client := newResetClient(t, dialer.Dial)

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		conn, err := client.DialContext(context.Background(), resetDestination())
		if conn != nil {
			_ = conn.Close()
		}
		_ = err
	}()
	select {
	case <-dialer.firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("the first creation never started")
	}

	client.Reset()

	// The new demand must reach the dialer's second (healthy) call within the test budget. If it
	// attached to the abandoned creation it would wait for the stuck handshake instead.
	dialed := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), resetDestination())
		if conn != nil {
			_ = conn.Close()
		}
		dialed <- err
	}()
	select {
	case err := <-dialed:
		require.NoError(t, err, "demand after Reset must succeed on a fresh creation")
	case <-time.After(3 * time.Second):
		t.Fatal("demand after Reset joined the abandoned creation instead of dialing the new path")
	}
	require.GreaterOrEqual(t, dialer.calls.Load(), int32(2))
	<-firstDone
}

// lateDialer ignores cancellation on the first call and returns a connection only when released: the
// creation completes AFTER the network change, which is the late-result window.
type lateDialer struct {
	calls        atomic.Int32
	firstStarted chan struct{}
	release      chan struct{}
}

func (d *lateDialer) Dial(ctx context.Context) (net.Conn, error) {
	if d.calls.Add(1) == 1 {
		close(d.firstStarted)
		<-d.release
		return newPipeConn()
	}
	return newPipeConn()
}

// TestResetRejectsTheLateCreationResult: a session built for the old path must not be published.
func TestResetRejectsTheLateCreationResult(t *testing.T) {
	dialer := &lateDialer{
		firstStarted: make(chan struct{}),
		release:      make(chan struct{}),
	}
	client := newResetClient(t, dialer.Dial)

	done := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), resetDestination())
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case <-dialer.firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("the creation never started")
	}

	client.Reset()
	close(dialer.release)

	select {
	case err := <-done:
		require.NoError(t, err, "the demand that owned the abandoned creation must retry, not receive it")
	case <-time.After(3 * time.Second):
		t.Fatal("the abandoned creation's caller never returned")
	}

	client.access.Lock()
	held := len(client.sessions)
	pending := client.pending
	client.access.Unlock()
	// Exactly the retry's session may be in the pool. The late session was built for the old path:
	// publishing it would show up here as a second entry.
	require.Equal(t, 1, held, "the late session was published into the pool")
	require.Nil(t, pending, "the abandoned creation left a pool entry behind")
}

// TestResetWaiterRetriesOnTheNewGeneration: a caller that attached BEFORE the change is released by
// the abandon and retries, instead of failing with the old handshake's error.
func TestResetWaiterRetriesOnTheNewGeneration(t *testing.T) {
	dialer := newResetDialer()
	client := newResetClient(t, dialer.Dial)

	var creatorDone sync.WaitGroup
	creatorDone.Add(1)
	go func() {
		defer creatorDone.Done()
		conn, err := client.DialContext(context.Background(), resetDestination())
		if conn != nil {
			_ = conn.Close()
		}
		_ = err
	}()
	select {
	case <-dialer.firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("the creation never started")
	}

	waiterDone := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(context.Background(), resetDestination())
		if conn != nil {
			_ = conn.Close()
		}
		waiterDone <- err
	}()
	require.Eventually(t, func() bool { return client.PendingCreationWaiters() == 1 },
		2*time.Second, time.Millisecond, "the waiter never attached to the in-flight creation")

	client.Reset()

	select {
	case err := <-waiterDone:
		require.NoError(t, err, "the waiter must retry on the new generation, not inherit the old failure")
	case <-time.After(3 * time.Second):
		t.Fatal("the waiter was not released by the abandon")
	}
	creatorDone.Wait()
}
