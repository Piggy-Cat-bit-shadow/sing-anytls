package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Concurrent first flows must share ONE session creation.
//
// takeIdleSession only returns sessions that already completed a stream, so a burst of first flows
// finds it empty in every goroutine and each one would connect, handshake and write on its own. The
// admission gate paced those creations but did not reduce their number: the measured 200-flow burst
// still performed up to 200 handshakes. These tests pin the coalescing contract at the client, where
// the pool lives.

type blockingDialer struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	err     error
	usePipe bool
}

func newBlockingDialer(block bool) *blockingDialer {
	dialer := &blockingDialer{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
		usePipe: true,
	}
	if !block {
		close(dialer.release)
	}
	return dialer
}

func (d *blockingDialer) Dial(ctx context.Context) (net.Conn, error) {
	call := d.calls.Add(1)
	if call == 1 {
		select {
		case d.started <- struct{}{}:
		default:
		}
	}
	select {
	case <-d.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if d.err != nil {
		return nil, d.err
	}
	clientConn, serverConn := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
		_ = serverConn.Close()
	}()
	return clientConn, nil
}

func newCoalescingClient(t *testing.T, dial func(context.Context) (net.Conn, error), admission func(ctx context.Context, create func(context.Context) error) error) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{
		Password:           "test-password",
		DialOut:            dial,
		IdleSessionTimeout: time.Minute,
		AdmitCreation:      admission,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func coalescingDestination() M.Socksaddr {
	return M.Socksaddr{Fqdn: "example.com", Port: 80}
}

// TestConcurrentFirstFlowsShareOneCreation is the regression.
func TestConcurrentFirstFlowsShareOneCreation(t *testing.T) {
	const flows = 50
	dialer := newBlockingDialer(true)
	client := newCoalescingClient(t, dialer.Dial, nil)

	var attached atomic.Int32
	client.creationWaiterHook = func() { attached.Add(1) }

	var wg sync.WaitGroup
	errs := make(chan error, flows)
	conns := make(chan net.Conn, flows)
	for index := 0; index < flows; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := client.DialContext(context.Background(), coalescingDestination())
			if err != nil {
				errs <- err
				return
			}
			conns <- conn
		}()
	}

	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the shared creation never started")
	}
	require.Eventually(t, func() bool {
		return attached.Load() == flows-1
	}, 2*time.Second, time.Millisecond, "not every flow attached to the in-flight creation")
	close(dialer.release)
	wg.Wait()
	close(errs)
	close(conns)

	for err := range errs {
		require.NoError(t, err)
	}
	opened := 0
	for conn := range conns {
		opened++
		_ = conn.Close()
	}
	require.Equal(t, flows, opened)
	require.EqualValues(t, 1, dialer.calls.Load(),
		"%d concurrent first flows performed %d session creations", flows, dialer.calls.Load())
}

// TestWaiterCancellationDoesNotTearDownTheSharedCreation pins the lifetime split: the creation runs
// under the client and the first caller's VALUES, not that caller's cancellation.
func TestWaiterCancellationDoesNotTearDownTheSharedCreation(t *testing.T) {
	dialer := newBlockingDialer(true)
	client := newCoalescingClient(t, dialer.Dial, nil)
	attached := make(chan struct{}, 1)
	client.creationWaiterHook = func() {
		select {
		case attached <- struct{}{}:
		default:
		}
	}

	creatorDone := make(chan error, 1)
	go func() {
		_, err := client.DialContext(context.Background(), coalescingDestination())
		creatorDone <- err
	}()
	<-dialer.started

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := client.DialContext(waiterCtx, coalescingDestination())
		waiterDone <- err
	}()
	select {
	case <-attached:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter never attached")
	}
	cancelWaiter()
	require.ErrorIs(t, <-waiterDone, context.Canceled)

	close(dialer.release)
	select {
	case err := <-creatorDone:
		require.NoError(t, err, "a departing waiter tore down the shared creation")
	case <-time.After(2 * time.Second):
		t.Fatal("the creation did not finish")
	}
	require.EqualValues(t, 1, dialer.calls.Load())
}

// TestFailedCreationWakesEveryWaiter pins the failure ending: one dial, one error for all, and the
// next demand is free to create again.
func TestFailedCreationWakesEveryWaiter(t *testing.T) {
	dialer := newBlockingDialer(true)
	sentinel := errors.New("handshake refused")
	dialer.err = sentinel
	client := newCoalescingClient(t, dialer.Dial, nil)

	const flows = 10
	var attached atomic.Int32
	client.creationWaiterHook = func() { attached.Add(1) }

	errs := make(chan error, flows)
	for index := 0; index < flows; index++ {
		go func() {
			_, err := client.DialContext(context.Background(), coalescingDestination())
			errs <- err
		}()
	}
	<-dialer.started
	require.Eventually(t, func() bool { return attached.Load() == flows-1 }, 2*time.Second, time.Millisecond)
	close(dialer.release)

	for index := 0; index < flows; index++ {
		require.ErrorIs(t, <-errs, sentinel)
	}
	require.EqualValues(t, 1, dialer.calls.Load())

	// The failed creation is gone: the next demand performs a new one.
	dialer.err = nil
	conn, err := client.DialContext(context.Background(), coalescingDestination())
	require.NoError(t, err)
	_ = conn.Close()
	require.EqualValues(t, 2, dialer.calls.Load())
}

// TestCloseDuringCreationReleasesEveryWaiter pins shutdown: nobody may wait for a creation whose
// owner is closed, and no session may be published.
func TestCloseDuringCreationReleasesEveryWaiter(t *testing.T) {
	dialer := newBlockingDialer(true)
	client, err := NewClient(ClientOptions{
		Password:           "test-password",
		DialOut:            dialer.Dial,
		IdleSessionTimeout: time.Minute,
	})
	require.NoError(t, err)

	const flows = 5
	errs := make(chan error, flows)
	for index := 0; index < flows; index++ {
		go func() {
			_, dialErr := client.DialContext(context.Background(), coalescingDestination())
			errs <- dialErr
		}()
	}
	<-dialer.started
	require.NoError(t, client.Close())

	for index := 0; index < flows; index++ {
		select {
		case dialErr := <-errs:
			require.Error(t, dialErr)
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not release a waiter of the shared creation")
		}
	}
	require.EqualValues(t, 1, dialer.calls.Load())
	require.Zero(t, len(client.sessions))
}

// TestAdmissionIsChargedOncePerSharedCreation is the point of the change for the process budget:
// twenty flows, one expensive creation, one admission decision. The gate itself lives in the
// embedding process (sing-box); here a counting hook with a one-slot semaphore stands in for it,
// because this module must not depend on the box.
func TestAdmissionIsChargedOncePerSharedCreation(t *testing.T) {
	var admitCalls atomic.Int32
	slot := make(chan struct{}, 1)
	admission := func(ctx context.Context, create func(context.Context) error) error {
		admitCalls.Add(1)
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
			return create(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	dialer := newBlockingDialer(true)
	client := newCoalescingClient(t, dialer.Dial, admission)

	const flows = 20
	var attached atomic.Int32
	client.creationWaiterHook = func() { attached.Add(1) }

	errs := make(chan error, flows)
	for index := 0; index < flows; index++ {
		go func() {
			conn, err := client.DialContext(context.Background(), coalescingDestination())
			if err == nil {
				_ = conn.Close()
			}
			errs <- err
		}()
	}
	<-dialer.started
	require.Eventually(t, func() bool { return attached.Load() == flows-1 }, 2*time.Second, time.Millisecond)
	close(dialer.release)
	for index := 0; index < flows; index++ {
		require.NoError(t, <-errs)
	}
	require.EqualValues(t, 1, admitCalls.Load(), "the admission hook was asked once per flow")
	require.EqualValues(t, 1, dialer.calls.Load())
}
