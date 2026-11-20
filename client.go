package anytls

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
)

type keepSessionKey struct{}

func ContextWithKeepSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*keepSessionKey)(nil), true)
}

func keepSessionFromContext(ctx context.Context) bool {
	keep, _ := ctx.Value((*keepSessionKey)(nil)).(bool)
	return keep
}

type ClientOptions struct {
	Password                 string
	ClientMetadata           string
	DialOut                  DialOutFunc
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	DisableReuse             bool
	Logger                   logger.ContextLogger
	// AdmitCreation, when set, is called exactly once per NEW session and never when an idle
	// session is reused. It OWNS the call: it must invoke create exactly once and return its
	// error (a hook that refuses must return its own error without calling create).
	//
	// The hook exists because the two paths have different costs. Creating a session pays a TCP
	// connect, a TLS handshake and the first write; reusing an idle session pays one frame. A
	// caller that bounds session creation must therefore be consulted at THIS seam, after the
	// reuse attempt has failed, or a healthy reuse would wait behind creations it is unrelated to.
	AdmitCreation func(ctx context.Context, create func(context.Context) error) error
}

type Client struct {
	password       [passwordLen]byte
	clientMetadata string
	dialOut        DialOutFunc
	admitCreation  func(ctx context.Context, create func(context.Context) error) error
	logger         logger.ContextLogger
	padding        common.TypedValue[*paddingFactory]

	idleCheckInterval time.Duration
	idleTimeout       time.Duration
	minIdleSession    int
	disableReuse      bool
	closeIdle         atomic.Bool

	access       sync.Mutex
	closed       bool
	sessions     map[*session]struct{}
	idleSessions list.List[*session]
	idleTimer    *time.Timer

	// creationCtx is the lifetime of a SHARED creation. A dial that starts one must not be
	// cancellable by the single caller that happened to arrive first, because every other waiter
	// owns the result too; Close cancels it with its cause instead.
	creationCtx    context.Context
	cancelCreation context.CancelCauseFunc
	// pending is the session creation currently in flight, or nil. It is set and cleared under
	// access; the offer goroutine owns the result and publishes it under the same lock.
	pending *pendingCreation
	// creationWaiterHook is a test seam: called after a caller attaches to the pending creation and
	// before it waits. Nil in production and costs one branch in that path.
	creationWaiterHook func()
	// pendingWaiters is the number of callers currently attached to the in-flight creation. It is a
	// diagnostic gauge: "one creation with 199 waiters" and "200 creations" are indistinguishable
	// from the accept count alone under scheduler skew, and this is what tells them apart.
	pendingWaiters atomic.Int32
}

// pendingCreation is one shared session creation and its result.
//
// abandoned is closed when the creation stops belonging to the pool: a network change (Reset) clears
// c.pending so new demand starts a fresh creation on the new path, and close(abandoned) releases the
// waiters that attached to the old one. Abandoning is not a failure of the dial: the waiters retry in
// the new generation. done is still closed by the creator, which owns the result.
type pendingCreation struct {
	done      chan struct{}
	abandoned chan struct{}

	abandonOnce sync.Once
	cancelMu    sync.Mutex
	cancel      context.CancelFunc

	session *session
	err     error
}

// abandon detaches the creation from the pool: waiters stop waiting on done, and the creation's
// context is cancelled so a dial or handshake parked on the old path returns instead of pinning the
// goroutine (and its waiters) until the creation timeout. Safe to call more than once, and safe to
// call before the creator has published its cancel function.
func (p *pendingCreation) abandon() {
	p.abandonOnce.Do(func() {
		close(p.abandoned)
		p.cancelMu.Lock()
		cancel := p.cancel
		p.cancelMu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
}

// setCancel publishes the creation's cancel function and reports whether the creation was abandoned
// before it could start. When that happens the caller must cancel immediately and must not dial: the
// pool no longer wants this creation.
func (p *pendingCreation) setCancel(cancel context.CancelFunc) (abandoned bool) {
	p.cancelMu.Lock()
	p.cancel = cancel
	p.cancelMu.Unlock()
	select {
	case <-p.abandoned:
		return true
	default:
		return false
	}
}

// creationAbandoned is the error a creation reports when a network change took its pool entry away.
// It is not a dial failure: the demand it served retries against the new generation.
var creationAbandoned = E.New("anytls: session creation abandoned by a network change")

// defaultSessionCreationTimeout bounds a shared creation whose first caller had no deadline, so a
// peer that never completes the handshake cannot pin the creation (and its waiters) indefinitely.
const defaultSessionCreationTimeout = 30 * time.Second

func NewClient(options ClientOptions) (*Client, error) {
	factory, err := newPaddingFactory(DefaultPaddingScheme)
	if err != nil {
		return nil, err
	}
	client := &Client{
		password:          sha256.Sum256([]byte(options.Password)),
		clientMetadata:    options.ClientMetadata,
		dialOut:           options.DialOut,
		admitCreation:     options.AdmitCreation,
		logger:            options.Logger,
		idleCheckInterval: options.IdleSessionCheckInterval,
		idleTimeout:       options.IdleSessionTimeout,
		minIdleSession:    options.MinIdleSession,
		disableReuse:      options.DisableReuse,
		sessions:          make(map[*session]struct{}),
	}
	if client.logger == nil {
		client.logger = logger.NOP()
	}
	if client.idleCheckInterval <= minimumIdleSessionInterval {
		client.idleCheckInterval = defaultIdleSessionCheckInterval
	}
	if client.idleTimeout <= minimumIdleSessionInterval {
		client.idleTimeout = defaultIdleSessionTimeout
	}
	client.creationCtx, client.cancelCreation = context.WithCancelCause(context.Background())
	client.padding.Store(factory)
	return client, nil
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsValid() {
		return nil, E.New("anytls: invalid destination: ", destination)
	}
	if len(destination.Fqdn) > 255 {
		return nil, E.New("anytls: domain too long: ", destination.Fqdn)
	}
	keepSession := keepSessionFromContext(ctx)
	idle := c.takeIdleSession()
	if idle != nil {
		opened, err := idle.openStream(destination)
		if err == nil && !idle.IsClosed() {
			if keepSession {
				idle.keepOnce.Store(true)
			}
			return opened, nil
		}
		if opened != nil {
			opened.Close()
		}
		idle.Close()
	}
	created, err := c.sessionForCreation(ctx)
	if err != nil {
		return nil, err
	}
	opened, err := created.openStream(destination)
	if err != nil {
		created.Close()
		return nil, err
	}
	if keepSession {
		created.keepOnce.Store(true)
	}
	return opened, nil
}

// sessionForCreation returns a session a new stream can be opened on, sharing one in-flight
// creation with every other caller that arrives while it runs.
//
// # Why this exists
//
// takeIdleSession only returns sessions that have already completed a stream: a session re-enters
// the idle list when one of its streams finishes (see releaseSession). A burst of first flows
// therefore finds the list empty in every goroutine, and each one starts its own connect, TLS
// handshake and first write. The admission gate bounds how many of those run at once, but not how
// many are performed: 200 concurrent flows still perform up to 200 handshakes, paced 32 at a time.
// Coalescing turns that into one creation plus 199 stream opens on the result.
//
// # The rules it keeps
//
//   - A caller still tries the idle list first; a coalesced creation is only for demand that found
//     no reusable session.
//   - The creation runs under the client's lifetime plus the FIRST caller's values (traffic class,
//     held admission permit), never under that caller's cancellation: one caller leaving must not
//     tear down a dial the waiters still need.
//   - Each waiter keeps its own cancellation while waiting.
//   - A failed creation fails every waiter with the same error and is not retried here; the next
//     demand starts a new one. A success whose session closed before a waiter used it gets one more
//     attempt, because the result was discarded, not refused.
//   - A network change takes the creation with it: Reset clears c.pending and abandons it, so new
//     demand starts a creation on the new path instead of joining a handshake that may be parked on
//     the old one. Waiters on the abandoned creation retry against the new generation, and a result
//     that arrives after the abandon is closed rather than published.
func (c *Client) sessionForCreation(ctx context.Context) (*session, error) {
	for attempt := 0; ; attempt++ {
		c.access.Lock()
		if c.closed {
			c.access.Unlock()
			return nil, net.ErrClosed
		}
		pending := c.pending
		if pending == nil {
			pending = &pendingCreation{done: make(chan struct{}), abandoned: make(chan struct{})}
			c.pending = pending
			c.access.Unlock()

			createCtx, cancelCreate := c.creationContext(ctx)
			if pending.setCancel(cancelCreate) {
				// The generation changed between registering this creation and publishing its
				// cancel: do not dial on the old path at all.
				cancelCreate()
			}
			created, err := c.createSession(createCtx)
			cancelCreate()

			c.access.Lock()
			superseded := c.pending != pending
			if !superseded {
				c.pending = nil
			}
			c.access.Unlock()
			if superseded {
				// A network change (or Close) took the pool entry away while this dial/handshake
				// was still running. The result belongs to the old path: never publish it, and
				// close it so a session whose readLoop already started does not linger.
				if created != nil {
					c.removeSession(created)
					created.Close()
				}
				pending.session = nil
				pending.err = creationAbandoned
				close(pending.done)
				if attempt < 1 {
					continue
				}
				return nil, creationAbandoned
			}
			pending.session = created
			pending.err = err
			close(pending.done)
			return created, err
		}
		c.access.Unlock()

		c.pendingWaiters.Add(1)
		if c.creationWaiterHook != nil {
			c.creationWaiterHook()
		}
		var (
			shared  *session
			waitErr error
		)
		select {
		case <-pending.done:
			if pending.err != nil {
				waitErr = pending.err
			} else if pending.session != nil && !pending.session.IsClosed() {
				shared = pending.session
			}
		case <-pending.abandoned:
			waitErr = creationAbandoned
		case <-ctx.Done():
			waitErr = ctx.Err()
		}
		c.pendingWaiters.Add(-1)
		if shared != nil {
			return shared, nil
		}
		if waitErr == creationAbandoned && attempt < 1 {
			// The pool moved to a new generation under this waiter: retry there instead of
			// reporting the abandoned creation as this demand's failure.
			continue
		}
		if waitErr != nil {
			return nil, waitErr
		}
		if attempt >= 1 {
			return nil, net.ErrClosed
		}
	}
}

// PendingCreationWaiters reports how many callers are currently waiting on the in-flight session
// creation (0 when none is pending). A caller that is itself creating the session is not counted.
//
// This is the gauge that distinguishes coalescing from pacing: one creation with N-1 waiters is the
// fixed shape, N creations is the old one, and the accept count alone cannot tell them apart when a
// goroutine is scheduled after the creation completed.
func (c *Client) PendingCreationWaiters() int {
	return int(c.pendingWaiters.Load())
}

// creationContext builds the context one shared creation runs under.
//
// Values come from the caller that started the creation (the traffic class and an already-held
// admission permit are properties of the work being created); cancellation comes from the client,
// so a departing caller cannot abort a dial other callers are waiting for. The registration is
// removed when the creation returns.
func (c *Client) creationContext(callerCtx context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(callerCtx)
	createCtx, cancel := context.WithCancel(detached)
	// The caller's DEADLINE is kept: it is the bound on how long anyone should wait for this
	// creation, and the caller that started it is the best available estimate. Its CANCELLATION is
	// not kept, because one caller giving up must not abort a dial other waiters still need. A
	// caller without a deadline gets a hard bound so a silent peer cannot pin the creation forever
	// (the pre-coalescing code inherited the caller's cancellation for this, which no longer
	// reaches the creation).
	var boundCancel context.CancelFunc
	if deadline, hasDeadline := callerCtx.Deadline(); hasDeadline {
		createCtx, boundCancel = context.WithDeadline(createCtx, deadline)
	} else {
		createCtx, boundCancel = context.WithTimeout(createCtx, defaultSessionCreationTimeout)
	}
	stop := context.AfterFunc(c.creationCtx, cancel)
	return createCtx, func() {
		stop()
		boundCancel()
		cancel()
	}
}

// createSession builds a new session. Admission is asked HERE, after the idle-reuse attempt in
// DialContext has already failed: a caller that bounds creation must not be charged for a reuse,
// and the hook must see the real creation (dial, handshake and first write), not a stream open.
func (c *Client) createSession(ctx context.Context) (*session, error) {
	if c.admitCreation == nil {
		return c.createSessionDirect(ctx)
	}
	var created *session
	err := c.admitCreation(ctx, func(ctx context.Context) error {
		var createErr error
		created, createErr = c.createSessionDirect(ctx)
		return createErr
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (c *Client) createSessionDirect(ctx context.Context) (*session, error) {
	c.access.Lock()
	closed := c.closed
	c.access.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}
	paddingLen := c.padding.Load().GenerateHandshakePaddingSize()
	request := buf.NewSize(passwordLen + 2 + paddingLen)
	common.Must1(request.Write(c.password[:]))
	binary.BigEndian.PutUint16(request.Extend(2), uint16(paddingLen))
	common.Must(request.WriteZeroN(paddingLen))
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		conn.SetWriteDeadline(deadline)
	}
	_, err = conn.Write(request.Bytes())
	request.Release()
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "anytls: write request")
	}
	conn.SetWriteDeadline(time.Time{})
	created := newClientSession(c, conn)
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		created.Close()
		return nil, net.ErrClosed
	}
	c.sessions[created] = struct{}{}
	c.access.Unlock()
	go func() {
		loopErr := created.readLoop()
		created.Close()
		if !E.IsClosedOrCanceled(loopErr) {
			c.logger.Debug(E.Cause(loopErr, "anytls: session closed"))
		}
	}()
	return created, nil
}

func (c *Client) takeIdleSession() *session {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil
	}
	for element := c.idleSessions.Front(); element != nil; element = element.Next() {
		idle := element.Value
		c.idleSessions.Remove(element)
		idle.element = nil
		return idle
	}
	return nil
}

func (c *Client) releaseSession(released *session) {
	if c.disableReuse {
		released.Close()
		return
	}
	c.access.Lock()
	if released.IsClosed() || c.closed {
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		delete(c.sessions, released)
		c.access.Unlock()
		return
	}
	keepOnce := released.keepOnce.Swap(false)
	if released.retired {
		// A reuse boundary retired this session while it carried this stream. It never takes new work
		// again, so it is never listed for reuse again either: the stream that just finished may have
		// been its last one, and then the session closes here.
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		if !released.hasStreams() {
			delete(c.sessions, released)
			c.access.Unlock()
			released.Close()
			return
		}
		c.access.Unlock()
		return
	}
	if !released.hasStreams() && c.closeIdle.Load() && !keepOnce {
		if released.element != nil {
			c.idleSessions.Remove(released.element)
			released.element = nil
		}
		delete(c.sessions, released)
		c.access.Unlock()
		released.Close()
		return
	}
	if released.element == nil {
		released.idleSince = time.Now()
		released.element = c.idleSessions.PushFront(released)
		if c.idleTimer == nil {
			c.idleTimer = time.AfterFunc(c.idleCheckInterval, c.cleanupIdleSessions)
		}
	}
	c.access.Unlock()
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	var closing []*session
	for element := c.idleSessions.Front(); element != nil; {
		idle := element.Value
		element = element.Next()
		if idle.hasStreams() {
			continue
		}
		c.idleSessions.Remove(idle.element)
		idle.element = nil
		delete(c.sessions, idle)
		closing = append(closing, idle)
	}
	c.access.Unlock()
	for _, idle := range closing {
		idle.Close()
	}
}

// RetireSuspect refuses new streams on every session this client holds now, while the streams
// already on them finish.
//
// # Why this is not CloseIdleConnections
//
// The trim may only drop resources nobody is using, so it skips a session that still carries a
// stream (see CloseIdleConnections). But a session that predates a sleep boundary may not be handed
// the next flow either: an open stream is not proof that the path survived the sleep, because a
// stream can be open and silent across one (a paused response body, a flow between packets). Such a
// session is unverified whatever its stream count says, and the stream that would prove it is the
// next one - which is why the boundary has to happen before that stream is written, not three
// seconds after it stalls (streamOpenTimeout).
//
// Draining is the only action that is neither of the two wrong ones:
//
//   - a session with no stream is closed here, exactly like the trim;
//   - a session with a live stream stops being listed for reuse, keeps the stream, and closes itself
//     when its last stream finishes (releaseSession owns that moment);
//   - a session a dial is already opening a stream on is marked but not closed, so a demand that
//     raced the boundary is not cut by it.
//
// A session created after this call is unaffected: completing a connect and handshake after the
// boundary is itself the proof the retired sessions do not have.
func (c *Client) RetireSuspect() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	var closing []*session
	for held := range c.sessions {
		held.retired = true
		listed := held.element != nil
		if listed {
			c.idleSessions.Remove(held.element)
			held.element = nil
		}
		if listed && !held.hasStreams() {
			delete(c.sessions, held)
			closing = append(closing, held)
		}
	}
	c.access.Unlock()
	for _, held := range closing {
		held.Close()
	}
}

func (c *Client) Reset() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	// The in-flight creation was started for the path that just went away. Clearing c.pending is
	// what stops new demand from joining it; abandoning it releases its waiters and cancels the
	// dial/handshake itself, so a handshake parked on the old path cannot hold the pool hostage.
	pending := c.pending
	c.pending = nil
	sessions := make([]*session, 0, len(c.sessions))
	for closing := range c.sessions {
		closing.element = nil
		sessions = append(sessions, closing)
	}
	clear(c.sessions)
	c.idleSessions.Init()
	c.access.Unlock()
	if pending != nil {
		pending.abandon()
	}
	for _, closing := range sessions {
		closing.Close()
	}
}

func (c *Client) removeSession(removed *session) {
	c.access.Lock()
	defer c.access.Unlock()
	if removed.element != nil {
		c.idleSessions.Remove(removed.element)
		removed.element = nil
	}
	delete(c.sessions, removed)
}

func (c *Client) cleanupIdleSessions() {
	var expired []*session
	c.access.Lock()
	if c.closed {
		c.idleTimer = nil
		c.access.Unlock()
		return
	}
	deadline := time.Now().Add(-c.idleTimeout)
	for element := c.idleSessions.Back(); element != nil && c.idleSessions.Len() > c.minIdleSession; {
		previous := element.Prev()
		idle := element.Value
		if !idle.idleSince.Before(deadline) {
			break
		}
		if idle.hasStreams() {
			element = previous
			continue
		}
		c.idleSessions.Remove(element)
		idle.element = nil
		expired = append(expired, idle)
		element = previous
	}
	if c.idleSessions.Len() > 0 {
		c.idleTimer.Reset(c.idleCheckInterval)
	} else {
		c.idleTimer = nil
	}
	c.access.Unlock()
	for _, idle := range expired {
		idle.Close()
	}
}

func (c *Client) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	pending := c.pending
	c.pending = nil
	cancelCreation := c.cancelCreation
	if c.idleTimer != nil {
		c.idleTimer.Stop()
		c.idleTimer = nil
	}
	sessions := make([]*session, 0, len(c.sessions))
	for closing := range c.sessions {
		closing.element = nil
		sessions = append(sessions, closing)
	}
	clear(c.sessions)
	c.idleSessions.Init()
	c.access.Unlock()
	if pending != nil {
		pending.abandon()
	}
	if cancelCreation != nil {
		cancelCreation(net.ErrClosed)
	}
	var err error
	for _, closing := range sessions {
		err = E.Errors(err, closing.Close())
	}
	return err
}
