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
}

// pendingCreation is one shared session creation and its result.
type pendingCreation struct {
	done    chan struct{}
	session *session
	err     error
}

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
func (c *Client) sessionForCreation(ctx context.Context) (*session, error) {
	for attempt := 0; ; attempt++ {
		c.access.Lock()
		if c.closed {
			c.access.Unlock()
			return nil, net.ErrClosed
		}
		pending := c.pending
		if pending == nil {
			pending = &pendingCreation{done: make(chan struct{})}
			c.pending = pending
			c.access.Unlock()

			createCtx, cancelCreate := c.creationContext(ctx)
			created, err := c.createSession(createCtx)
			cancelCreate()

			c.access.Lock()
			pending.session = created
			pending.err = err
			if c.pending == pending {
				c.pending = nil
			}
			c.access.Unlock()
			close(pending.done)
			return created, err
		}
		c.access.Unlock()

		if c.creationWaiterHook != nil {
			c.creationWaiterHook()
		}
		select {
		case <-pending.done:
			if pending.err != nil {
				return nil, pending.err
			}
			if pending.session != nil && !pending.session.IsClosed() {
				return pending.session, nil
			}
			if attempt >= 1 {
				return nil, net.ErrClosed
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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
	stop := context.AfterFunc(c.creationCtx, cancel)
	return createCtx, func() {
		stop()
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

func (c *Client) Reset() {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return
	}
	sessions := make([]*session, 0, len(c.sessions))
	for closing := range c.sessions {
		closing.element = nil
		sessions = append(sessions, closing)
	}
	clear(c.sessions)
	c.idleSessions.Init()
	c.access.Unlock()
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
	if cancelCreation != nil {
		cancelCreation(net.ErrClosed)
	}
	var err error
	for _, closing := range sessions {
		err = E.Errors(err, closing.Close())
	}
	return err
}
