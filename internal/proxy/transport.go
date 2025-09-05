package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arencloud/hecate/internal/config"
	"github.com/arencloud/hecate/internal/telemetry"
	"golang.org/x/net/http2"
)

type policyRoundTripper struct {
	base        http.RoundTripper
	r           *config.RetryPolicy
	breakers    sync.Map // key: upstream host (scheme://host) -> *breaker
	h2cUpstream bool
}

func newPolicyRoundTripper(base http.RoundTripper, r *config.RetryPolicy, c *config.CircuitBreaker) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	p := &policyRoundTripper{
		base: base,
		r:    r,
	}
	// We initialize breakers lazily per-upstream using c for thresholds.
	if c != nil {
		// Store a template config in a special key for cloning
		p.breakers.Store("_config", c)
	}
	return p
}

func (p *policyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	key := upstreamKey(req)
	var br *breaker
	if cfgAny, ok := p.breakers.Load("_config"); ok {
		if v, ok2 := p.breakers.Load(key); ok2 {
			br = v.(*breaker)
		} else {
			cfg := cfgAny.(*config.CircuitBreaker)
			nb := newBreaker(cfg, key, telemetry.BreakerEvent)
			if v2, loaded := p.breakers.LoadOrStore(key, nb); loaded {
				br = v2.(*breaker)
			} else {
				br = nb
			}
		}
	}

	// If breaker is open, fail fast except allow limited half-open probes
	if br != nil && !br.allow() {
		return nil, ErrCircuitOpen
	}

	// Select base RT per-request (h2c upstream if enabled and scheme is http)
	rt := p.base
	if p.h2cUpstream && strings.EqualFold(req.URL.Scheme, "http") {
		rt = h2cRoundTripper()
	}

	maxRetries := 0
	perTry := time.Duration(0)
	backoffBase := 50 * time.Millisecond
	backoffMax := 500 * time.Millisecond
	retryOn5xx := true
	retryOnConn := true
	retryIdempotent := true

	if p.r != nil {
		maxRetries = p.r.MaxRetries
		if p.r.PerTryTimeoutSec > 0 {
			perTry = time.Duration(p.r.PerTryTimeoutSec) * time.Second
		}
		if p.r.BackoffBaseMs > 0 {
			backoffBase = time.Duration(p.r.BackoffBaseMs) * time.Millisecond
		}
		if p.r.BackoffMaxMs > 0 {
			backoffMax = time.Duration(p.r.BackoffMaxMs) * time.Millisecond
		}
		retryOn5xx = p.r.RetryOn5xx
		retryOnConn = p.r.RetryOnConnectErr
		retryIdempotent = p.r.RetryIdempotent
	}

	attempts := maxRetries + 1
	var lastErr error
	var resp *http.Response

	for i := 0; i < attempts; i++ {
		// Enforce per-try timeout if configured
		rctx := req.Context()
		var cancel context.CancelFunc
		if perTry > 0 {
			rctx, cancel = context.WithTimeout(rctx, perTry)
		}
		clone := req.Clone(rctx)

		// Observability headers (to upstream)
		clone.Header.Set("Via", "1.1 hecate")
		clone.Header.Set("X-Hecate-Retry-Attempt", strconv.Itoa(i))

		// Ensure body is re-usable across retries only if it's safe
		hasBody := clone.Body != nil && clone.GetBody == nil
		shouldAttemptRetry := retryIdempotent && isIdempotent(clone.Method) && !hasBody
		if i == 0 {
			shouldAttemptRetry = true
		}

		resp, lastErr = rt.RoundTrip(clone)
		if cancel != nil {
			cancel()
		}

		// Evaluate result
		if lastErr == nil {
			if retryOn5xx && shouldAttemptRetry && resp != nil && (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout) && i < attempts-1 {
				// Metrics: record retry
				telemetry.IncRetry(req.Context(), key)
				drainAndClose(resp)
				sleepWithJitter(backoffBase, backoffMax, i)
				continue
			}
			if br != nil {
				br.success()
			}
			return resp, nil
		}

		// Error path: connection errors/timeouts
		if shouldAttemptRetry && i < attempts-1 && (retryOnConn && isConnErr(lastErr)) {
			telemetry.IncRetry(req.Context(), key)
			sleepWithJitter(backoffBase, backoffMax, i)
			continue
		}

		if br != nil {
			br.failure()
		}
		return nil, lastErr
	}

	if br != nil {
		br.failure()
	}
	return resp, lastErr
}

func h2cRoundTripper() http.RoundTripper {
	return &http2.Transport{
		// AllowHTTP: true means we can use h2c (HTTP/2 over cleartext)
		AllowHTTP: true,
		// DialTLS is used for h2c: returns a raw TCP conn
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 60 * time.Second}
			return d.Dial(network, addr)
		},
	}
}

func upstreamKey(req *http.Request) string {
	// per-upstream breaker keyed by scheme://host (ignores path)
	scheme := req.URL.Scheme
	host := req.URL.Host
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + host
}

func isIdempotent(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func isConnErr(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return true
	}
	// TLS handshake errors, etc.
	return false
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 512)
}

func sleepWithJitter(base, max time.Duration, attempt int) {
	// Exponential backoff with jitter, capped at max
	backoff := base << attempt
	if backoff > max {
		backoff = max
	}
	j := time.Duration(rand.Int63n(int64(backoff / 2)))
	time.Sleep(backoff/2 + j)
}

// breaker is a simple state machine: closed -> open -> half-open -> closed
type breaker struct {
	threshold int
	cooldown  time.Duration
	halfMax   int

	state     int32 // 0 closed, 1 open, 2 half-open
	failSeq   int32 // consecutive failures (only used in closed)
	mu        sync.Mutex
	openUntil time.Time
	halfLeft  int32

	name    string
	onEvent func(name, event string)
}

var ErrCircuitOpen = errors.New("circuit breaker open")

func newBreaker(c *config.CircuitBreaker, name string, on func(name, event string)) *breaker {
	return &breaker{
		threshold: maxInt(1, c.OpenAfterConsecutiveFailures),
		cooldown:  time.Duration(maxInt(1, c.CooldownSec)) * time.Second,
		halfMax:   maxInt(1, c.HalfOpenMaxRequests),
		state:     0,
		failSeq:   0,
		halfLeft:  0,
		name:      name,
		onEvent:   on,
	}
}

func (b *breaker) allow() bool {
	s := atomic.LoadInt32(&b.state)
	switch s {
	case 0: // closed
		return true
	case 1: // open
		// if cooldown elapsed, move to half-open
		b.mu.Lock()
		if time.Now().After(b.openUntil) {
			atomic.StoreInt32(&b.state, 2)
			atomic.StoreInt32(&b.halfLeft, int32(b.halfMax))
			// event: half-open
			if b.onEvent != nil {
				b.onEvent(b.name, "half_open")
			}
			b.mu.Unlock()
			return true
		}
		b.mu.Unlock()
		return false
	case 2: // half-open
		// allow limited number of probes
		left := atomic.AddInt32(&b.halfLeft, -1)
		return left >= 0
	default:
		return true
	}
}

func (b *breaker) success() {
	s := atomic.LoadInt32(&b.state)
	switch s {
	case 0: // closed
		atomic.StoreInt32(&b.failSeq, 0)
	case 1: // open -> ignore
	case 2: // half-open: if a success occurs and we have no more probes outstanding, close
		if atomic.LoadInt32(&b.halfLeft) <= 0 {
			atomic.StoreInt32(&b.state, 0)
			atomic.StoreInt32(&b.failSeq, 0)
			if b.onEvent != nil {
				b.onEvent(b.name, "close")
			}
		}
	}
}

func (b *breaker) failure() {
	s := atomic.LoadInt32(&b.state)
	switch s {
	case 0: // closed
		if atomic.AddInt32(&b.failSeq, 1) >= int32(b.threshold) {
			// open circuit
			atomic.StoreInt32(&b.state, 1)
			b.mu.Lock()
			b.openUntil = time.Now().Add(b.cooldown)
			b.mu.Unlock()
			if b.onEvent != nil {
				b.onEvent(b.name, "open")
			}
		}
	case 1: // open -> ignore
	case 2: // half-open -> open again immediately
		atomic.StoreInt32(&b.state, 1)
		b.mu.Lock()
		b.openUntil = time.Now().Add(b.cooldown)
		b.mu.Unlock()
		if b.onEvent != nil {
			b.onEvent(b.name, "open")
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
