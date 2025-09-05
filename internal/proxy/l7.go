package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	"github.com/arencloud/hecate/internal/config"
)

type L7 struct {
	log         *slog.Logger
	cfg         *config.Config
	routers     []*router
	limiter     *rate.Limiter
	headerCap   int
	bodyCap     int64
	clientIPHdr string
	hc          *healthManager

	draining atomic.Bool
}

func NewL7(log *slog.Logger, cfg *config.Config) (*L7, error) {
	// Build shared base transport and wrap with retry/circuit breaker
	baseTransport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 60 * time.Second}).DialContext,
		MaxIdleConns:        1024,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,                                      // HTTP/2 upstreams if available
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12}, // can be tightened
	}
	rt := newPolicyRoundTripper(baseTransport, cfg.Proxy.Retry, cfg.Proxy.CB)

	rtrs := make([]*router, 0, len(cfg.Proxy.Routes))
	for _, r := range cfg.Proxy.Routes {
		rtx, err := newRouter(log, r, rt, getOrDefault(cfg.Proxy.Limits, func(l *config.Limits) string { return l.ClientIPHeader }, ""))
		if err != nil {
			return nil, err
		}
		rtrs = append(rtrs, rtx)
	}
	var lim *rate.Limiter
	if cfg.Proxy.Limits != nil && cfg.Proxy.Limits.RPS > 0 {
		burst := cfg.Proxy.Limits.Burst
		if burst <= 0 {
			burst = cfg.Proxy.Limits.RPS
		}
		lim = rate.NewLimiter(rate.Limit(cfg.Proxy.Limits.RPS), burst)
	}
	hm := newHealthManager(log, cfg)
	return &L7{
		log:         log,
		cfg:         cfg,
		routers:     rtrs,
		limiter:     lim,
		headerCap:   getOrDefault(cfg.Proxy.Limits, func(l *config.Limits) int { return l.HeaderBytesCap }, 1<<20),  // 1MB
		bodyCap:     getOrDefault(cfg.Proxy.Limits, func(l *config.Limits) int64 { return l.BodyBytesCap }, 10<<20), // 10MB
		clientIPHdr: getOrDefault(cfg.Proxy.Limits, func(l *config.Limits) string { return l.ClientIPHeader }, ""),
		hc:          hm,
	}, nil
}

func (l *L7) SetDraining(on bool) {
	l.draining.Store(on)
}

func (l *L7) IsDraining() bool {
	return l.draining.Load()
}

func getOrDefault[T any, V any](ptr *T, getter func(*T) V, def V) V {
	if ptr == nil {
		return def
	}
	return getter(ptr)
}

func (l *L7) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Draining: politely refuse new requests and encourage clients to close.
	if l.draining.Load() {
		w.Header().Set("Connection", "close")
		http.Error(w, "server is draining", http.StatusServiceUnavailable)
		return
	}

	// Safety caps
	r.Body = http.MaxBytesReader(w, r.Body, l.bodyCap)
	r2 := r.Clone(r.Context())
	r2.Header = cloneHeaderWithCap(r.Header, l.headerCap)

	// Rate limiting (per-node simple limiter)
	if l.limiter != nil {
		if !l.limiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	host := strings.ToLower(r2.Host)
	for _, rt := range l.routers {
		if rt.matches(host, r2.URL.Path) {
			rt.serve(w, r2, l.hc)
			return
		}
	}
	http.NotFound(w, r2)
}

func cloneHeaderWithCap(h http.Header, cap int) http.Header {
	out := make(http.Header, len(h))
	var total int
	for k, vv := range h {
		for _, v := range vv {
			total += len(k) + len(v)
			if total > cap {
				continue
			}
			out.Add(k, v)
		}
	}
	return out
}

type router struct {
	log         *slog.Logger
	name        string
	hosts       map[string]struct{}
	pathPref    string
	backends    []*backend
	beByID      map[string]*backend
	nextIdx     uint32 // round-robin
	lbAlg       string
	hashKey     string
	sticky      *config.Stickiness
	clientIPHdr string
}

func newRouter(log *slog.Logger, r config.Route, rt http.RoundTripper, clientIPHdr string) (*router, error) {
	hosts := map[string]struct{}{}
	for _, h := range r.Hosts {
		hosts[strings.ToLower(h)] = struct{}{}
	}
	if len(r.Upstreams) == 0 {
		return nil, fmt.Errorf("route %s has no upstreams", r.Name)
	}
	bes := make([]*backend, 0, len(r.Upstreams))
	beMap := make(map[string]*backend, len(r.Upstreams))
	for _, u := range r.Upstreams {
		be, err := newBackend(u, rt)
		if err != nil {
			return nil, err
		}
		bes = append(bes, be)
		beMap[be.target.String()] = be
	}
	lbAlg := "round_robin"
	hashKey := ""
	if r.LB != nil {
		if r.LB.Algorithm != "" {
			lbAlg = strings.ToLower(r.LB.Algorithm)
		}
		hashKey = r.LB.HashKey
	}
	return &router{
		log:         log.With("route", r.Name),
		name:        r.Name,
		hosts:       hosts,
		pathPref:    r.PathPrefix,
		backends:    bes,
		beByID:      beMap,
		lbAlg:       lbAlg,
		hashKey:     hashKey,
		sticky:      r.Stickiness,
		clientIPHdr: clientIPHdr,
	}, nil
}

func (r *router) matches(host, path string) bool {
	if len(r.hosts) > 0 {
		if _, ok := r.hosts[host]; !ok {
			return false
		}
	}
	if r.pathPref == "" {
		return true
	}
	return strings.HasPrefix(path, r.pathPref)
}

func (r *router) serve(w http.ResponseWriter, req *http.Request, hm *healthManager) {
	// select backend with stickiness and algorithm
	be := r.selectBackend(req, hm)
	if be == nil {
		http.Error(w, "no healthy backends", http.StatusBadGateway)
		return
	}

	// Span attributes on server span
	if sp := trace.SpanFromContext(req.Context()); sp != nil {
		attrs := []attribute.KeyValue{
			attribute.String("hecate.route", r.name),
			attribute.String("hecate.lb.algorithm", r.lbAlg),
			attribute.String("hecate.backend.url", be.target.String()),
		}
		if r.sticky != nil && r.sticky.Enabled {
			attrs = append(attrs,
				attribute.String("hecate.sticky.mode", r.sticky.Mode),
				attribute.Bool("hecate.sticky.enabled", true),
			)
		} else {
			attrs = append(attrs, attribute.Bool("hecate.sticky.enabled", false))
		}
		sp.SetAttributes(attrs...)
	}

	// If stickiness enabled, set marker for client
	if r.sticky != nil && r.sticky.Enabled {
		r.injectStickiness(w, be)
	}
	be.proxy.ServeHTTP(w, req)
}

func (r *router) selectBackend(req *http.Request, hm *healthManager) *backend {
	// 1) sticky mapping from cookie/header
	if r.sticky != nil && r.sticky.Enabled {
		if id := r.readSticky(req); id != "" {
			if be := r.beByID[id]; be != nil {
				if hm == nil || hm.isHealthy(be.target) {
					return be
				}
			}
		}
	}
	// 2) algorithmic selection
	switch r.lbAlg {
	case "consistent_hash":
		// determine hash key
		key := r.hashSource(req)
		if key == "" {
			// fallback to round robin
			return r.nextHealthyRR(hm)
		}
		return r.chooseByHash(key, hm)
	default: // round_robin
		return r.nextHealthyRR(hm)
	}
}

func (r *router) nextHealthyRR(hm *healthManager) *backend {
	n := len(r.backends)
	for i := 0; i < n; i++ {
		idx := int(atomic.AddUint32(&r.nextIdx, 1)) % n
		be := r.backends[idx]
		if hm == nil || hm.isHealthy(be.target) {
			return be
		}
	}
	return nil
}

func (r *router) chooseByHash(key string, hm *healthManager) *backend {
	// Build a list of healthy backends and stable index mapping
	healthy := make([]*backend, 0, len(r.backends))
	for _, be := range r.backends {
		if hm == nil || hm.isHealthy(be.target) {
			healthy = append(healthy, be)
		}
	}
	if len(healthy) == 0 {
		return nil
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	idx := jumpHash(h.Sum64(), len(healthy))
	return healthy[idx]
}

func (r *router) hashSource(req *http.Request) string {
	// Priority: explicit header/cookie name in LB.HashKey
	if r.hashKey != "" {
		// check cookie first, then header
		if c, err := req.Cookie(r.hashKey); err == nil && c.Value != "" {
			return c.Value
		}
		if v := req.Header.Get(r.hashKey); v != "" {
			return v
		}
	}
	// fallback to client IP
	ip := clientIP(req, r.clientIPHdr)
	if ip != "" {
		return ip
	}
	// final fallback: host+path for object-level stickiness
	return req.Host + req.URL.Path
}

func clientIP(r *http.Request, header string) string {
	if header != "" {
		if v := r.Header.Get(header); v != "" {
			// may contain multiple IPs (X-Forwarded-For), take first
			parts := strings.Split(v, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (r *router) readSticky(req *http.Request) string {
	st := r.sticky
	if st == nil || !st.Enabled {
		return ""
	}
	switch strings.ToLower(st.Mode) {
	case "header":
		return req.Header.Get(st.HeaderName)
	default: // cookie
		if c, err := req.Cookie(st.CookieName); err == nil {
			return c.Value
		}
	}
	return ""
}

func (r *router) injectStickiness(w http.ResponseWriter, be *backend) {
	st := r.sticky
	if st == nil || !st.Enabled {
		return
	}
	val := be.target.String()
	switch strings.ToLower(st.Mode) {
	case "header":
		w.Header().Set(st.HeaderName, val)
	default:
		// Set a cookie on first write using a wrapper to ensure it reaches client
		c := &http.Cookie{
			Name:     st.CookieName,
			Value:    val,
			MaxAge:   st.TTLSeconds,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			// Secure flag could be set when serving HTTPS; omitted here for simplicity
		}
		// If headers aren't written yet, we can set directly
		http.SetCookie(w, c)
	}
}

type backend struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func newBackend(raw string, rt http.RoundTripper) (*backend, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	// Timeout/Retry/Circuit-breaker handled by provided RoundTripper
	rp.Transport = rt

	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		// Add simple trace header
		if r.Header.Get("X-Request-Id") == "" {
			r.Header.Set("X-Request-Id", genID())
		}
		// Add Via header for requests
		// Note: transport will also set Via per-attempt; this ensures at least one is present.
		if v := r.Header.Get("Via"); v == "" {
			r.Header.Set("Via", "1.1 hecate")
		}
	}

	// Copy retry attempt to client response and add Via header
	rp.ModifyResponse = func(resp *http.Response) error {
		if resp != nil && resp.Request != nil {
			if a := resp.Request.Header.Get("X-Hecate-Retry-Attempt"); a != "" {
				resp.Header.Set("X-Retry-Attempt", a)
			}
			// Ensure Via on response
			// Append if already present (comma-separated as per RFC)
			if v := resp.Header.Get("Via"); v == "" {
				resp.Header.Set("Via", "1.1 hecate")
			} else if !strings.Contains(v, "hecate") {
				resp.Header.Set("Via", v+", 1.1 hecate")
			}
		}
		return nil
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		code := http.StatusBadGateway
		var nErr net.Error
		if errors.As(e, &nErr) && nErr.Timeout() {
			code = http.StatusGatewayTimeout
		}
		http.Error(w, http.StatusText(code), code)
	}
	return &backend{
		target: u,
		proxy:  rp,
	}, nil
}

func genID() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// health manager — simple active health checking
type healthManager struct {
	log      *slog.Logger
	cfg      *config.Config
	mu       sync.RWMutex
	healthy  map[string]bool // upstream URL -> health
	interval time.Duration
	timeout  time.Duration
	failTh   int
	resetTh  int
	counts   map[string]int // consecutive fail or success
}

func newHealthManager(log *slog.Logger, cfg *config.Config) *healthManager {
	h := cfg.Proxy.Health
	if h == nil || h.IntervalSec <= 0 {
		return nil
	}
	m := &healthManager{
		log:      log.With("component", "health"),
		cfg:      cfg,
		healthy:  map[string]bool{},
		interval: time.Duration(h.IntervalSec) * time.Second,
		timeout:  time.Duration(h.TimeoutSec) * time.Second,
		failTh:   max(1, h.FailThreshold),
		resetTh:  max(1, h.SuccessReset),
		counts:   map[string]int{},
	}
	// Seed all upstreams as healthy initially
	for _, r := range cfg.Proxy.Routes {
		for _, u := range r.Upstreams {
			m.healthy[u] = true
		}
	}
	go m.loop()
	return m
}

func (m *healthManager) loop() {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	client := &http.Client{Timeout: m.timeout}
	for range t.C {
		for _, r := range m.cfg.Proxy.Routes {
			for _, u := range r.Upstreams {
				ok := m.checkHTTP(client, u)
				m.update(u, ok)
			}
		}
	}
}

func (m *healthManager) checkHTTP(c *http.Client, upstream string) bool {
	// HEAD /healthz (fallback to GET /)
	url := strings.TrimRight(upstream, "/") + "/healthz"
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		// try GET /
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(upstream, "/")+"/", nil)
		resp, err = c.Do(req2)
		if err != nil {
			return false
		}
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode < 500
}

func (m *healthManager) update(upstream string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.healthy[upstream]
	cnt := m.counts[upstream]
	if success {
		if cnt < 0 {
			cnt++
			if -cnt >= m.resetTh {
				m.healthy[upstream] = true
				m.counts[upstream] = 0
				m.log.Info("upstream recovered", "upstream", upstream)
				return
			}
			m.counts[upstream] = cnt
			return
		}
		m.healthy[upstream] = true
		m.counts[upstream] = 0
		return
	}
	// failure path
	if cur {
		cnt++
		if cnt >= m.failTh {
			m.healthy[upstream] = false
			m.counts[upstream] = -1 // start recovery counting negative
			m.log.Warn("upstream marked unhealthy", "upstream", upstream)
			return
		}
		m.counts[upstream] = cnt
		return
	}
	// already unhealthy, continue negative streak
	m.counts[upstream] = -1
}

func (m *healthManager) isHealthy(target *url.URL) bool {
	if m == nil {
		return true
	}
	mu := target.String()
	m.mu.RLock()
	h := m.healthy[mu]
	m.mu.RUnlock()
	return h
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
