package policy

import (
	"crypto/subtle"
	"expvar"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/arencloud/hecate/internal/config"
	"github.com/arencloud/hecate/internal/telemetry"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/time/rate"
)

// Middleware interface
type Middleware interface {
	Handle(w http.ResponseWriter, r *http.Request, next http.Handler)
}

// BuildChain builds the public Policy/WAF chain as a reusable library.
func BuildChain(logger *slog.Logger, cfg *config.Config, next http.Handler) http.Handler {
	var mws []Middleware

	// Global IP ACL
	if cfg.Proxy.Policy != nil && cfg.Proxy.Policy.IPACL != nil {
		if mw := newIPACL(logger, cfg.Proxy.Policy.IPACL); mw != nil {
			mws = append(mws, mw)
		}
	}
	// Global GeoIP/ASN
	if cfg.Proxy.Policy != nil && (cfg.Proxy.Policy.GeoIP != nil || cfg.Proxy.Policy.ASN != nil) {
		stats := false
		if cfg.Proxy.Policy != nil {
			stats = cfg.Proxy.Policy.CacheStats
		}
		mws = append(mws, newGeoASN(logger, cfg.Proxy.Policy.GeoIP, cfg.Proxy.Policy.ASN, stats))
	}
	// Global rate limit
	if cfg.Proxy.Policy != nil && cfg.Proxy.Policy.RateLimit != nil && cfg.Proxy.Policy.RateLimit.RPS > 0 {
		mws = append(mws, newKeyLimiter(cfg.Proxy.Policy.RateLimit))
	}
	// Route-level policy
	if len(cfg.Proxy.Routes) > 0 {
		mws = append(mws, newRoutePolicy(logger, cfg))
	}
	// Adapter
	mws = append(mws, &adaptNext{next: next})
	return &mwChain{mws: mws}
}

// -------------------- Chain driver --------------------

type mwChain struct {
	mws []Middleware
}

func (m *mwChain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var idx int
	var next http.Handler
	next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if idx >= len(m.mws) {
			return
		}
		cur := m.mws[idx]
		idx++
		cur.Handle(w, r, next)
	})
	next.ServeHTTP(w, r)
}

type adaptNext struct{ next http.Handler }

func (a *adaptNext) Handle(w http.ResponseWriter, r *http.Request, _ http.Handler) {
	a.next.ServeHTTP(w, r)
}

// -------------------- Helpers --------------------

func clientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := net.ParseIP(strings.TrimSpace(parts[0]))
		if ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// -------------------- IP ACL --------------------

type ipACL struct {
	log   *slog.Logger
	allow []*net.IPNet
	deny  []*net.IPNet
}

func newIPACL(log *slog.Logger, c *config.IPACL) Middleware {
	parse := func(cidrs []string) []*net.IPNet {
		var res []*net.IPNet
		for _, s := range cidrs {
			if s == "" {
				continue
			}
			_, n, err := net.ParseCIDR(strings.TrimSpace(s))
			if err == nil && n != nil {
				res = append(res, n)
			}
		}
		return res
	}
	return &ipACL{
		log:   log.With("mw", "ipacl"),
		allow: parse(c.AllowCIDRs),
		deny:  parse(c.DenyCIDRs),
	}
}

func (m *ipACL) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ip := clientIP(r)
	for _, n := range m.deny {
		if n.Contains(ip) {
			telemetry.PolicyHit("ipacl_deny")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	if len(m.allow) > 0 {
		ok := false
		for _, n := range m.allow {
			if n.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			telemetry.PolicyHit("ipacl_deny")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		telemetry.PolicyHit("ipacl_allow")
	} else {
		telemetry.PolicyMiss("ipacl")
	}
	next.ServeHTTP(w, r)
}

// -------------------- GeoIP/ASN with LRU + TTL cache, expvar stats, graceful close --------------------

var (
	cacheVarsOnce sync.Once
	cacheVars     *expvar.Map

	closeMu sync.Mutex
	closers []io.Closer
)

func registerCloser(c io.Closer) {
	closeMu.Lock()
	closers = append(closers, c)
	closeMu.Unlock()
}

// Shutdown closes any open DB handles (call on hot reload).
func Shutdown() {
	closeMu.Lock()
	defer closeMu.Unlock()
	for _, c := range closers {
		_ = c.Close()
	}
	closers = nil
}

type cacheEntry[T any] struct {
	key        string
	val        T
	exp        time.Time
	prev, next *cacheEntry[T]
}

type lruCache[T any] struct {
	mu     sync.Mutex
	items  map[string]*cacheEntry[T]
	head   *cacheEntry[T]
	tail   *cacheEntry[T]
	ttl    time.Duration
	maxEnt int

	// stats
	name      string
	hits      uint64
	misses    uint64
	evictions uint64
	statsOn   bool
}

func newLRU[T any](ttl time.Duration, maxEnt int, name string, stats bool) *lruCache[T] {
	if maxEnt <= 0 {
		maxEnt = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c := &lruCache[T]{
		items:   make(map[string]*cacheEntry[T], maxEnt),
		ttl:     ttl,
		maxEnt:  maxEnt,
		name:    name,
		statsOn: stats,
	}
	if stats {
		cacheVarsOnce.Do(func() {
			cacheVars = expvar.NewMap("hecate_policy_cache")
		})
	}
	return c
}

func (c *lruCache[T]) publish() {
	if !c.statsOn || cacheVars == nil {
		return
	}
	m := new(expvar.Map).Init()

	h := new(expvar.Int)
	h.Set(int64(c.hits))
	m.Set("hits", h)

	ms := new(expvar.Int)
	ms.Set(int64(c.misses))
	m.Set("misses", ms)

	ev := new(expvar.Int)
	ev.Set(int64(c.evictions))
	m.Set("evictions", ev)

	sz := new(expvar.Int)
	sz.Set(int64(len(c.items)))
	m.Set("size", sz)

	ttl := new(expvar.Int)
	ttl.Set(int64(c.ttl.Seconds()))
	m.Set("ttl_seconds", ttl)

	max := new(expvar.Int)
	max.Set(int64(c.maxEnt))
	m.Set("max_entries", max)

	cacheVars.Set(c.name, m)
}

func (c *lruCache[T]) get(key string) (v T, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		c.misses++
		c.publish()
		return v, false
	}
	if time.Now().After(e.exp) {
		c.remove(e)
		delete(c.items, key)
		c.misses++
		c.publish()
		var zero T
		return zero, false
	}
	c.moveToFront(e)
	c.hits++
	c.publish()
	return e.val, true
}

func (c *lruCache[T]) set(key string, val T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		e.val = val
		e.exp = time.Now().Add(c.ttl)
		c.moveToFront(e)
		c.publish()
		return
	}
	e := &cacheEntry[T]{key: key, val: val, exp: time.Now().Add(c.ttl)}
	c.items[key] = e
	c.addToFront(e)
	if len(c.items) > c.maxEnt {
		if c.tail != nil {
			del := c.tail
			c.remove(del)
			delete(c.items, del.key)
			c.evictions++
		}
	}
	c.publish()
}

func (c *lruCache[T]) addToFront(e *cacheEntry[T]) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

func (c *lruCache[T]) moveToFront(e *cacheEntry[T]) {
	if c.head == e {
		return
	}
	c.remove(e)
	c.addToFront(e)
}

func (c *lruCache[T]) remove(e *cacheEntry[T]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

type ipCache[T any] struct {
	mu     sync.RWMutex
	data   map[string]cacheEntry[T]
	ttl    time.Duration
	maxEnt int
}

func newIPCache[T any](ttl time.Duration, maxEnt int) *ipCache[T] {
	return &ipCache[T]{data: make(map[string]cacheEntry[T], maxEnt), ttl: ttl, maxEnt: maxEnt}
}

func (c *ipCache[T]) get(key string) (T, bool) {
	var zero T
	c.mu.RLock()
	e, ok := c.data[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.exp) {
		return zero, false
	}
	return e.val, true
}

func (c *ipCache[T]) set(key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Light eviction: if beyond capacity, clear half (simple strategy)
	if len(c.data) >= c.maxEnt {
		// remove arbitrary ~half
		i := 0
		target := c.maxEnt / 2
		for k := range c.data {
			delete(c.data, k)
			i++
			if i >= target {
				break
			}
		}
	}
	c.data[key] = cacheEntry[T]{val: v, exp: time.Now().Add(c.ttl)}
}

type geoASN struct {
	log     *slog.Logger
	geoDB   *geoip2.Reader
	asnDB   *geoip2.Reader
	allowCC map[string]struct{}
	denyCC  map[string]struct{}
	allowAS map[uint]struct{}
	denyAS  map[uint]struct{}

	ccCache  *lruCache[string]
	asnCache *lruCache[uint]
}

func newGeoASN(log *slog.Logger, g *config.GeoIP, a *config.ASN, stats bool) Middleware {
	var geoDB, asnDB *geoip2.Reader
	var err error
	if g != nil && g.DBPath != "" {
		if geoDB, err = geoip2.Open(g.DBPath); err != nil {
			log.Warn("geoip open failed", "err", err)
		} else {
			registerCloser(geoDB)
		}
	}
	if a != nil && a.DBPath != "" {
		if asnDB, err = geoip2.Open(a.DBPath); err != nil {
			log.Warn("asn db open failed", "err", err)
		} else {
			registerCloser(asnDB)
		}
	}
	setStr := func(ss []string) map[string]struct{} {
		m := map[string]struct{}{}
		for _, s := range ss {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "" {
				m[s] = struct{}{}
			}
		}
		return m
	}
	setU := func(us []uint) map[uint]struct{} {
		m := map[uint]struct{}{}
		for _, u := range us {
			m[u] = struct{}{}
		}
		return m
	}

	var allowCC, denyCC map[string]struct{}
	if g != nil {
		allowCC = setStr(g.AllowCountries)
		denyCC = setStr(g.DenyCountries)
	}
	var allowAS, denyAS map[uint]struct{}
	if a != nil {
		allowAS = setU(a.AllowASN)
		denyAS = setU(a.DenyASN)
	}

	// Cache settings with defaults if unset
	ccTTL := 5 * time.Minute
	ccMax := 10000
	if g != nil {
		if g.CacheTTLSeconds > 0 {
			ccTTL = time.Duration(g.CacheTTLSeconds) * time.Second
		}
		if g.CacheMaxEntries > 0 {
			ccMax = g.CacheMaxEntries
		}
	}
	asTTL := 5 * time.Minute
	asMax := 10000
	if a != nil {
		if a.CacheTTLSeconds > 0 {
			asTTL = time.Duration(a.CacheTTLSeconds) * time.Second
		}
		if a.CacheMaxEntries > 0 {
			asMax = a.CacheMaxEntries
		}
	}

	return &geoASN{
		log:      log.With("mw", "geoasn"),
		geoDB:    geoDB,
		asnDB:    asnDB,
		allowCC:  allowCC,
		denyCC:   denyCC,
		allowAS:  allowAS,
		denyAS:   denyAS,
		ccCache:  newLRU[string](ccTTL, ccMax, "geoip", stats),
		asnCache: newLRU[uint](asTTL, asMax, "asn", stats),
	}
}

func (m *geoASN) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	ip := clientIP(r)
	if ip == nil {
		telemetry.PolicyMiss("geoasn")
		next.ServeHTTP(w, r)
		return
	}
	key := ip.String()

	// Country check
	if m.geoDB != nil && (len(m.allowCC) > 0 || len(m.denyCC) > 0) {
		cc, ok := m.ccCache.get(key)
		if ok {
			telemetry.CacheHit("geoip")
		} else {
			telemetry.CacheMiss("geoip")
			if rec, err := m.geoDB.Country(ip); err == nil {
				cc = strings.ToUpper(rec.Country.IsoCode)
				if cc != "" {
					m.ccCache.set(key, cc)
				}
			}
		}
		if cc != "" {
			if _, bad := m.denyCC[cc]; bad {
				telemetry.PolicyHit("geoip_deny")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if len(m.allowCC) > 0 {
				if _, ok := m.allowCC[cc]; !ok {
					telemetry.PolicyHit("geoip_deny")
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				telemetry.PolicyHit("geoip_allow")
			}
		} else {
			telemetry.PolicyMiss("geoip_lookup")
		}
	}

	// ASN check
	if m.asnDB != nil && (len(m.allowAS) > 0 || len(m.denyAS) > 0) {
		var asn uint
		if v, ok := m.asnCache.get(key); ok {
			telemetry.CacheHit("asn")
			asn = v
		} else {
			telemetry.CacheMiss("asn")
			if rec, err := m.asnDB.ASN(ip); err == nil {
				asn = uint(rec.AutonomousSystemNumber)
				if asn != 0 {
					m.asnCache.set(key, asn)
				}
			}
		}
		if asn != 0 {
			if _, bad := m.denyAS[asn]; bad {
				telemetry.PolicyHit("asn_deny")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if len(m.allowAS) > 0 {
				if _, ok := m.allowAS[asn]; !ok {
					telemetry.PolicyHit("asn_deny")
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				telemetry.PolicyHit("asn_allow")
			}
		} else {
			telemetry.PolicyMiss("asn_lookup")
		}
	}

	if (m.geoDB == nil || (len(m.allowCC) == 0 && len(m.denyCC) == 0)) &&
		(m.asnDB == nil || (len(m.allowAS) == 0 && len(m.denyAS) == 0)) {
		telemetry.PolicyMiss("geoasn")
	}
	next.ServeHTTP(w, r)
}

// -------------------- Keyed Rate Limit (with path bucketing) --------------------

type keyLimiter struct {
	keySel func(*http.Request) string
	limMu  sync.Mutex
	lims   map[string]*rate.Limiter
	rps    rate.Limit
	burst  int
}

func newKeyLimiter(rl *config.KeyRate) Middleware {
	burst := rl.Burst
	if burst <= 0 {
		burst = rl.RPS
	}
	return &keyLimiter{
		keySel: buildKeySelector(rl.Key),
		lims:   make(map[string]*rate.Limiter),
		rps:    rate.Limit(rl.RPS),
		burst:  burst,
	}
}

func buildKeySelector(spec string) func(*http.Request) string {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch {
	case spec == "" || spec == "ip":
		return func(r *http.Request) string { return clientIP(r).String() }
	case strings.HasPrefix(spec, "header:"):
		name := strings.TrimSpace(spec[len("header:"):])
		return func(r *http.Request) string { return r.Header.Get(name) }
	case strings.HasPrefix(spec, "cookie:"):
		name := strings.TrimSpace(spec[len("cookie:"):])
		return func(r *http.Request) string {
			if c, err := r.Cookie(name); err == nil {
				return c.Value
			}
			return ""
		}
	default:
		return func(r *http.Request) string { return clientIP(r).String() }
	}
}

func (k *keyLimiter) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	key := k.keySel(r)
	if key == "" {
		key = "anon"
	}
	bucket := pathBucket(r.URL.Path)
	bucketKey := key + "|" + bucket

	k.limMu.Lock()
	lim, ok := k.lims[bucketKey]
	if !ok {
		lim = rate.NewLimiter(k.rps, k.burst)
		k.lims[bucketKey] = lim
	}
	k.limMu.Unlock()
	if !lim.Allow() {
		telemetry.PolicyHitLabels("ratelimit_deny", "", bucket)
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	telemetry.PolicyHitLabels("ratelimit_allow", "", bucket)
	next.ServeHTTP(w, r)
}

func pathBucket(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) == 1 {
		return "/" + parts[0]
	}
	return "/" + parts[0] + "/" + parts[1]
}

// -------------------- Route-level Policy and Auth --------------------

type routePolicy struct {
	log      *slog.Logger
	cfg      *config.Config
	compiled []routeMatcher
}

type routeMatcher struct {
	name    string
	hostSet map[string]struct{}
	prefix  string
	mws     []Middleware
}

func newRoutePolicy(log *slog.Logger, cfg *config.Config) Middleware {
	var rms []routeMatcher
	for _, rt := range cfg.Proxy.Routes {
		var mws []Middleware
		if rt.Auth != nil {
			mws = append(mws, newRouteAuth(rt.Auth))
		}
		if rt.Policy != nil {
			if rt.Policy.IPACL != nil {
				mws = append(mws, newIPACL(log, rt.Policy.IPACL))
			}
			if rt.Policy.GeoIP != nil || rt.Policy.ASN != nil {
				stats := cfg.Proxy.Policy != nil && cfg.Proxy.Policy.CacheStats
				mws = append(mws, newGeoASN(log, rt.Policy.GeoIP, rt.Policy.ASN, stats))
			}
			if len(rt.Policy.Paths) > 0 {
				mws = append(mws, newPathOverrides(rt.Name, rt.Policy.Paths))
			}
			if rl := rt.Policy.RateLimit; rl != nil && rl.RPS > 0 {
				mws = append(mws, newKeyLimiter(rl))
			}
		}
		hs := map[string]struct{}{}
		for _, h := range rt.Hosts {
			hs[strings.ToLower(h)] = struct{}{}
		}
		rms = append(rms, routeMatcher{
			name:    rt.Name,
			hostSet: hs,
			prefix:  rt.PathPrefix,
			mws:     mws,
		})
	}
	return &routePolicy{log: log.With("mw", "routePolicy"), cfg: cfg, compiled: rms}
}

func (rp *routePolicy) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	host := strings.ToLower(r.Host)
	for _, rm := range rp.compiled {
		if len(rm.hostSet) > 0 {
			if _, ok := rm.hostSet[host]; !ok {
				continue
			}
		}
		if rm.prefix != "" && !strings.HasPrefix(r.URL.Path, rm.prefix) {
			continue
		}
		// route matched
		telemetry.PolicyHitLabels("route_match", rm.name, pathBucket(r.URL.Path))
		var idx int
		var call http.Handler
		call = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if idx >= len(rm.mws) {
				next.ServeHTTP(w, r)
				return
			}
			cur := rm.mws[idx]
			idx++
			cur.Handle(w, r, call)
		})
		call.ServeHTTP(w, r)
		return
	}
	telemetry.PolicyMiss("route_match")
	next.ServeHTTP(w, r)
}

// Path-based overrides for rate limits
type pathOverrides struct {
	route string
	rules []pathRule
}

type pathRule struct {
	prefix string
	rl     *keyLimiter
}

func newPathOverrides(route string, rules []config.PathRule) Middleware {
	var compiled []pathRule
	for _, pr := range rules {
		if pr.RateLimit != nil && pr.RateLimit.RPS > 0 {
			compiled = append(compiled, pathRule{
				prefix: pr.PathPrefix,
				rl:     newKeyLimiter(pr.RateLimit).(*keyLimiter),
			})
		}
	}
	return &pathOverrides{route: route, rules: compiled}
}

func (p *pathOverrides) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	for _, pr := range p.rules {
		if pr.prefix == "" || strings.HasPrefix(r.URL.Path, pr.prefix) {
			telemetry.PolicyHitLabels("path_override_applied", p.route, pr.prefix)
			pr.rl.Handle(w, r, next)
			return
		}
	}
	telemetry.PolicyMiss("path_override")
	next.ServeHTTP(w, r)
}

// -------------------- Route-level Auth --------------------

type routeAuth struct {
	basicUser string
	basicPass string
	bearer    string
}

func newRouteAuth(a *config.RouteAuth) Middleware {
	ra := &routeAuth{}
	if a == nil {
		return ra
	}
	if a.BearerToken != "" {
		ra.bearer = strings.TrimSpace(a.BearerToken)
	}
	if a.Basic != nil {
		ra.basicUser = a.Basic.Username
		ra.basicPass = a.Basic.Password
	}
	return ra
}

func (a *routeAuth) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if a.bearer != "" {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			telemetry.PolicyHit("routeauth_deny")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.bearer)) != 1 {
			telemetry.PolicyHit("routeauth_deny")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		telemetry.PolicyHit("routeauth_allow")
		next.ServeHTTP(w, r)
		return
	}
	if a.basicUser != "" || a.basicPass != "" {
		user, pass, ok := r.BasicAuth()
		if !ok {
			telemetry.PolicyHit("routeauth_deny")
			w.Header().Set("WWW-Authenticate", `Basic realm="hecate"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(user), []byte(a.basicUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(a.basicPass)) != 1 {
			telemetry.PolicyHit("routeauth_deny")
			w.Header().Set("WWW-Authenticate", `Basic realm="hecate"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		telemetry.PolicyHit("routeauth_allow")
	}
	if a.bearer == "" && a.basicUser == "" && a.basicPass == "" {
		telemetry.PolicyMiss("routeauth")
	}
	next.ServeHTTP(w, r)
}
