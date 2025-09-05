package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Admin     Admin      `yaml:"admin"`
	Proxy     Proxy      `yaml:"proxy"`
	TLS       TLS        `yaml:"tls"`
	Telemetry *Telemetry `yaml:"telemetry,omitempty"`
	// Future: discovery, policies, glb, rate-limits, waf, auth, observability, etc.
}

type Admin struct {
	Listen string     `yaml:"listen"` // e.g. ":9000"
	Auth   *AdminAuth `yaml:"auth,omitempty"`
}

type AdminAuth struct {
	// Choose one of:
	Basic *BasicAuth `yaml:"basic,omitempty"`
	// Or a static bearer token
	BearerToken string `yaml:"bearerToken,omitempty"`
}

type BasicAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Proxy struct {
	Listen string          `yaml:"listen"` // e.g. ":8443"
	Routes []Route         `yaml:"routes"`
	Limits *Limits         `yaml:"limits,omitempty"`
	Health *Health         `yaml:"health,omitempty"`
	Retry  *RetryPolicy    `yaml:"retry,omitempty"`
	CB     *CircuitBreaker `yaml:"circuitBreaker,omitempty"`
	Server *ServerTimeouts `yaml:"server,omitempty"`
	// Protocol toggles
	EnableHTTP3       bool `yaml:"enableHTTP3,omitempty"`       // enable HTTP/3 (QUIC)
	EnableH2C         bool `yaml:"enableH2C,omitempty"`         // accept HTTP/2 cleartext when TLS is disabled
	EnableUpstreamH2C bool `yaml:"enableUpstreamH2C,omitempty"` // allow HTTP/2 cleartext to http:// upstreams
	// Optional separate address for HTTP/3 (UDP). If empty, uses Listen.
	HTTP3Listen string `yaml:"http3Listen,omitempty"`

	Policy *Policy `yaml:"policy,omitempty"`
}

type Limits struct {
	RPS            int    `yaml:"rps"`            // per-listener simple token bucket
	Burst          int    `yaml:"burst"`          // burst size
	HeaderBytesCap int    `yaml:"headerBytesCap"` // safety cap
	BodyBytesCap   int64  `yaml:"bodyBytesCap"`   // safety cap
	ClientIPHeader string `yaml:"clientIPHeader"` // e.g. X-Forwarded-For or X-Real-IP
}

type Health struct {
	IntervalSec int `yaml:"intervalSec"`
	TimeoutSec  int `yaml:"timeoutSec"`
	// Outlier ejection: consecutive failures to mark unhealthy
	FailThreshold int `yaml:"failThreshold"`
	SuccessReset  int `yaml:"successReset"`
}

type Route struct {
	Name       string         `yaml:"name"`
	Hosts      []string       `yaml:"hosts"` // SNI/Host match
	PathPrefix string         `yaml:"pathPrefix"`
	Upstreams  []string       `yaml:"upstreams"` // http(s)://host:port
	LB         *LoadBalancing `yaml:"lb,omitempty"`
	Stickiness *Stickiness    `yaml:"stickiness,omitempty"`
	// Optional route-level policy override/extension
	Policy *Policy `yaml:"policy,omitempty"`
	// Optional route-level public auth
	Auth *RouteAuth `yaml:"auth,omitempty"`
}

// Public route auth (Basic or Bearer)
type RouteAuth struct {
	Basic       *BasicAuth `yaml:"basic,omitempty"`
	BearerToken string     `yaml:"bearerToken,omitempty"`
}

type TLS struct {
	// File paths to PEM cert and key; support multiple for SNI
	CertFiles []string `yaml:"certFiles"`
	KeyFiles  []string `yaml:"keyFiles"`
	// Optional: client auth (mTLS)
	ClientCAFile      string `yaml:"clientCAFile,omitempty"`
	RequireClientCert bool   `yaml:"requireClientCert,omitempty"`
	// Min/max versions are TLS 1.3 by default in Go 1.24
}

// RetryPolicy defines outbound retry behavior for upstream requests.
type RetryPolicy struct {
	MaxRetries        int  `yaml:"maxRetries"`        // total retries after first attempt (e.g., 2)
	PerTryTimeoutSec  int  `yaml:"perTryTimeoutSec"`  // per-try timeout in seconds
	RetryOn5xx        bool `yaml:"retryOn5xx"`        // retry on 502/503/504
	RetryOnConnectErr bool `yaml:"retryOnConnectErr"` // retry on dial/TLS/timeouts
	RetryIdempotent   bool `yaml:"retryIdempotent"`   // only retry GET/HEAD/OPTIONS/TRACE by default
	// Backoff
	BackoffBaseMs int `yaml:"backoffBaseMs"` // base backoff (e.g., 50ms)
	BackoffMaxMs  int `yaml:"backoffMaxMs"`  // max backoff cap (e.g., 500ms)
}

// CircuitBreaker defines a simple consecutive-failure breaker.
type CircuitBreaker struct {
	OpenAfterConsecutiveFailures int `yaml:"openAfterConsecutiveFailures"` // e.g., 5
	CooldownSec                  int `yaml:"cooldownSec"`                  // time in open state (e.g., 30)
	HalfOpenMaxRequests          int `yaml:"halfOpenMaxRequests"`          // probe requests allowed when half-open (e.g., 10)
}

// ServerTimeouts controls the public listener behavior.
type ServerTimeouts struct {
	ReadHeaderTimeoutSec int `yaml:"readHeaderTimeoutSec"` // default 10
	ReadTimeoutSec       int `yaml:"readTimeoutSec"`       // optional
	WriteTimeoutSec      int `yaml:"writeTimeoutSec"`      // optional
	IdleTimeoutSec       int `yaml:"idleTimeoutSec"`       // default 90
	MaxHeaderBytes       int `yaml:"maxHeaderBytes"`       // default 1<<20 (1MB)
}

// LoadBalancing selects the algorithm and hash key.
type LoadBalancing struct {
	Algorithm       string `yaml:"algorithm"`                 // "round_robin" (default) or "consistent_hash"
	HashKey         string `yaml:"hashKey,omitempty"`         // header/cookie name to hash; fallback to client IP
	MaglevTableSize int    `yaml:"maglevTableSize,omitempty"` // reserved for future
}

// Stickiness enables session affinity.
type Stickiness struct {
	Enabled    bool   `yaml:"enabled"`
	Mode       string `yaml:"mode,omitempty"`       // "cookie" (default) or "header"
	CookieName string `yaml:"cookieName,omitempty"` // default: hecate_sticky_<route>
	HeaderName string `yaml:"headerName,omitempty"` // default: X-Hecate-Sticky
	TTLSeconds int    `yaml:"ttlSeconds,omitempty"` // default: 3600
}

// Telemetry config for OpenTelemetry.
type Telemetry struct {
	ServiceName  string            `yaml:"serviceName"`            // e.g., "hecate"
	OTLPEndpoint string            `yaml:"otlpEndpoint,omitempty"` // e.g., "http://localhost:4318"
	Headers      map[string]string `yaml:"headers,omitempty"`      // optional exporter headers
	Insecure     bool              `yaml:"insecure,omitempty"`     // OTLP/HTTP without TLS
	Sampling     float64           `yaml:"sampling,omitempty"`     // 0..1
}

// Policy config for WAF/pipeline
type Policy struct {
	IPACL     *IPACL     `yaml:"ipAcl,omitempty"`
	GeoIP     *GeoIP     `yaml:"geoIp,omitempty"`
	ASN       *ASN       `yaml:"asn,omitempty"`
	RateLimit *KeyRate   `yaml:"rateLimit,omitempty"`
	Paths     []PathRule `yaml:"paths,omitempty"`
	// Expose LRU cache stats to /debug/vars if true
	CacheStats bool `yaml:"cacheStats,omitempty"`
}

type IPACL struct {
	AllowCIDRs []string `yaml:"allowCidrs,omitempty"`
	DenyCIDRs  []string `yaml:"denyCidrs,omitempty"`
}

// GeoIP: allow/deny by ISO country code. Requires city DB.
type GeoIP struct {
	DBPath         string   `yaml:"dbPath,omitempty"`         // MaxMind City DB (mmdb), optional
	AllowCountries []string `yaml:"allowCountries,omitempty"` // ISO codes (e.g., "US","DE")
	DenyCountries  []string `yaml:"denyCountries,omitempty"`  // takes precedence
	// Cache settings (optional)
	CacheTTLSeconds int `yaml:"cacheTtlSeconds,omitempty"`
	CacheMaxEntries int `yaml:"cacheMaxEntries,omitempty"`
}

// ASN: allow/deny by ASN number. Requires ASN DB.
type ASN struct {
	DBPath   string `yaml:"dbPath,omitempty"` // MaxMind ASN DB (mmdb), optional
	AllowASN []uint `yaml:"allowAsn,omitempty"`
	DenyASN  []uint `yaml:"denyAsn,omitempty"` // takes precedence
	// Cache settings (optional)
	CacheTTLSeconds int `yaml:"cacheTtlSeconds,omitempty"`
	CacheMaxEntries int `yaml:"cacheMaxEntries,omitempty"`
}

type KeyRate struct {
	RPS   int `yaml:"rps"`
	Burst int `yaml:"burst"`
	// Key selector:
	// "ip" (default) or "header:<Name>" or "cookie:<Name>"
	Key string `yaml:"key,omitempty"`
}

// Per-path overrides (prefix match) for rate limits.
type PathRule struct {
	PathPrefix string   `yaml:"pathPrefix"`
	RateLimit  *KeyRate `yaml:"rateLimit,omitempty"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	// Defaults
	if c.Admin.Listen == "" {
		c.Admin.Listen = ":9000"
	}
	if c.Proxy.Listen == "" {
		c.Proxy.Listen = ":8443"
	}
	// Retry defaults
	if c.Proxy.Retry == nil {
		c.Proxy.Retry = &RetryPolicy{
			MaxRetries:        2,
			PerTryTimeoutSec:  2,
			RetryOn5xx:        true,
			RetryOnConnectErr: true,
			RetryIdempotent:   true,
			BackoffBaseMs:     50,
			BackoffMaxMs:      500,
		}
	}
	// Circuit breaker defaults
	if c.Proxy.CB == nil {
		c.Proxy.CB = &CircuitBreaker{
			OpenAfterConsecutiveFailures: 5,
			CooldownSec:                  30,
			HalfOpenMaxRequests:          10,
		}
	}
	// Server timeouts defaults
	if c.Proxy.Server == nil {
		c.Proxy.Server = &ServerTimeouts{
			ReadHeaderTimeoutSec: 10,
			IdleTimeoutSec:       90,
			MaxHeaderBytes:       1 << 20,
		}
	} else {
		if c.Proxy.Server.ReadHeaderTimeoutSec <= 0 {
			c.Proxy.Server.ReadHeaderTimeoutSec = 10
		}
		if c.Proxy.Server.IdleTimeoutSec <= 0 {
			c.Proxy.Server.IdleTimeoutSec = 90
		}
		if c.Proxy.Server.MaxHeaderBytes <= 0 {
			c.Proxy.Server.MaxHeaderBytes = 1 << 20
		}
	}
	// Fill per-route defaults
	for i := range c.Proxy.Routes {
		if c.Proxy.Routes[i].LB == nil {
			c.Proxy.Routes[i].LB = &LoadBalancing{Algorithm: "round_robin"}
		} else if c.Proxy.Routes[i].LB.Algorithm == "" {
			c.Proxy.Routes[i].LB.Algorithm = "round_robin"
		}
		if c.Proxy.Routes[i].Stickiness != nil && c.Proxy.Routes[i].Stickiness.Enabled {
			st := c.Proxy.Routes[i].Stickiness
			if st.Mode == "" {
				st.Mode = "cookie"
			}
			if st.CookieName == "" {
				st.CookieName = "hecate_sticky_" + c.Proxy.Routes[i].Name
			}
			if st.HeaderName == "" {
				st.HeaderName = "X-Hecate-Sticky"
			}
			if st.TTLSeconds <= 0 {
				st.TTLSeconds = 3600
			}
		}
	}
	// Policy sane defaults
	if c.Proxy.Policy != nil && c.Proxy.Policy.RateLimit != nil {
		if c.Proxy.Policy.RateLimit.Burst <= 0 {
			c.Proxy.Policy.RateLimit.Burst = c.Proxy.Policy.RateLimit.RPS
		}
		if c.Proxy.Policy.RateLimit.Key == "" {
			c.Proxy.Policy.RateLimit.Key = "ip"
		}
	}
	for i := range c.Proxy.Routes {
		if p := c.Proxy.Routes[i].Policy; p != nil {
			if p.RateLimit != nil {
				if p.RateLimit.Burst <= 0 {
					p.RateLimit.Burst = p.RateLimit.RPS
				}
				if p.RateLimit.Key == "" {
					p.RateLimit.Key = "ip"
				}
			}
			for j := range p.Paths {
				if pr := p.Paths[j].RateLimit; pr != nil {
					if pr.Burst <= 0 {
						pr.Burst = pr.RPS
					}
					if pr.Key == "" {
						pr.Key = "ip"
					}
				}
			}
		}
	}
	// Telemetry defaults
	if c.Telemetry == nil {
		c.Telemetry = &Telemetry{
			ServiceName: "hecate",
			Sampling:    0.1,
		}
	} else {
		if c.Telemetry.ServiceName == "" {
			c.Telemetry.ServiceName = "hecate"
		}
		if c.Telemetry.Sampling <= 0 {
			c.Telemetry.Sampling = 0.1
		}
	}
	return &c, nil
}
