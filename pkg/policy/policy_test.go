package policy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arencloud/hecate/internal/config"
)

func baseLogger() *slog.Logger { return slog.New(slog.NewTextHandler(httptest.NewRecorder(), nil)) }

func TestIPACLAllowDeny(t *testing.T) {
	mw := newIPACL(baseLogger(), &config.IPACL{
		AllowCIDRs: []string{"10.0.0.0/8"},
		DenyCIDRs:  []string{"10.1.0.0/16"},
	})
	ok := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ok = true; w.WriteHeader(200) })

	// Deny specific subnet
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	rr := httptest.NewRecorder()
	mw.Handle(rr, req, h)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rr.Code)
	}

	// Allow other in 10.0.0.0/8
	req2 := httptest.NewRequest("GET", "http://x/", nil)
	req2.RemoteAddr = "10.2.2.2:5555"
	rr2 := httptest.NewRecorder()
	mw.Handle(rr2, req2, h)
	if rr2.Code != 200 || !ok {
		t.Fatalf("want 200, got %d", rr2.Code)
	}
}

func TestKeyLimiterHeader(t *testing.T) {
	mw := newKeyLimiter(&config.KeyRate{
		RPS:   1,
		Burst: 1,
		Key:   "header:X-API-Key",
	})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	req := httptest.NewRequest("GET", "http://x/a", nil)
	req.Header.Set("X-API-Key", "k")
	rr1 := httptest.NewRecorder()
	mw.Handle(rr1, req, h)
	if rr1.Code != 200 {
		t.Fatalf("first should pass, got %d", rr1.Code)
	}
	// second immediate should be limited
	rr2 := httptest.NewRecorder()
	mw.Handle(rr2, req, h)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rr2.Code)
	}
}

func TestRouteAuthBearer(t *testing.T) {
	ra := newRouteAuth(&config.RouteAuth{BearerToken: "tok"})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	// Missing -> 401
	req := httptest.NewRequest("GET", "http://x/a", nil)
	rr := httptest.NewRecorder()
	ra.Handle(rr, req, h)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	// Good -> 200
	req2 := httptest.NewRequest("GET", "http://x/a", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	rr2 := httptest.NewRecorder()
	ra.Handle(rr2, req2, h)
	if rr2.Code != 200 {
		t.Fatalf("want 200, got %d", rr2.Code)
	}
}

func TestRoutePolicyApplyFirstMatch(t *testing.T) {
	cfg := &config.Config{
		Proxy: config.Proxy{
			Routes: []config.Route{
				{
					Name:       "api",
					Hosts:      []string{"x"},
					PathPrefix: "/api",
					Policy: &config.Policy{
						RateLimit: &config.KeyRate{RPS: 1, Burst: 1, Key: "ip"},
					},
				},
			},
		},
	}
	mw := newRoutePolicy(baseLogger(), cfg)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	req := httptest.NewRequest("GET", "http://x/api/items", nil)
	req.RemoteAddr = net.JoinHostPort("1.2.3.4", "1234")
	rr1 := httptest.NewRecorder()
	mw.Handle(rr1, req, h)
	if rr1.Code != 200 {
		t.Fatalf("want 200, got %d", rr1.Code)
	}
	// second should be throttled
	rr2 := httptest.NewRecorder()
	mw.Handle(rr2, req, h)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rr2.Code)
	}
}
