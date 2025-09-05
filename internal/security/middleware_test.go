package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arencloud/hecate/internal/config"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
}

func TestAdminBearer(t *testing.T) {
	mw := AdminAuthMiddleware(&config.AdminAuth{BearerToken: "tok"})
	srv := httptest.NewServer(mw(okHandler()))
	defer srv.Close()

	// Missing header -> 401
	req, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	// Good token -> 200
	req2, _ := http.NewRequest("GET", srv.URL+"/admin", nil)
	req2.Header.Set("Authorization", "Bearer tok")
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp2.StatusCode)
	}
}

func TestAdminBasic(t *testing.T) {
	mw := AdminAuthMiddleware(&config.AdminAuth{
		Basic: &config.BasicAuth{Username: "u", Password: "p"},
	})
	srv := httptest.NewServer(mw(okHandler()))
	defer srv.Close()

	// missing -> 401
	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	// good -> 200
	req2, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req2.SetBasicAuth("u", "p")
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp2.StatusCode)
	}
}

func TestAdminHealthzBypass(t *testing.T) {
	mw := AdminAuthMiddleware(&config.AdminAuth{BearerToken: "tok"})
	srv := httptest.NewServer(mw(okHandler()))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/healthz", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("healthz should pass, got %d", resp.StatusCode)
	}
}
