package security

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/arencloud/hecate/internal/config"
)

// AdminAuthMiddleware applies either Basic or Bearer auth for admin endpoints.
func AdminAuthMiddleware(a *config.AdminAuth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// If no auth configured, pass-through
		if a == nil || (a.Basic == nil && a.BearerToken == "") {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow unauthenticated healthz
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}
			// Prefer bearer if set
			if tok := strings.TrimSpace(a.BearerToken); tok != "" {
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "Bearer ") {
					unauth(w)
					return
				}
				got := strings.TrimPrefix(auth, "Bearer ")
				if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
					unauth(w)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Basic auth fallback
			user, pass, ok := r.BasicAuth()
			if !ok || a.Basic == nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="hecate-admin"`)
				unauth(w)
				return
			}
			if subtle.ConstantTimeCompare([]byte(user), []byte(a.Basic.Username)) != 1 ||
				subtle.ConstantTimeCompare([]byte(pass), []byte(a.Basic.Password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="hecate-admin"`)
				unauth(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func unauth(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
