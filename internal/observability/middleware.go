package observability

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/arencloud/hecate/internal/telemetry"
)

func RequestLogger(next http.Handler) http.Handler {
	log := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lrw, r)
		dur := time.Since(start)

		// Logs
		log.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"host", r.Host,
			"status", lrw.status,
			"size", lrw.size,
			"dur_ms", strconv.FormatInt(dur.Milliseconds(), 10),
			"ua", r.UserAgent(),
			"remote", r.RemoteAddr,
		)

		// Metrics (RED)
		telemetry.RecordHTTPServer(r.Context(), r.Method, r.Host, r.URL.Path, lrw.status, dur)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	size   int64
}

func (l *loggingResponseWriter) WriteHeader(code int) {
	l.status = code
	l.ResponseWriter.WriteHeader(code)
}

func (l *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := l.ResponseWriter.Write(b)
	l.size += int64(n)
	return n, err
}
