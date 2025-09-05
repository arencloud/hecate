package main

import (
	"context"
	"expvar"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arencloud/hecate/internal/config"
	"github.com/arencloud/hecate/internal/observability"
	"github.com/arencloud/hecate/internal/proxy"
	"github.com/arencloud/hecate/internal/security"
	"github.com/arencloud/hecate/internal/telemetry"
	"github.com/arencloud/hecate/pkg/policy"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type switchableHandler struct {
	h atomic.Value // stores http.Handler
}

func (s *switchableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := s.h.Load()
	if h == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	h.(http.Handler).ServeHTTP(w, r)
}
func (s *switchableHandler) Set(h http.Handler) { s.h.Store(h) }

func main() {
	cfgPath := flag.String("config", "config/example.yaml", "Path to YAML config")
	flag.Parse()

	// Structured logger (slog)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	loadCfg := func() (*config.Config, error) { return config.Load(*cfgPath) }

	cfg, err := loadCfg()
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Telemetry init
	otelShutdown, err := telemetry.InitProvider(cfg.Telemetry)
	if err != nil {
		logger.Error("failed to init telemetry", "err", err)
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Error("telemetry shutdown error", "err", err)
		}
	}()

	// Build L7 proxy and initial handler
	buildPipeline := func(c *config.Config) (*proxy.L7, http.Handler, error) {
		l7, err := proxy.NewL7(logger, c)
		if err != nil {
			return nil, nil, err
		}
		var handler http.Handler = l7
		handler = policy.BuildChain(logger, c, handler)
		handler = observability.RequestLogger(handler)
		return l7, handler, nil
	}

	l7, handler, err := buildPipeline(cfg)
	if err != nil {
		logger.Error("failed to create proxy", "err", err)
		os.Exit(1)
	}

	// Switchable handler wrapper for hot swap
	sw := &switchableHandler{}
	sw.Set(handler)

	// Observability (expvar, pprof, basic health) + admin control
	adminMux := http.NewServeMux()
	attachAdminEndpoints(adminMux, l7, func() error {
		// close previous policy resources
		policy.Shutdown()
		newCfg, err := loadCfg()
		if err != nil {
			return err
		}
		newL7, newHandler, err := buildPipeline(newCfg)
		if err != nil {
			return err
		}
		sw.Set(newHandler)
		*l7 = *newL7
		cfg = newCfg
		logger.Info("config reloaded")
		return nil
	})
	// Use http.Handler here (not *http.ServeMux)
	var adminHandler http.Handler = adminMux
	if cfg.Admin.Auth != nil {
		adminHandler = security.AdminAuthMiddleware(cfg.Admin.Auth)(adminMux)
	}
	// Keep request logging on admin endpoints
	adminWrapped := observability.RequestLogger(adminHandler)
	adminSrv := &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           adminWrapped,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("admin server starting", "addr", cfg.Admin.Listen)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server exited", "err", err)
		}
	}()

	// TLS config for public listener
	tlsCfg, err := security.BuildServerTLS(cfg.TLS)
	if err != nil {
		logger.Error("failed to build TLS config", "err", err)
		os.Exit(1)
	}

	// Public server with configurable timeouts
	publicSrv := &http.Server{
		Addr:              cfg.Proxy.Listen,
		Handler:           sw,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: time.Duration(cfg.Proxy.Server.ReadHeaderTimeoutSec) * time.Second,
		IdleTimeout:       time.Duration(cfg.Proxy.Server.IdleTimeoutSec) * time.Second,
		MaxHeaderBytes:    cfg.Proxy.Server.MaxHeaderBytes,
	}
	if cfg.Proxy.Server.ReadTimeoutSec > 0 {
		publicSrv.ReadTimeout = time.Duration(cfg.Proxy.Server.ReadTimeoutSec) * time.Second
	}
	if cfg.Proxy.Server.WriteTimeoutSec > 0 {
		publicSrv.WriteTimeout = time.Duration(cfg.Proxy.Server.WriteTimeoutSec) * time.Second
	}

	// h2c support if TLS disabled and enabled by config
	if (tlsCfg == nil || len(tlsCfg.Certificates) == 0) && cfg.Proxy.EnableH2C {
		publicSrv.Handler = h2c.NewHandler(sw, &http2.Server{})
	}

	// Start listeners
	errCh := make(chan error, 3)
	go func() {
		logger.Info("public listener starting", "addr", cfg.Proxy.Listen)
		ln, lerr := net.Listen("tcp", cfg.Proxy.Listen)
		if lerr != nil {
			errCh <- lerr
			return
		}
		// HTTPS/TLS (and optionally HTTP/3)
		if tlsCfg != nil && len(tlsCfg.Certificates) > 0 {
			go func() { errCh <- publicSrv.ServeTLS(ln, "", "") }()
			// Optional HTTP/3 on separate port if provided, else same as TLS port
			if cfg.Proxy.EnableHTTP3 && len(cfg.TLS.CertFiles) > 0 && len(cfg.TLS.KeyFiles) > 0 {
				certFile := cfg.TLS.CertFiles[0]
				keyFile := cfg.TLS.KeyFiles[0]
				h3Addr := cfg.Proxy.HTTP3Listen
				if h3Addr == "" {
					h3Addr = cfg.Proxy.Listen
				}
				go func() {
					logger.Info("HTTP/3 listener starting", "addr", h3Addr)
					errCh <- http3.ListenAndServeTLS(h3Addr, certFile, keyFile, sw)
				}()
			}
			return
		}
		// Plain HTTP (possibly h2c)
		errCh <- publicSrv.Serve(ln)
	}()

	// Graceful shutdown and hot reload via SIGHUP
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	// On termination, also close policy resources
	defer policy.Shutdown()

loop:
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown signal")
			break loop
		case e := <-errCh:
			logger.Error("listener error", "err", e)
			break loop
		case sig := <-signalChan(syscall.SIGHUP):
			_ = sig // already handled by NotifyContext; this case is for clarity
		}
	}

	shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = publicSrv.Shutdown(shCtx)
	_ = adminSrv.Shutdown(shCtx)
	logger.Info("shutdown complete")
}

func signalChan(sig os.Signal) <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig)
	return ch
}

// pprof and expvar endpoints
func attachAdminEndpoints(mux *http.ServeMux, l7 *proxy.L7, reload func() error) {
	// pprof
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// expvar
	mux.Handle("/debug/vars", expvar.Handler())

	// basic liveness
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Graceful drain controls
	mux.HandleFunc("/admin/drain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		l7.SetDraining(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("draining enabled"))
	})
	mux.HandleFunc("/admin/undrain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		l7.SetDraining(false)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("draining disabled"))
	})

	// Hot reload endpoint
	mux.HandleFunc("/admin/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := reload(); err != nil {
			http.Error(w, "reload failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reloaded"))
	})
}
