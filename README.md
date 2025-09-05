<div align="center">
  <img src="img/logo.png" alt="Hecate Logo" width="140" />
  <h1>Hecate</h1>
  <p>A modern, observable L7 HTTP(S) reverse proxy with policy, retries, circuit‑breaking, rate limits, and HTTP/3.</p>
  
  <!-- Badges -->
  <p>
    <a href="https://go.dev/" title="Go"><img alt="Go Version" src="https://img.shields.io/badge/Go-%3E%3D1.24-00ADD8?logo=go"/></a>
    <a href="LICENSE" title="License"><img alt="License" src="https://img.shields.io/badge/License-MIT-yellow.svg"/></a>
    <a href="#getting-started" title="Get Started"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen"/></a>
  </p>
</div>

---

- ⚡ Fast reverse proxy with routing by host and path prefix
- 🔒 TLS termination, optional HTTP/3 (QUIC), and h2c support
- ♻️ Retries with backoff, circuit breaker, and health checking
- 🎯 Sticky sessions and consistent hashing load balancing
- 🛡️ Per‑route and global policies (IP ACL, rate limit, auth)
- 🛠️ Admin server with pprof, expvar, health, drain/reload controls
- 📊 First‑class observability: structured logs, Prometheus, OpenTelemetry traces


Table of Contents
- Overview
- Quick links
- Features
- Architecture at a glance
- Getting started
  - Prerequisites
  - Option A: Run locally
  - Option B: Docker Compose observability stack
- Configuration
- Admin API and operations
- Security notes
- Observability
- Development
- FAQ
- License


Quick links
- Example config: config/example.yaml
- Docker Compose stack: docker-compose.yml
- Make targets: Makefile
- License: see LICENSE


Overview
Hecate is a single binary reverse proxy written in Go. It listens on a public address for HTTP/HTTPS traffic and forwards requests to configured upstreams. It also exposes an admin server for health, debugging, and runtime operations like config reload and drain mode. Telemetry is built‑in via OpenTelemetry and Prometheus so you can see spans, metrics, and logs right away.

> Note: This README uses self‑contained examples you can copy/paste. See docker-compose.yml and config/example.yaml for a turnkey demo stack.


Features
- Protocols
  - HTTP/1.1 and HTTP/2 upstreams (ForceAttemptHTTP2)
  - Optional HTTP/3 (QUIC) on a separate UDP/TCP port when TLS is enabled
  - Optional h2c clear‑text on public listener when TLS is disabled
- Routing and load balancing
  - Match by Host and Path Prefix per route
  - Round‑robin (default) and consistent hashing
  - Stickiness via cookie or header with TTL
- Resilience
  - Configurable retries with exponential backoff
  - Circuit breaker with open/half‑open states
  - Active health checks and outlier ejection thresholds
- Policies and security
  - Global and per‑route rate limits (token bucket)
  - IP ACL allow/deny lists
  - Public route auth (Basic or Bearer)
  - Admin API auth (Basic or Bearer)
  - TLS termination with optional mTLS
- Observability
  - Structured JSON logging (slog)
  - /debug/pprof and /debug/vars (expvar) on admin server
  - Prometheus metrics via Otel Collector config provided
  - Tracing via OTLP (HTTP or gRPC) to Tempo/Jaeger/etc.
- Operations
  - Hot reload on SIGHUP and via admin endpoint
  - Graceful drain mode
  - Configurable server timeouts and safety caps


Architecture at a glance
- cmd/hecate/main.go initializes config, telemetry, proxy pipeline, and servers.
- internal/proxy implements routing, LB, health checks, retries, CB, and request handling.
- pkg/policy provides policy chain (rate limit, ip ACL, geo/asn options, etc.).
- internal/security contains TLS helpers and auth middleware for admin/public.
- internal/observability and internal/telemetry add logs, metrics, and traces.


Getting started
Prerequisites
- Go 1.24+
- Podman or Docker (optional, for containerized quick start)

Option A: Run locally
1. Build and run with the example config (generates a self‑signed cert on first run):
   
   ```bash
   make run
   ```
2. Send a request (self‑signed TLS; ignoring cert) routed by Host header:
   
   ```bash
   curl -sk -H "Host: api.example.com" https://127.0.0.1:9443/
   ```
3. Admin server endpoints (auth configured in example.yaml):
   - Health:            http://127.0.0.1:9000/healthz
   - Expvar (401 w/o auth): http://127.0.0.1:9000/debug/vars
   - Pprof index:       http://127.0.0.1:9000/debug/pprof/

Option B: Docker Compose observability stack
This brings up Hecate, two sample upstreams, an OpenTelemetry Collector, Prometheus, Tempo, and Grafana.
1. Build image and start stack:
   
   ```bash
   make up
   ```
2. Quick checks:
   
   ```bash
   make curl
   ```
3. Explore telemetry:
   - Prometheus: http://localhost:9090
   - Tempo API:  http://localhost:3200
   - Grafana:    http://localhost:3000 (admin/admin)
4. Stop and clean:
   
   ```bash
   make down
   ```


Configuration
Edit config/example.yaml or point Hecate to your own file with -config.
Top‑level sections:
- admin
  - listen: ":9000"
  - auth: { basic: { username, password } | bearerToken }
- proxy
  - listen: public listener (e.g., ":8443")
  - http3Listen: UDP/TCP for HTTP/3 (e.g., ":8444")
  - enableHTTP3, enableH2C, enableUpstreamH2C
  - limits: rps, burst, headerBytesCap, bodyBytesCap, clientIPHeader
  - health: intervalSec, timeoutSec, failThreshold, successReset
  - routes: list of routes
    - name, hosts, pathPrefix, upstreams
    - lb: algorithm, hashKey
    - stickiness: enabled, mode(cookie|header), cookieName, ttlSeconds
    - policy: per‑route policy overrides (rateLimit, geoIp, asn)
    - auth: { basic | bearerToken } for public route protection
  - policy: global policy (ipAcl, rateLimit)
  - retry: maxRetries, perTryTimeoutSec, retryOn5xx, retryOnConnectErr, retryIdempotent, backoffBaseMs, backoffMaxMs
  - circuitBreaker: openAfterConsecutiveFailures, cooldownSec, halfOpenMaxRequests
  - server: read/write/idle timeouts, maxHeaderBytes
- tls
  - certFiles, keyFiles, optional clientCAFile, requireClientCert
- telemetry
  - serviceName, otlpEndpoint, insecure, sampling

Run with a specific config file:

```bash
./hecate -config=config/example.yaml
```


Admin API and operations
- Health:      GET /healthz
- Drain mode:  PUT /admin/drain on|off
- Hot reload:  POST /admin/reload (or send SIGHUP to process)
- Debug:       /debug/pprof, /debug/vars (expvar)
Admin server address and auth are set in admin section of the config. Admin endpoints are also wrapped with request logging.


Security notes
- The example uses self‑signed certificates; generate your own for production.
- Enable mTLS by setting tls.clientCAFile and tls.requireClientCert.
- Protect admin endpoints with Basic or Bearer auth (see config example).
- Set reasonable limits and timeouts to protect the proxy and upstreams.


Observability
- Logs: JSON structured logs via slog to stdout.
- Traces: configure telemetry.otlpEndpoint to your collector (OTLP/HTTP default in example). Sampling rate can be tuned.
- Metrics: provided via Otel Collector config (config/otel-collector.yaml) and scraped by Prometheus (config/prometheus.yml). Tempo and Grafana compose services are included for a turnkey demo.


Development
- Format, vet, test:
  
  ```bash
  make fmt vet test
  ```
- Run in HTTP (no TLS): either remove the tls section in config or ignore TLS in clients. h2c can be enabled with proxy.enableH2C.
- Build binary:
  
  ```bash
  make build
  ```
- Build container image:
  
  ```bash
  make image
  ```
- End‑to‑end smoke:
  
  ```bash
  make smoke
  ```


FAQ
- How do I enable HTTP/3?
  - Ensure tls.certFiles/keyFiles are set and proxy.enableHTTP3: true. Optional proxy.http3Listen can set a dedicated port.
- How do I reload configuration without downtime?
  - Send SIGHUP or call the admin reload endpoint. The server hot‑swaps the handler and preserves listeners.
- Can I use consistent hashing per client?
  - Set route.lb.algorithm to consistent_hash and specify lb.hashKey with a header or cookie name. Falls back to client IP if absent.


License
This project is licensed under the terms of the LICENSE file included in this repository.

---

If you find Hecate useful, consider giving it a ⭐ to help others discover it.
