How to run
- Generate or place TLS certs under config/ (or remove tls section for HTTP):
- Run: go run ./cmd/hecate -config=config/example.yaml
- Admin endpoints:
    - [http://localhost:9000/healthz](http://localhost:9000/healthz)
    - [http://localhost:9000/debug/vars](http://localhost:9000/debug/vars)
    - [http://localhost:9000/debug/pprof/](http://localhost:9000/debug/pprof/)

What’s included vs. placeholders
- Included: L7 reverse proxy (HTTP/1.1 + upstream HTTP/2), host/path routing, round‑robin, active health checks with outlier ejection, TLS 1.3 termination, simple rate limit, structured logs, pprof/expvar.
- Not yet implemented (scaffold next):
    - HTTP/3/QUIC and gRPC: add golang.org/x/net/http3 listener; ensure h2c support for clear‑text gRPC if desired.
    - Retries with backoff/jitter, circuit breakers, outlier detection via EWMA, load‑balancing algorithms (least‑x, maglev/consistent hashing).
    - Sticky sessions; cookie or header affinity.
    - WAF/bot defense/DDoS: pluggable middleware chain; start with IP/Geo/ASN ACLs and token bucket per key.
    - Auth: OIDC/JWT validation, mTLS device identity.
    - OpenTelemetry: traces/metrics/logs exporters; RED/USE dashboards.
    - Service discovery: Kubernetes EndpointSlice, Consul, cloud registries.
    - GLB: DNS steering, multi‑region health from multiple vantage points, weighted/latency/cost routing; HTTP proxy steering fallback.
    - Edge agent: local policy cache, OTA updates, buffered telemetry, offline tolerance.

Next steps (suggested order)
1. Add retries + backoff and timeouts (transport wrapper).
2. Add consistent hashing LB and stickiness options.
3. Introduce middleware chain with policy engine (WASM/Lua hooks later).
4. Integrate OpenTelemetry SDK for traces/metrics.
5. Implement HTTP/3 listener; test gRPC and WebSockets.
6. Add discovery backends (K8s, Consul).
7. Add GLB control plane skeleton and DNS/Anycast integration.
8. Harden security (mTLS upstreams, WAF module, rate limiting per identity).

If you’d like, I can follow up with:
- HTTP/3 + gRPC enablement
- Retry/circuit breaker transport wrapper
- A minimal GLB control-plane interface and a DNS health‑aware steering stub
