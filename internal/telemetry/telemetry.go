package telemetry

import (
	"context"
	"os"
	"time"

	"github.com/arencloud/hecate/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type ShutdownFunc func(ctx context.Context) error

var (
	meter          metric.Meter
	httpReqs       metric.Int64Counter
	httpDurMs      metric.Float64Histogram
	retriesCounter metric.Int64Counter
	breakerEvents  metric.Int64Counter
	policyHits     metric.Int64Counter
	policyMisses   metric.Int64Counter
	cacheHits      metric.Int64Counter
	cacheMisses    metric.Int64Counter
	commonAttrs    []attribute.KeyValue
)

func InitProvider(t *config.Telemetry) (ShutdownFunc, error) {
	// Resources
	res, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(defaultIfEmpty(t.ServiceName, "hecate")),
			attribute.String("service.instance.id", hostnameOr("unknown")),
		),
	)

	// Traces
	var tp *sdktrace.TracerProvider
	{
		var exp sdktrace.SpanExporter
		var err error
		if t != nil && t.OTLPEndpoint != "" {
			exp, err = newTraceExporter(t)
			if err != nil {
				return func(ctx context.Context) error { return nil }, err
			}
		}
		if exp == nil {
			tp = sdktrace.NewTracerProvider(
				sdktrace.WithResource(res),
				sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingOr(t, 0.1)))),
			)
		} else {
			tp = sdktrace.NewTracerProvider(
				sdktrace.WithBatcher(exp),
				sdktrace.WithResource(res),
				sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingOr(t, 0.1)))),
			)
		}
		otel.SetTracerProvider(tp)
	}

	// Metrics
	var mp *sdkmetric.MeterProvider
	if t != nil && t.OTLPEndpoint != "" {
		mexp, err := newMetricExporter(t)
		if err != nil {
			return tp.Shutdown, err
		}
		reader := sdkmetric.NewPeriodicReader(mexp, sdkmetric.WithInterval(10*time.Second))
		mp = sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(reader),
			sdkmetric.WithResource(res),
		)
	} else {
		// No OTLP endpoint: use an SDK MeterProvider without readers/exporters (no-op sink)
		mp = sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
		)
	}
	otel.SetMeterProvider(mp)

	// Instruments
	meter = otel.Meter("hecate")
	httpReqs, _ = meter.Int64Counter("http_server_requests_total")
	httpDurMs, _ = meter.Float64Histogram("http_server_duration_ms")
	retriesCounter, _ = meter.Int64Counter("hecate_retries_total")
	breakerEvents, _ = meter.Int64Counter("hecate_breaker_events_total")
	policyHits, _ = meter.Int64Counter("hecate_policy_hits_total")
	policyMisses, _ = meter.Int64Counter("hecate_policy_misses_total")
	cacheHits, _ = meter.Int64Counter("hecate_policy_cache_hits_total")
	cacheMisses, _ = meter.Int64Counter("hecate_policy_cache_misses_total")

	commonAttrs = []attribute.KeyValue{}

	return func(ctx context.Context) error {
		_ = tp.Shutdown(ctx)
		return mp.Shutdown(ctx)
	}, nil
}

func newTraceExporter(t *config.Telemetry) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(t.OTLPEndpoint),
	}
	if t.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(t.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(t.Headers))
	}
	return otlptracehttp.New(context.Background(), opts...)
}

func newMetricExporter(t *config.Telemetry) (*otlpmetrichttp.Exporter, error) {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(t.OTLPEndpoint),
	}
	if t.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(t.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(t.Headers))
	}
	return otlpmetrichttp.New(context.Background(), opts...)
}

func samplingOr(t *config.Telemetry, def float64) float64 {
	if t == nil || t.Sampling <= 0 {
		return def
	}
	if t.Sampling > 1 {
		return 1
	}
	return t.Sampling
}

func clampRatio(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func hostnameOr(def string) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return def
	}
	return h
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// split to help testing
var osHostname = func() (string, error) { return osHost() }

func osHost() (string, error) {
	return osHostnameImpl()
}

func osHostnameImpl() (string, error) {
	return os.Hostname()
}

// RecordHTTPServer records server-side RED metrics.
func RecordHTTPServer(ctx context.Context, method, host, path string, status int, dur time.Duration) {
	if httpReqs != nil {
		httpReqs.Add(ctx, 1, metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("host", host),
			attribute.String("status_class", statusClass(status)),
		))
	}
	if httpDurMs != nil {
		httpDurMs.Record(ctx, float64(dur.Milliseconds()), metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("host", host),
			attribute.String("path", path),
			attribute.String("status_class", statusClass(status)),
		))
	}
}

func statusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// IncRetry increments retry count for an upstream.
func IncRetry(ctx context.Context, upstream string) {
	if retriesCounter != nil {
		retriesCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("upstream", upstream)))
	}
}

// BreakerEvent records breaker transitions: open, close, half_open.
func BreakerEvent(upstream, event string) {
	if breakerEvents != nil {
		breakerEvents.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("upstream", upstream),
			attribute.String("event", event),
		))
	}
}

// PolicyHit increments policy hit counter (a rule matched and enforced).
func PolicyHit(kind string) {
	if policyHits != nil {
		policyHits.Add(context.Background(), 1, metric.WithAttributes(attribute.String("kind", kind)))
	}
}

// PolicyMiss increments policy miss counter (no rule matched or DB unavailable).
func PolicyMiss(kind string) {
	if policyMisses != nil {
		policyMisses.Add(context.Background(), 1, metric.WithAttributes(attribute.String("kind", kind)))
	}
}

// PolicyHitLabels adds route and bucket labels.
func PolicyHitLabels(kind, route, bucket string) {
	if policyHits != nil {
		opts := []attribute.KeyValue{attribute.String("kind", kind)}
		if route != "" {
			opts = append(opts, attribute.String("route", route))
		}
		if bucket != "" {
			opts = append(opts, attribute.String("bucket", bucket))
		}
		policyHits.Add(context.Background(), 1, metric.WithAttributes(opts...))
	}
}

// CacheHit increments cache hit metrics for policy caches.
func CacheHit(kind string) {
	if cacheHits != nil {
		cacheHits.Add(context.Background(), 1, metric.WithAttributes(attribute.String("kind", kind)))
	}
}

// CacheMiss increments cache miss metrics for policy caches.
func CacheMiss(kind string) {
	if cacheMisses != nil {
		cacheMisses.Add(context.Background(), 1, metric.WithAttributes(attribute.String("kind", kind)))
	}
}
