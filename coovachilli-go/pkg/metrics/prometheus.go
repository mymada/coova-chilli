// Package metrics provides a standard interface for instrumenting the application.
package metrics

import (
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusRecorder is an implementation of Recorder that uses the Prometheus client library.
type PrometheusRecorder struct {
	mu         sync.RWMutex
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec
	registry   *prometheus.Registry
}

// NewPrometheusRecorder creates a new Prometheus recorder.
func NewPrometheusRecorder() Recorder {
	return &PrometheusRecorder{
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		registry:   prometheus.NewRegistry(),
	}
}

// metricKey generates a consistent key for a metric based on its name and label keys.
func metricKey(name string, labels Labels) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return name + ";" + strings.Join(keys, ",")
}

// IncCounter increments a counter by 1.
func (r *PrometheusRecorder) IncCounter(name string, labels Labels) {
	r.getCounter(name, labels).With(prometheus.Labels(labels)).Inc()
}

// AddToCounter adds a float64 value to a counter.
func (r *PrometheusRecorder) AddToCounter(name string, labels Labels, value float64) {
	r.getCounter(name, labels).With(prometheus.Labels(labels)).Add(value)
}

// SetGauge sets the value of a gauge.
func (r *PrometheusRecorder) SetGauge(name string, labels Labels, value float64) {
	r.getGauge(name, labels).With(prometheus.Labels(labels)).Set(value)
}

// IncGauge increments a gauge by 1.
func (r *PrometheusRecorder) IncGauge(name string, labels Labels) {
	r.getGauge(name, labels).With(prometheus.Labels(labels)).Inc()
}

// DecGauge decrements a gauge by 1.
func (r *PrometheusRecorder) DecGauge(name string, labels Labels) {
	r.getGauge(name, labels).With(prometheus.Labels(labels)).Dec()
}

// ObserveHistogram records a new observation for a histogram.
func (r *PrometheusRecorder) ObserveHistogram(name string, labels Labels, value float64) {
	r.getHistogram(name, labels).With(prometheus.Labels(labels)).Observe(value)
}

// Handler returns an http.Handler that can be used to expose the metrics.
func (r *PrometheusRecorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// getCounter finds or creates a counter vector.
func (r *PrometheusRecorder) getCounter(name string, labels Labels) *prometheus.CounterVec {
	key := metricKey(name, labels)
	r.mu.RLock()
	c, ok := r.counters[key]
	r.mu.RUnlock()
	if ok {
		return c
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Double-check in case it was created while waiting for the lock.
	if c, ok := r.counters[key]; ok {
		return c
	}

	labelKeys := make([]string, 0, len(labels))
	for k := range labels {
		labelKeys = append(labelKeys, k)
	}

	c = prometheus.NewCounterVec(prometheus.CounterOpts{Name: name}, labelKeys)
	r.registry.MustRegister(c)
	r.counters[key] = c
	return c
}

// getGauge finds or creates a gauge vector.
func (r *PrometheusRecorder) getGauge(name string, labels Labels) *prometheus.GaugeVec {
	key := metricKey(name, labels)
	r.mu.RLock()
	g, ok := r.gauges[key]
	r.mu.RUnlock()
	if ok {
		return g
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[key]; ok {
		return g
	}

	labelKeys := make([]string, 0, len(labels))
	for k := range labels {
		labelKeys = append(labelKeys, k)
	}

	g = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name}, labelKeys)
	r.registry.MustRegister(g)
	r.gauges[key] = g
	return g
}

// getHistogram finds or creates a histogram vector.
func (r *PrometheusRecorder) getHistogram(name string, labels Labels) *prometheus.HistogramVec {
	key := metricKey(name, labels)
	r.mu.RLock()
	h, ok := r.histograms[key]
	r.mu.RUnlock()
	if ok {
		return h
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[key]; ok {
		return h
	}

	labelKeys := make([]string, 0, len(labels))
	for k := range labels {
		labelKeys = append(labelKeys, k)
	}

	h = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name}, labelKeys)
	r.registry.MustRegister(h)
	r.histograms[key] = h
	return h
}