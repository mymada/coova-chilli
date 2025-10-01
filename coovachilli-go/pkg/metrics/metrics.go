// Package metrics provides a standard interface for instrumenting the application.
// This allows for different backend implementations (e.g., Prometheus, InfluxDB)
// to be plugged in without changing the application's instrumentation points.
package metrics

import "net/http"

// Labels represents a collection of labels (key-value pairs) for a metric.
type Labels map[string]string

// Recorder defines the standard interface for recording application metrics.
// Each method takes a name, a set of labels, and a value.
type Recorder interface {
	// IncCounter increments a counter by 1.
	IncCounter(name string, labels Labels)

	// AddToCounter adds a float64 value to a counter.
	AddToCounter(name string, labels Labels, value float64)

	// SetGauge sets the value of a gauge.
	SetGauge(name string, labels Labels, value float64)

	// IncGauge increments a gauge by 1.
	IncGauge(name string, labels Labels)

	// DecGauge decrements a gauge by 1.
	DecGauge(name string, labels Labels)

	// ObserveHistogram records a new observation for a histogram.
	ObserveHistogram(name string, labels Labels, value float64)

	// Handler returns an http.Handler that can be used to expose the metrics
	// for scraping, if the backend supports it. Returns nil if not supported.
	Handler() http.Handler
}

// noopRecorder is an implementation of Recorder that does nothing.
// It is used when metrics are disabled to avoid nil checks.
type noopRecorder struct{}

// NewNoopRecorder returns a new no-op recorder.
func NewNoopRecorder() Recorder {
	return &noopRecorder{}
}

// IncCounter does nothing.
func (r *noopRecorder) IncCounter(name string, labels Labels) {}

// AddToCounter does nothing.
func (r *noopRecorder) AddToCounter(name string, labels Labels, value float64) {}

// SetGauge does nothing.
func (r *noopRecorder) SetGauge(name string, labels Labels, value float64) {}

// IncGauge does nothing.
func (r *noopRecorder) IncGauge(name string, labels Labels) {}

// DecGauge does nothing.
func (r *noopRecorder) DecGauge(name string, labels Labels) {}

// ObserveHistogram does nothing.
func (r *noopRecorder) ObserveHistogram(name string, labels Labels, value float64) {}

// Handler returns nil.
func (r *noopRecorder) Handler() http.Handler {
	return nil
}