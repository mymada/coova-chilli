package config

import (
	"github.com/rs/zerolog"
	"reflect"
	"sync"
)

// Reconfigurable defines the interface for components that can be reconfigured at runtime.
type Reconfigurable interface {
	// Reconfigure applies a new configuration to the component.
	// It should return an error if the new configuration is invalid or cannot be applied.
	Reconfigure(newConfig *Config) error
}

// Reloader manages the process of reloading configuration for registered components.
type Reloader struct {
	mu           sync.Mutex
	components   []Reconfigurable
	configPath   string
	logger       zerolog.Logger
}

// NewReloader creates a new Reloader.
func NewReloader(configPath string, logger zerolog.Logger) *Reloader {
	return &Reloader{
		configPath: configPath,
		logger:     logger.With().Str("component", "reloader").Logger(),
	}
}

// Register adds a component to the list of components to be reconfigured on reload.
func (r *Reloader) Register(c Reconfigurable) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.components = append(r.components, c)
}

// PerformReload loads the configuration from disk and applies it to all registered components.
func (r *Reloader) PerformReload() {
	r.logger.Info().Msg("Starting configuration reload from file...")

	newConfig, err := Load(r.configPath)
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to load new configuration file. Aborting reload.")
		return
	}

	r.ReloadWithConfig(newConfig)
}

// ReloadWithConfig applies a new configuration object to all registered components.
func (r *Reloader) ReloadWithConfig(newConfig *Config) {
	r.logger.Info().Msg("Applying new configuration to all components...")
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, component := range r.components {
		componentName := reflect.TypeOf(component).Elem().Name()
		if err := component.Reconfigure(newConfig); err != nil {
			r.logger.Error().Err(err).Str("component", componentName).Msg("Failed to reconfigure component.")
		} else {
			r.logger.Info().Str("component", componentName).Msg("Component reconfigured successfully.")
		}
	}
	r.logger.Info().Msg("Configuration reload complete.")
}