package performance

import (
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// PoolConfig holds connection pool configuration
type PoolConfig struct {
	Enabled         bool          `yaml:"enabled" envconfig:"POOL_ENABLED"`
	MinConnections  int           `yaml:"min_connections" envconfig:"POOL_MIN_CONNECTIONS"`
	MaxConnections  int           `yaml:"max_connections" envconfig:"POOL_MAX_CONNECTIONS"`
	MaxIdleTime     time.Duration `yaml:"max_idle_time" envconfig:"POOL_MAX_IDLE_TIME"`
	MaxLifetime     time.Duration `yaml:"max_lifetime" envconfig:"POOL_MAX_LIFETIME"`
	AcquireTimeout  time.Duration `yaml:"acquire_timeout" envconfig:"POOL_ACQUIRE_TIMEOUT"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" envconfig:"POOL_HEALTH_CHECK_INTERVAL"`
}

// Connection represents a pooled connection
type Connection interface {
	Close() error
	IsAlive() bool
	Reset() error
}

// ConnectionFactory creates new connections
type ConnectionFactory func() (Connection, error)

// ConnectionPool provides a thread-safe connection pool
type ConnectionPool struct {
	factory             ConnectionFactory
	config              *PoolConfig
	logger              zerolog.Logger
	mu                  sync.Mutex
	cond                *sync.Cond
	connections         []*pooledConnection
	activeConnections   int
	totalConnections    int
	closed              bool
	stats               PoolStats
}

// pooledConnection wraps a connection with metadata
type pooledConnection struct {
	conn       Connection
	createdAt  time.Time
	lastUsedAt time.Time
	usageCount uint64
	inUse      bool
}

// PoolStats tracks pool statistics
type PoolStats struct {
	ActiveConnections int
	IdleConnections   int
	TotalConnections  int
	WaitCount         uint64
	WaitDuration      time.Duration
	MaxWaitDuration   time.Duration
	ConnectionsCreated uint64
	ConnectionsClosed  uint64
	Errors            uint64
}

var (
	ErrPoolClosed        = errors.New("connection pool is closed")
	ErrAcquireTimeout    = errors.New("timeout acquiring connection from pool")
	ErrMaxConnections    = errors.New("maximum connections reached")
)

// NewConnectionPool creates a new connection pool
func NewConnectionPool(factory ConnectionFactory, config *PoolConfig, logger zerolog.Logger) (*ConnectionPool, error) {
	if !config.Enabled {
		return nil, errors.New("connection pool is not enabled")
	}

	// Set defaults
	if config.MinConnections == 0 {
		config.MinConnections = 2
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 20
	}
	if config.MaxIdleTime == 0 {
		config.MaxIdleTime = 10 * time.Minute
	}
	if config.MaxLifetime == 0 {
		config.MaxLifetime = 1 * time.Hour
	}
	if config.AcquireTimeout == 0 {
		config.AcquireTimeout = 30 * time.Second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 1 * time.Minute
	}

	pool := &ConnectionPool{
		factory:     factory,
		config:      config,
		logger:      logger.With().Str("component", "connection-pool").Logger(),
		connections: make([]*pooledConnection, 0, config.MaxConnections),
	}

	pool.cond = sync.NewCond(&pool.mu)

	// Create minimum connections
	for i := 0; i < config.MinConnections; i++ {
		if err := pool.createConnection(); err != nil {
			pool.logger.Error().Err(err).Msg("Failed to create initial connection")
			// Continue even if some fail
		}
	}

	// Start maintenance goroutines
	go pool.healthCheck()
	go pool.reaper()

	pool.logger.Info().
		Int("min", config.MinConnections).
		Int("max", config.MaxConnections).
		Msg("Connection pool initialized")

	return pool, nil
}

// Acquire gets a connection from the pool
func (p *ConnectionPool) Acquire() (Connection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPoolClosed
	}

	startTime := time.Now()
	timeout := time.After(p.config.AcquireTimeout)

	for {
		// Try to find an available connection
		for _, pc := range p.connections {
			if !pc.inUse && pc.conn.IsAlive() {
				pc.inUse = true
				pc.lastUsedAt = time.Now()
				pc.usageCount++
				p.activeConnections++
				p.stats.ActiveConnections = p.activeConnections
				return pc.conn, nil
			}
		}

		// Try to create a new connection if below max
		if p.totalConnections < p.config.MaxConnections {
			if err := p.createConnectionLocked(); err == nil {
				// Get the newly created connection
				pc := p.connections[len(p.connections)-1]
				pc.inUse = true
				pc.lastUsedAt = time.Now()
				pc.usageCount++
				p.activeConnections++
				p.stats.ActiveConnections = p.activeConnections
				return pc.conn, nil
			}
		}

		// Wait for a connection to become available
		p.stats.WaitCount++

		select {
		case <-timeout:
			waitDuration := time.Since(startTime)
			p.stats.WaitDuration += waitDuration
			if waitDuration > p.stats.MaxWaitDuration {
				p.stats.MaxWaitDuration = waitDuration
			}
			return nil, ErrAcquireTimeout
		default:
			p.cond.Wait()
		}

		if p.closed {
			return nil, ErrPoolClosed
		}
	}
}

// Release returns a connection to the pool
func (p *ConnectionPool) Release(conn Connection) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return conn.Close()
	}

	// Find the connection
	for _, pc := range p.connections {
		if pc.conn == conn {
			if !pc.inUse {
				// Connection already released
				return nil
			}

			// Reset connection state
			if err := conn.Reset(); err != nil {
				p.logger.Warn().Err(err).Msg("Failed to reset connection, closing it")
				p.removeConnection(pc)
				return err
			}

			pc.inUse = false
			pc.lastUsedAt = time.Now()
			p.activeConnections--
			p.stats.ActiveConnections = p.activeConnections

			// Notify waiting goroutines
			p.cond.Signal()
			return nil
		}
	}

	// Connection not found in pool, close it
	return conn.Close()
}

// createConnection creates a new connection (must be called with lock held)
func (p *ConnectionPool) createConnectionLocked() error {
	conn, err := p.factory()
	if err != nil {
		p.stats.Errors++
		return err
	}

	pc := &pooledConnection{
		conn:       conn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		usageCount: 0,
		inUse:      false,
	}

	p.connections = append(p.connections, pc)
	p.totalConnections++
	p.stats.TotalConnections = p.totalConnections
	p.stats.ConnectionsCreated++

	return nil
}

// createConnection creates a new connection (acquires lock)
func (p *ConnectionPool) createConnection() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.createConnectionLocked()
}

// removeConnection removes a connection from the pool (must be called with lock held)
func (p *ConnectionPool) removeConnection(pc *pooledConnection) {
	pc.conn.Close()

	// Find and remove from slice
	for i, c := range p.connections {
		if c == pc {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}

	if pc.inUse {
		p.activeConnections--
	}
	p.totalConnections--
	p.stats.TotalConnections = p.totalConnections
	p.stats.ConnectionsClosed++
}

// healthCheck periodically checks connection health
func (p *ConnectionPool) healthCheck() {
	ticker := time.NewTicker(p.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()

		if p.closed {
			p.mu.Unlock()
			return
		}

		unhealthy := 0
		for i := len(p.connections) - 1; i >= 0; i-- {
			pc := p.connections[i]

			// Skip connections in use
			if pc.inUse {
				continue
			}

			// Check if connection is alive
			if !pc.conn.IsAlive() {
				p.removeConnection(pc)
				unhealthy++
			}
		}

		p.mu.Unlock()

		if unhealthy > 0 {
			p.logger.Debug().
				Int("unhealthy", unhealthy).
				Msg("Removed unhealthy connections")
		}
	}
}

// reaper removes idle and old connections
func (p *ConnectionPool) reaper() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()

		if p.closed {
			p.mu.Unlock()
			return
		}

		now := time.Now()
		reaped := 0

		for i := len(p.connections) - 1; i >= 0; i-- {
			pc := p.connections[i]

			// Skip connections in use
			if pc.inUse {
				continue
			}

			// Keep minimum connections
			if p.totalConnections <= p.config.MinConnections {
				break
			}

			// Remove if idle too long
			if now.Sub(pc.lastUsedAt) > p.config.MaxIdleTime {
				p.removeConnection(pc)
				reaped++
				continue
			}

			// Remove if too old
			if now.Sub(pc.createdAt) > p.config.MaxLifetime {
				p.removeConnection(pc)
				reaped++
				continue
			}
		}

		p.mu.Unlock()

		if reaped > 0 {
			p.logger.Debug().
				Int("reaped", reaped).
				Msg("Reaped idle/old connections")
		}
	}
}

// GetStats returns pool statistics
func (p *ConnectionPool) GetStats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	stats := p.stats
	stats.ActiveConnections = p.activeConnections
	stats.IdleConnections = p.totalConnections - p.activeConnections
	stats.TotalConnections = p.totalConnections

	return stats
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true

	// Close all connections
	for _, pc := range p.connections {
		pc.conn.Close()
	}

	p.connections = nil
	p.totalConnections = 0
	p.activeConnections = 0

	// Wake up all waiting goroutines
	p.cond.Broadcast()

	p.logger.Info().Msg("Connection pool closed")

	return nil
}

// Size returns the current number of connections in the pool
func (p *ConnectionPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalConnections
}

// ActiveCount returns the number of active connections
func (p *ConnectionPool) ActiveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.activeConnections
}

// IdleCount returns the number of idle connections
func (p *ConnectionPool) IdleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalConnections - p.activeConnections
}
