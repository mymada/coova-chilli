package performance

import (
	"container/list"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// CacheConfig holds cache configuration
type CacheConfig struct {
	Enabled       bool          `yaml:"enabled" envconfig:"CACHE_ENABLED"`
	MaxEntries    int           `yaml:"max_entries" envconfig:"CACHE_MAX_ENTRIES"`
	DefaultTTL    time.Duration `yaml:"default_ttl" envconfig:"CACHE_DEFAULT_TTL"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" envconfig:"CACHE_CLEANUP_INTERVAL"`
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Key        string
	Value      interface{}
	ExpiresAt  time.Time
	AccessedAt time.Time
	HitCount   uint64
	element    *list.Element // For LRU
}

// Cache provides a thread-safe LRU cache with TTL
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]*CacheEntry
	lru        *list.List
	maxEntries int
	defaultTTL time.Duration
	logger     zerolog.Logger
	stats      CacheStats
}

// CacheStats tracks cache statistics
type CacheStats struct {
	Hits         uint64
	Misses       uint64
	Evictions    uint64
	Expirations  uint64
	Entries      int
	TotalSize    int64
}

// NewCache creates a new cache
func NewCache(config *CacheConfig, logger zerolog.Logger) *Cache {
	if !config.Enabled {
		return nil
	}

	// Set defaults
	if config.MaxEntries == 0 {
		config.MaxEntries = 10000
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 5 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}

	c := &Cache{
		entries:    make(map[string]*CacheEntry),
		lru:        list.New(),
		maxEntries: config.MaxEntries,
		defaultTTL: config.DefaultTTL,
		logger:     logger.With().Str("component", "cache").Logger(),
	}

	// Start cleanup goroutine
	go c.cleanupExpired(config.CleanupInterval)

	logger.Info().
		Int("max_entries", config.MaxEntries).
		Dur("default_ttl", config.DefaultTTL).
		Msg("Cache initialized")

	return c
}

// Get retrieves a value from cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		c.stats.Misses++
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.delete(key)
		c.stats.Expirations++
		c.mu.Unlock()
		c.mu.RLock()
		c.stats.Misses++
		return nil, false
	}

	// Update access time and hit count
	entry.AccessedAt = time.Now()
	entry.HitCount++

	// Move to front of LRU
	c.lru.MoveToFront(entry.element)

	c.stats.Hits++
	return entry.Value, true
}

// Set stores a value in cache with default TTL
func (c *Cache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, c.defaultTTL)
}

// SetWithTTL stores a value in cache with custom TTL
func (c *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Update existing entry
	if entry, exists := c.entries[key]; exists {
		entry.Value = value
		entry.ExpiresAt = now.Add(ttl)
		entry.AccessedAt = now
		c.lru.MoveToFront(entry.element)
		return
	}

	// Evict if at capacity
	if c.lru.Len() >= c.maxEntries {
		c.evictOldest()
	}

	// Create new entry
	entry := &CacheEntry{
		Key:        key,
		Value:      value,
		ExpiresAt:  now.Add(ttl),
		AccessedAt: now,
		HitCount:   0,
	}

	// Add to maps and LRU
	entry.element = c.lru.PushFront(entry)
	c.entries[key] = entry
	c.stats.Entries = len(c.entries)
}

// Delete removes a value from cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.delete(key)
}

// delete removes a value (must be called with lock held)
func (c *Cache) delete(key string) {
	if entry, exists := c.entries[key]; exists {
		c.lru.Remove(entry.element)
		delete(c.entries, key)
		c.stats.Entries = len(c.entries)
	}
}

// evictOldest removes the least recently used entry
func (c *Cache) evictOldest() {
	elem := c.lru.Back()
	if elem != nil {
		entry := elem.Value.(*CacheEntry)
		c.delete(entry.Key)
		c.stats.Evictions++
	}
}

// Clear removes all entries
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.lru.Init()
	c.stats.Entries = 0
}

// cleanupExpired periodically removes expired entries
func (c *Cache) cleanupExpired(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		expired := 0

		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				c.delete(key)
				expired++
			}
		}

		c.mu.Unlock()

		if expired > 0 {
			c.logger.Debug().
				Int("expired", expired).
				Msg("Cleaned up expired cache entries")
			c.stats.Expirations += uint64(expired)
		}
	}
}

// GetStats returns cache statistics
func (c *Cache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Entries = len(c.entries)

	return stats
}

// GetHitRate returns cache hit rate percentage
func (c *Cache) GetHitRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.stats.Hits + c.stats.Misses
	if total == 0 {
		return 0
	}

	return float64(c.stats.Hits) / float64(total) * 100
}

// GetSize returns number of entries in cache
func (c *Cache) GetSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Keys returns all keys in cache
func (c *Cache) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.entries))
	for key := range c.entries {
		keys = append(keys, key)
	}

	return keys
}

// MultiCache manages multiple named caches
type MultiCache struct {
	caches map[string]*Cache
	mu     sync.RWMutex
	logger zerolog.Logger
}

// NewMultiCache creates a new multi-cache manager
func NewMultiCache(logger zerolog.Logger) *MultiCache {
	return &MultiCache{
		caches: make(map[string]*Cache),
		logger: logger.With().Str("component", "multi-cache").Logger(),
	}
}

// GetCache returns a named cache, creating it if necessary
func (mc *MultiCache) GetCache(name string, config *CacheConfig) *Cache {
	mc.mu.RLock()
	cache, exists := mc.caches[name]
	mc.mu.RUnlock()

	if exists {
		return cache
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists := mc.caches[name]; exists {
		return cache
	}

	// Create new cache
	cache = NewCache(config, mc.logger.With().Str("cache", name).Logger())
	mc.caches[name] = cache

	mc.logger.Info().Str("cache", name).Msg("Created new cache")

	return cache
}

// GetAllStats returns statistics for all caches
func (mc *MultiCache) GetAllStats() map[string]CacheStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	stats := make(map[string]CacheStats)
	for name, cache := range mc.caches {
		stats[name] = cache.GetStats()
	}

	return stats
}

// ClearAll clears all caches
func (mc *MultiCache) ClearAll() {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	for _, cache := range mc.caches {
		cache.Clear()
	}

	mc.logger.Info().Msg("Cleared all caches")
}
