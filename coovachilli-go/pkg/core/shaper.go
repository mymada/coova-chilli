package core

import (
	"sync"
	"time"

	"coovachilli-go/pkg/config"
)

const (
	// BUCKET_TIME is the reference time in seconds for calculating bucket size.
	// This value is based on the C implementation.
	BUCKET_TIME = 1
	// BUCKET_SIZE_MIN is the minimum size for a bucket.
	BUCKET_SIZE_MIN = 2048
)

// QoSClass represents traffic quality of service classification
type QoSClass int

const (
	QoSClassBestEffort QoSClass = iota
	QoSClassBackground
	QoSClassVideo
	QoSClassVoice
	QoSClassInteractive
	QoSClassCritical
)

// TrafficClass represents a traffic classification for shaping
type TrafficClass struct {
	Name            string
	Priority        int
	GuaranteedRate  uint64 // bits per second
	MaxRate         uint64 // bits per second
	BurstSize       uint64 // bytes
	DropProbability float64
}

// ShaperStats holds statistics for bandwidth shaping
type ShaperStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsDropped  uint64
	PacketsShaped   uint64
	LastUpdateTime  time.Time
	AvgUploadRate   float64 // bytes per second
	AvgDownloadRate float64 // bytes per second
	mu              sync.RWMutex
}

// InitializeShaper sets up the leaky bucket parameters for a session.
func (s *Session) InitializeShaper(cfg *config.Config) {
	s.Lock()
	defer s.Unlock()

	// Initialize upload bucket size
	if cfg.BwBucketUpSize > 0 {
		s.BucketUpSize = cfg.BwBucketUpSize
	} else if s.SessionParams.BandwidthMaxUp > 0 {
		s.BucketUpSize = (s.SessionParams.BandwidthMaxUp / 8) * BUCKET_TIME
	}
	if s.BucketUpSize < BUCKET_SIZE_MIN {
		s.BucketUpSize = BUCKET_SIZE_MIN
	}

	// Initialize download bucket size
	if cfg.BwBucketDnSize > 0 {
		s.BucketDownSize = cfg.BwBucketDnSize
	} else if s.SessionParams.BandwidthMaxDown > 0 {
		s.BucketDownSize = (s.SessionParams.BandwidthMaxDown / 8) * BUCKET_TIME
	}
	if s.BucketDownSize < BUCKET_SIZE_MIN {
		s.BucketDownSize = BUCKET_SIZE_MIN
	}

	// Apply minimum bucket size if configured globally
	if cfg.BwBucketMinSize > 0 {
		if s.BucketUpSize < cfg.BwBucketMinSize {
			s.BucketUpSize = cfg.BwBucketMinSize
		}
		if s.BucketDownSize < cfg.BwBucketMinSize {
			s.BucketDownSize = cfg.BwBucketMinSize
		}
	}

	s.LastBWTime = time.Now()
}

// ShouldDropPacket checks if a packet should be dropped based on the leaky bucket algorithm.
// It returns true if the packet should be dropped. `isUpload` determines the direction.
func (s *Session) ShouldDropPacket(packetSize uint64, isUpload bool) bool {
	s.Lock()
	defer s.Unlock()

	// If no bandwidth limits are set for this direction, don't drop the packet.
	if (isUpload && s.SessionParams.BandwidthMaxUp == 0) || (!isUpload && s.SessionParams.BandwidthMaxDown == 0) {
		return false
	}

	now := time.Now()
	timeDiff := now.Sub(s.LastBWTime).Seconds()
	s.LastBWTime = now

	if isUpload {
		// Calculate how many bytes should have leaked from the bucket
		leakedBytes := uint64(timeDiff * float64(s.SessionParams.BandwidthMaxUp/8))

		// Drain the bucket
		if s.BucketUp > leakedBytes {
			s.BucketUp -= leakedBytes
		} else {
			s.BucketUp = 0
		}

		// Check if adding the new packet overflows the bucket
		if (s.BucketUp + packetSize) > s.BucketUpSize {
			return true // Drop packet
		}
		s.BucketUp += packetSize
	} else { // isDownload
		// Calculate how many bytes should have leaked from the bucket
		leakedBytes := uint64(timeDiff * float64(s.SessionParams.BandwidthMaxDown/8))

		// Drain the bucket
		if s.BucketDown > leakedBytes {
			s.BucketDown -= leakedBytes
		} else {
			s.BucketDown = 0
		}

		// Check if adding the new packet overflows the bucket
		if (s.BucketDown + packetSize) > s.BucketDownSize {
			return true // Drop packet
		}
		s.BucketDown += packetSize
	}

	return false // Do not drop packet
}

// UpdateShaperStats updates bandwidth shaping statistics for a session
func (s *Session) UpdateShaperStats(packetSize uint64, isUpload bool) {
	if s.ShaperStats == nil {
		s.ShaperStats = &ShaperStats{
			LastUpdateTime: time.Now(),
		}
	}

	s.ShaperStats.mu.Lock()
	defer s.ShaperStats.mu.Unlock()

	now := time.Now()
	timeDiff := now.Sub(s.ShaperStats.LastUpdateTime).Seconds()

	if isUpload {
		s.ShaperStats.BytesSent += packetSize
		if timeDiff > 0 {
			s.ShaperStats.AvgUploadRate = float64(s.ShaperStats.BytesSent) / timeDiff
		}
	} else {
		s.ShaperStats.BytesReceived += packetSize
		if timeDiff > 0 {
			s.ShaperStats.AvgDownloadRate = float64(s.ShaperStats.BytesReceived) / timeDiff
		}
	}

	s.ShaperStats.LastUpdateTime = now
}

// RecordDroppedPacket records a dropped packet in shaping statistics
func (s *Session) RecordDroppedPacket() {
	if s.ShaperStats == nil {
		s.ShaperStats = &ShaperStats{}
	}

	s.ShaperStats.mu.Lock()
	s.ShaperStats.PacketsDropped++
	s.ShaperStats.mu.Unlock()
}

// RecordShapedPacket records a shaped packet in statistics
func (s *Session) RecordShapedPacket() {
	if s.ShaperStats == nil {
		s.ShaperStats = &ShaperStats{}
	}

	s.ShaperStats.mu.Lock()
	s.ShaperStats.PacketsShaped++
	s.ShaperStats.mu.Unlock()
}

// GetShaperStats returns a copy of shaper statistics
func (s *Session) GetShaperStats() ShaperStats {
	if s.ShaperStats == nil {
		return ShaperStats{}
	}

	s.ShaperStats.mu.RLock()
	defer s.ShaperStats.mu.RUnlock()

	return ShaperStats{
		BytesSent:       s.ShaperStats.BytesSent,
		BytesReceived:   s.ShaperStats.BytesReceived,
		PacketsDropped:  s.ShaperStats.PacketsDropped,
		PacketsShaped:   s.ShaperStats.PacketsShaped,
		LastUpdateTime:  s.ShaperStats.LastUpdateTime,
		AvgUploadRate:   s.ShaperStats.AvgUploadRate,
		AvgDownloadRate: s.ShaperStats.AvgDownloadRate,
	}
}

// ApplyQoS applies QoS policies to a packet based on traffic class
func (s *Session) ApplyQoS(packetSize uint64, qosClass QoSClass, isUpload bool) bool {
	s.Lock()
	defer s.Unlock()

	// Get traffic class configuration
	tc := s.GetTrafficClass(qosClass)
	if tc == nil {
		// No QoS policy, use standard shaping
		return s.ShouldDropPacket(packetSize, isUpload)
	}

	// Apply priority-based shaping
	maxRate := tc.MaxRate / 8 // Convert bits/s to bytes/s
	guaranteedRate := tc.GuaranteedRate / 8

	// Check if packet exceeds maximum rate
	now := time.Now()
	timeDiff := now.Sub(s.LastBWTime).Seconds()
	s.LastBWTime = now

	var bucket *uint64
	var bucketSize uint64

	if isUpload {
		bucket = &s.BucketUp
		bucketSize = s.BucketUpSize
	} else {
		bucket = &s.BucketDown
		bucketSize = s.BucketDownSize
	}

	// Apply token bucket with guaranteed rate
	leakedBytes := uint64(timeDiff * float64(guaranteedRate))
	if *bucket > leakedBytes {
		*bucket -= leakedBytes
	} else {
		*bucket = 0
	}

	// Check burst allowance
	if tc.BurstSize > 0 && (*bucket+packetSize) <= tc.BurstSize {
		*bucket += packetSize
		return false // Allow burst traffic
	}

	// Check if exceeds maximum rate
	if (*bucket + packetSize) > bucketSize {
		// Apply drop probability for this class
		if tc.DropProbability > 0 {
			// Simple probabilistic dropping
			// In production, this should use RED (Random Early Detection) algorithm
			if float64((*bucket*100)/bucketSize) > (100.0-tc.DropProbability*100) {
				return true // Drop packet
			}
		}

		// Exceeded max rate without burst allowance
		if maxRate > 0 && (*bucket+packetSize) > maxRate {
			return true // Drop packet
		}
	}

	*bucket += packetSize
	return false
}

// GetTrafficClass returns the traffic class configuration for a QoS class
func (s *Session) GetTrafficClass(qosClass QoSClass) *TrafficClass {
	// Check if session has custom traffic classes
	if s.TrafficClasses != nil {
		if tc, ok := s.TrafficClasses[qosClass]; ok {
			return &tc
		}
	}

	// Return default traffic classes
	return getDefaultTrafficClass(qosClass)
}

// getDefaultTrafficClass returns default traffic class configurations
func getDefaultTrafficClass(qosClass QoSClass) *TrafficClass {
	switch qosClass {
	case QoSClassVoice:
		return &TrafficClass{
			Name:            "Voice",
			Priority:        5,
			GuaranteedRate:  64000,  // 64 Kbps
			MaxRate:         128000, // 128 Kbps
			BurstSize:       8192,   // 8 KB
			DropProbability: 0.001,  // Very low drop rate
		}
	case QoSClassVideo:
		return &TrafficClass{
			Name:            "Video",
			Priority:        4,
			GuaranteedRate:  512000,  // 512 Kbps
			MaxRate:         2000000, // 2 Mbps
			BurstSize:       65536,   // 64 KB
			DropProbability: 0.01,
		}
	case QoSClassInteractive:
		return &TrafficClass{
			Name:            "Interactive",
			Priority:        3,
			GuaranteedRate:  128000, // 128 Kbps
			MaxRate:         512000, // 512 Kbps
			BurstSize:       16384,  // 16 KB
			DropProbability: 0.05,
		}
	case QoSClassCritical:
		return &TrafficClass{
			Name:            "Critical",
			Priority:        6,
			GuaranteedRate:  256000,  // 256 Kbps
			MaxRate:         1000000, // 1 Mbps
			BurstSize:       32768,   // 32 KB
			DropProbability: 0.0001,  // Extremely low drop rate
		}
	case QoSClassBackground:
		return &TrafficClass{
			Name:            "Background",
			Priority:        1,
			GuaranteedRate:  0,       // No guarantee
			MaxRate:         256000,  // 256 Kbps
			BurstSize:       4096,    // 4 KB
			DropProbability: 0.2,     // High drop rate
		}
	case QoSClassBestEffort:
		fallthrough
	default:
		return &TrafficClass{
			Name:            "BestEffort",
			Priority:        2,
			GuaranteedRate:  0,       // No guarantee
			MaxRate:         1000000, // 1 Mbps
			BurstSize:       16384,   // 16 KB
			DropProbability: 0.1,
		}
	}
}

// SetTrafficClass sets a custom traffic class for a session
func (s *Session) SetTrafficClass(qosClass QoSClass, tc TrafficClass) {
	s.Lock()
	defer s.Unlock()

	if s.TrafficClasses == nil {
		s.TrafficClasses = make(map[QoSClass]TrafficClass)
	}

	s.TrafficClasses[qosClass] = tc
}

// ResetBandwidthBuckets resets the bandwidth buckets to allow burst traffic
func (s *Session) ResetBandwidthBuckets() {
	s.Lock()
	defer s.Unlock()

	s.BucketUp = 0
	s.BucketDown = 0
	s.LastBWTime = time.Now()
}

// AdjustBandwidthLimits dynamically adjusts bandwidth limits for a session
func (s *Session) AdjustBandwidthLimits(uploadBps, downloadBps uint64) {
	s.Lock()
	defer s.Unlock()

	// Update session parameters
	s.SessionParams.BandwidthMaxUp = uploadBps
	s.SessionParams.BandwidthMaxDown = downloadBps

	// Recalculate bucket sizes
	if uploadBps > 0 {
		s.BucketUpSize = (uploadBps / 8) * BUCKET_TIME
		if s.BucketUpSize < BUCKET_SIZE_MIN {
			s.BucketUpSize = BUCKET_SIZE_MIN
		}
	}

	if downloadBps > 0 {
		s.BucketDownSize = (downloadBps / 8) * BUCKET_TIME
		if s.BucketDownSize < BUCKET_SIZE_MIN {
			s.BucketDownSize = BUCKET_SIZE_MIN
		}
	}
}