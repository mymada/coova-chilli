package core

import (
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