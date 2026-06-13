// Package ratelimit provides distributed rate limiting with Redis backend
// and automatic fallback to local rate limiting when Redis is unavailable.
package ratelimit

import (
	"errors"
	"math"
	"sync"
	"time"
)

// Backend defines the rate limiting interface.
type Backend interface {
	// Allow checks if the request should be allowed.
	// Returns true if allowed, false if rate limited.
	// retryAfter suggests how long to wait before retrying.
	Allow(key string, ratePerSec float64, burst int) (allowed bool, retryAfter time.Duration, err error)
}

// Decision represents a rate limit decision.
type Decision struct {
	Allowed    bool
	Blocked    bool
	RetryAfter time.Duration
}

// LocalBackend implements a token bucket rate limiter in local memory.
// This is the same algorithm used by the existing proxy rate limiter.
type LocalBackend struct {
	mu     sync.Mutex
	states map[string]*bucketState
}

type bucketState struct {
	tokens         float64
	last           time.Time
	violationCount int
	violationStart time.Time
	blockedUntil   time.Time
}

// NewLocalBackend creates a new local token bucket backend.
func NewLocalBackend() *LocalBackend {
	return &LocalBackend{
		states: make(map[string]*bucketState),
	}
}

func (b *LocalBackend) Allow(key string, ratePerSec float64, burst int) (bool, time.Duration, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	state, ok := b.states[key]
	if !ok {
		state = &bucketState{
			tokens: float64(burst),
			last:   time.Now(),
		}
		b.states[key] = state
	}

	now := time.Now()

	// Check if blocked
	if !state.blockedUntil.IsZero() {
		if now.Before(state.blockedUntil) {
			return false, state.blockedUntil.Sub(now), nil
		}
		state.blockedUntil = time.Time{}
		state.violationCount = 0
	}

	// Refill tokens
	elapsed := now.Sub(state.last).Seconds()
	state.tokens = math.Min(float64(burst), state.tokens+elapsed*ratePerSec)
	state.last = now

	if state.tokens >= 1 {
		state.tokens--
		return true, 0, nil
	}

	// Rate limited - record violation
	state.violationCount++
	if state.violationStart.IsZero() {
		state.violationStart = now
	}

	return false, time.Duration(float64(time.Second) / ratePerSec), nil
}

// Cleanup removes stale state entries.
func (b *LocalBackend) Cleanup(maxAge time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for key, state := range b.states {
		if state.last.Before(cutoff) {
			delete(b.states, key)
		}
	}
}

// BackendType defines the type of rate limit backend.
type BackendType string

const (
	BackendLocal BackendType = "local"
	BackendRedis BackendType = "redis"
)

// Manager wraps a rate limit backend with health checking and fallback.
type Manager struct {
	mu          sync.RWMutex
	primary     Backend
	fallback    Backend
	backendType BackendType
	checkHealth func() bool
}

// NewManager creates a new rate limit manager.
func NewManager(primary Backend, fallback Backend, backendType BackendType, healthCheck func() bool) *Manager {
	if primary == nil {
		primary = NewLocalBackend()
	}
	if fallback == nil {
		fallback = NewLocalBackend()
	}
	return &Manager{
		primary:     primary,
		fallback:    fallback,
		backendType: backendType,
		checkHealth: healthCheck,
	}
}

// Allow delegates to the appropriate backend.
// If the primary backend fails (e.g., Redis is down), falls back to local.
func (m *Manager) Allow(key string, ratePerSec float64, burst int) (bool, time.Duration, error) {
	// Always try primary first
	primary := m.getPrimary()
	allowed, retryAfter, err := primary.Allow(key, ratePerSec, burst)
	if err == nil {
		return allowed, retryAfter, nil
	}

	// Primary failed, try fallback
	fallback := m.getFallback()
	allowed, retryAfter, fbErr := fallback.Allow(key, ratePerSec, burst)
	if fbErr == nil {
		return allowed, retryAfter, nil
	}

	return false, 0, errors.New("rate limit backends unavailable")
}

func (m *Manager) getPrimary() Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.checkHealth != nil && !m.checkHealth() {
		return m.fallback
	}
	return m.primary
}

func (m *Manager) getFallback() Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fallback
}

// Close releases resources held by the manager.
func (m *Manager) Close() {
	// Nothing to close for local backend
}
