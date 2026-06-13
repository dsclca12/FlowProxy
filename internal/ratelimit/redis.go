package ratelimit

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisRateLimitScript is a Lua script that implements a sliding window
// rate limiter with atomic operations.
//
// KEYS[1] = rate limit key
// ARGV[1] = window size in seconds (typically 1 for per-second rate)
// ARGV[2] = max requests per window (burst)
// ARGV[3] = current timestamp in microseconds
//
// Returns:
//   - 0 if allowed (with remaining count as second return value)
//   - 1 if rate limited (with retry-after in seconds as second return value)
const redisRateLimitScript = `
local key = KEYS[1]
local window = tonumber(ARGV[1])
local maxRequests = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local windowMicros = window * 1000000

-- Remove expired entries
redis.call("ZREMRANGEBYSCORE", key, 0, now - windowMicros)

-- Count requests in current window
local count = redis.call("ZCARD", key)

if count >= maxRequests then
	-- Get the oldest entry's timestamp for retry-after calculation
	local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
	local retryAfter = 0
	if oldest[2] then
		retryAfter = (tonumber(oldest[2]) + windowMicros - now) / 1000000
		if retryAfter < 0 then retryAfter = 0 end
	end
	return {1, retryAfter}
end

-- Add current request with microsecond precision
redis.call("ZADD", key, now, now .. ":" .. math.random())

-- Set TTL on the key to avoid stale data
redis.call("PEXPIRE", key, windowMicros)

return {0, maxRequests - count - 1}
`

// RedisBackend implements a distributed rate limiter using Redis.
// It uses a sorted set with microsecond timestamps for sliding window accuracy.
type RedisBackend struct {
	client    *redis.Client
	namespace string
}

// RedisOptions holds configuration for the Redis rate limit backend.
type RedisOptions struct {
	Endpoints []string `json:"endpoints,omitempty"`
	Password  string   `json:"password,omitempty"`
	DB        int      `json:"db,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
}

// NewRedisBackend creates a new Redis-backed rate limiter.
func NewRedisBackend(opts RedisOptions) (*RedisBackend, error) {
	if len(opts.Endpoints) == 0 {
		return nil, errors.New("redis endpoints are required")
	}

	namespace := opts.Namespace
	if namespace == "" {
		namespace = "flowproxy:ratelimit"
	}

	client := redis.NewClient(&redis.Options{
		Addr:         opts.Endpoints[0],
		Password:     opts.Password,
		DB:           opts.DB,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     10,
		MinIdleConns: 2,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}

	return &RedisBackend{
		client:    client,
		namespace: namespace,
	}, nil
}

// HealthCheck returns true if Redis is reachable.
func (b *RedisBackend) HealthCheck() bool {
	if b == nil || b.client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return b.client.Ping(ctx).Err() == nil
}

// Allow checks rate limit via Redis Lua script.
func (b *RedisBackend) Allow(key string, ratePerSec float64, burst int) (bool, time.Duration, error) {
	if b == nil || b.client == nil {
		return false, 0, errors.New("redis backend not initialized")
	}

	window := 1 // 1-second sliding window
	now := time.Now().UnixMicro()
	redisKey := b.namespace + ":" + key

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	result, err := b.client.Eval(ctx, redisRateLimitScript, []string{redisKey}, window, burst, now).Result()
	if err != nil {
		return false, 0, err
	}

	values, ok := result.([]interface{})
	if !ok || len(values) < 2 {
		return false, 0, errors.New("unexpected redis rate limit response")
	}

	limited, ok := values[0].(int64)
	if !ok {
		return false, 0, errors.New("unexpected redis rate limit response type")
	}

	if limited == 1 {
		retryAfter, _ := values[1].(float64)
		return false, time.Duration(retryAfter * float64(time.Second)), nil
	}

	return true, 0, nil
}

// Close closes the Redis connection.
func (b *RedisBackend) Close() error {
	if b == nil || b.client == nil {
		return nil
	}
	return b.client.Close()
}
