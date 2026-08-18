// Package ratelimit provides a Redis-backed fixed-window rate limiter.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Limit struct {
	Requests int
	Window   time.Duration
}

type Limiter struct {
	rdb *redis.Client
}

func NewLimiter(rdb *redis.Client) *Limiter {
	return &Limiter{rdb: rdb}
}

// incrScript atomically increments the counter and sets the TTL on first hit.
var incrScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return count
`)

type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Allow records a hit for key and reports whether it is within the limit.
func (l *Limiter) Allow(ctx context.Context, key string, limit Limit) (Result, error) {
	redisKey := fmt.Sprintf("ratelimit:%s", key)
	count, err := incrScript.Run(ctx, l.rdb, []string{redisKey}, limit.Window.Milliseconds()).Int()
	if err != nil {
		return Result{}, fmt.Errorf("rate limit incr: %w", err)
	}
	if count > limit.Requests {
		ttl, err := l.rdb.PTTL(ctx, redisKey).Result()
		if err != nil || ttl < 0 {
			ttl = limit.Window
		}
		return Result{Allowed: false, Remaining: 0, RetryAfter: ttl}, nil
	}
	return Result{Allowed: true, Remaining: limit.Requests - count}, nil
}
