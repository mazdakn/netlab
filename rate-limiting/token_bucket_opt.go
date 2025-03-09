package rate_limit

import (
	"context"
	"time"
)

type TokenBucketOpt struct {
	tokens int

	burst int
	rate  int

	lastChecked time.Time
}

func NewTockenBucketOpt(ctx context.Context, burst, rate int) *TokenBucketOpt {
	return &TokenBucketOpt{
		burst:       burst,
		rate:        rate,
		lastChecked: time.Now(),
	}
}

func (tb *TokenBucketOpt) TryConsume(req int) int {
	now := time.Now()
	p := now.Sub(tb.lastChecked)
	tokens := tb.rate * (int(p.Seconds()))
	tb.tokens = min(tb.burst, tb.tokens+tokens)
	tb.lastChecked = now

	if tb.tokens >= req {
		tb.tokens = tb.tokens - req
		return req
	}
	value := tb.tokens
	tb.tokens = 0
	return value
}
