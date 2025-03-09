package rate_limit

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

type TokenBucket struct {
	value atomic.Uint32

	burst  uint32
	period time.Duration
	tokens uint32
}

func NewTokenBucket(ctx context.Context, burst, tokens uint32, period time.Duration) *TokenBucket {
	ticker := time.NewTicker(period)
	return newTockenBucketWithShim(ctx, burst, tokens, period, ticker.C)
}

func newTockenBucketWithShim(
	ctx context.Context,
	burst, tokens uint32,
	period time.Duration,
	ticker <-chan time.Time,
) *TokenBucket {
	tb := &TokenBucket{
		burst:  burst,
		tokens: tokens,
		period: period,
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker:
				tb.value.Add(tokens)
				if tb.value.Load() > tb.burst {
					tb.value.Store(tb.burst)
				}
				fmt.Printf("Tick at %v: available tokens: %v\n ", t, tb.value.Load())
			}
		}
	}()
	return tb
}

func (tb *TokenBucket) TryConsume(req uint32) uint32 {
	value := tb.value.Load()
	if value >= req {
		tb.value.Store(value - req)
		return req
	}
	tb.value.Store(0)
	return value
}
