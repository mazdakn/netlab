package rate_limit

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	ticker := make(chan time.Time)
	tb := newTockenBucketWithShim(context.Background(), 10, 3, time.Second, ticker)
	tokens := tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 0 {
		t.Fail()
	}

	ticker <- time.Now()
	time.Sleep(time.Second)
	tokens = tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 3 {
		t.Fail()
	}

	tokens = tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 0 {
		t.Fail()
	}

	ticker <- time.Now()
	time.Sleep(time.Second)
	tokens = tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 3 {
		t.Fail()
	}
}

func TestTokenBucketOpts(t *testing.T) {
	tb := NewTockenBucketOpt(context.Background(), 10, 3)
	tokens := tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 0 {
		t.Fail()
	}

	time.Sleep(time.Second)
	tokens = tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 3 {
		t.Fail()
	}

	tokens = tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 0 {
		t.Fail()
	}

	time.Sleep(time.Second)
	tokens = tb.TryConsume(5)
	fmt.Printf("available tokens: %v\n", tokens)
	if tokens != 3 {
		t.Fail()
	}
}
