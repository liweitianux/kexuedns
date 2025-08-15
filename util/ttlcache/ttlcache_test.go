// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// TTL cache - tests
//

package ttlcache

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestAdd1(t *testing.T) {
	// TODO...
}

func TestEviction1(t *testing.T) {
	var evicted atomic.Uint32
	cache := New(10*time.Millisecond, 20*time.Millisecond,
		func(key string, value any) { evicted.Add(1) })
	defer cache.Close()

	key := "hello"

	cache.Set(key, "hoho", 100*time.Millisecond)
	if v, ok := cache.Get(key); !ok || v == nil {
		t.Errorf(`Get(%q) = (%v, %t); want (!nil, true)`, key, v, ok)
	}
	if v, ok := cache.Pop(key); !ok || v == nil {
		t.Errorf(`Pop(%q) = (%v, %t); want (!nil, true)`, key, v, ok)
	}
	// Pop() should skip the callback.
	if n := evicted.Load(); n != 0 {
		t.Errorf(`(a) evicted = %d; want 0`, n)
	}

	time.Sleep(30 * time.Millisecond)
	// Nothing to clean up and eviction.
	if n := evicted.Load(); n != 0 {
		t.Errorf(`(b) evicted = %d; want 0`, n)
	}
}

func TestEviction2(t *testing.T) {
	var evicted atomic.Uint32
	cache := New(10*time.Millisecond, 20*time.Millisecond,
		func(key string, value any) { evicted.Add(1) })
	defer cache.Close()

	keys := []string{"hello", "world", "yo"}
	for _, key := range keys {
		cache.Set(key, "hoho", 10*time.Millisecond)
	}

	time.Sleep(30 * time.Millisecond)
	if n := evicted.Load(); int(n) != len(keys) {
		t.Errorf(`evicted = %d; want %d`, n, len(keys))
	}
}

func TestEviction3(t *testing.T) {
	var evicted atomic.Uint32
	cache := New(100*time.Millisecond, 20*time.Millisecond,
		func(key string, value any) { evicted.Add(1) })
	defer cache.Close()

	key := "hello"
	cache.Set(key, "hoho", 10*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if v, ok := cache.Get(key); ok || v != nil {
		t.Errorf(`Get(%q) = (%v, %t); want (nil, false)`, key, v, ok)
	}
	if n := evicted.Load(); n != 0 {
		t.Errorf(`(a) evicted = %d; want 0`, n)
	}

	time.Sleep(20 * time.Millisecond)
	if n := evicted.Load(); n != 1 {
		t.Errorf(`(b) evicted = %d; want 1`, n)
	}
}
