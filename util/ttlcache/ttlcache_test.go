// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Aaron LI
//
// TTL cache - tests
//

package ttlcache

import (
	"testing"
	"time"
)

func TestAdd1(t *testing.T) {
	// TODO...
}

func TestEviction1(t *testing.T) {
	evicted := 0
	cache := New(10*time.Millisecond, 20*time.Millisecond,
		func(key string, value any) { evicted++ })
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
	if evicted != 0 {
		t.Errorf(`(a) evicted = %d; want 0`, evicted)
	}

	time.Sleep(30 * time.Millisecond)
	// Nothing to clean up and eviction.
	if evicted != 0 {
		t.Errorf(`(b) evicted = %d; want 0`, evicted)
	}
}

func TestEviction2(t *testing.T) {
	evicted := 0
	cache := New(10*time.Millisecond, 20*time.Millisecond,
		func(key string, value any) { evicted++ })
	defer cache.Close()

	keys := []string{"hello", "world", "yo"}
	for _, key := range keys {
		cache.Set(key, "hoho", 10*time.Millisecond)
	}

	time.Sleep(30 * time.Millisecond)
	if evicted != len(keys) {
		t.Errorf(`evicted = %d; want %d`, evicted, len(keys))
	}
}

func TestEviction3(t *testing.T) {
	evicted := 0
	cache := New(100*time.Millisecond, 20*time.Millisecond,
		func(key string, value any) { evicted++ })
	defer cache.Close()

	key := "hello"
	cache.Set(key, "hoho", 10*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if v, ok := cache.Get(key); ok || v != nil {
		t.Errorf(`Get(%q) = (%v, %t); want (nil, false)`, key, v, ok)
	}
	if evicted != 0 {
		t.Errorf(`(a) evicted = %d; want 0`, evicted)
	}

	time.Sleep(20 * time.Millisecond)
	if evicted != 1 {
		t.Errorf(`(b) evicted = %d; want 1`, evicted)
	}
}
