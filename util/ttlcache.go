// SPDX-License-Identifier: MIT
//
// Utilities - TTL cache
//

package util

import (
	"errors"
	"sync"
	"time"
)

const (
	DefaultTTL = 0
	NoTTL      = -1 * time.Second // no expiration
)

const defaultInterval = 5 * time.Second // default cleanup interval

var ErrCacheKeyExists = errors.New("cache key already exists")

type TtlCache struct {
	items      map[string]*ttlCacheItem
	lock       sync.RWMutex
	defaultTTL time.Duration
	onEviction func(string, any)
}

type ttlCacheItem struct {
	value    any
	expireAt int64 // UnixNano
}

func NewTtlCache(
	defaultTTL time.Duration,
	interval time.Duration,
	onEviction func(string, any),
) *TtlCache {
	if interval <= 0 {
		interval = defaultInterval
	}
	c := &TtlCache{
		items:      make(map[string]*ttlCacheItem),
		lock:       sync.RWMutex{},
		defaultTTL: defaultTTL,
		onEviction: onEviction,
	}
	go c.clean(interval)
	return c
}

// Add the key and value with the TTL.
// If key already exists, return ErrCacheKeyExists.
func (c *TtlCache) Add(key string, value any, ttl time.Duration) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if _, exists := c.items[key]; exists {
		return ErrCacheKeyExists
	}

	c.items[key] = &ttlCacheItem{
		value:    value,
		expireAt: c.getExpireAt(ttl),
	}
	return nil
}

// Similar to Add(), but overwrite the existing one.
func (c *TtlCache) Set(key string, value any, ttl time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.items[key] = &ttlCacheItem{
		value:    value,
		expireAt: c.getExpireAt(ttl),
	}
}

// Get the value of key, with a boolean indicating whether it's valid.
func (c *TtlCache) Get(key string) (any, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}
	if item.expireAt > 0 && item.expireAt < time.Now().UnixNano() {
		if c.onEviction != nil {
			c.onEviction(key, item.value)
		}
		return nil, false
	}
	return item.value, true
}

// Similar to Get() but also remove it.
func (c *TtlCache) Pop(key string) (any, bool) {
	v, ok := c.Get(key)
	if ok {
		c.lock.Lock()
		delete(c.items, key)
		c.lock.Unlock()
	}
	return v, ok
}

// Remove the item of key and invoke the eviction callback.
func (c *TtlCache) Remove(key string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	item, exists := c.items[key]
	if exists {
		delete(c.items, key)
		if c.onEviction != nil {
			c.onEviction(key, item.value)
		}
	}
}

func (c *TtlCache) getExpireAt(ttl time.Duration) int64 {
	if ttl < 0 {
		return -1
	}
	if ttl == 0 {
		ttl = c.defaultTTL
	}
	return time.Now().Add(ttl).UnixNano()
}

func (c *TtlCache) clean(interval time.Duration) {
	type kvItem struct {
		key   string
		value any
	}

	ticker := time.NewTicker(interval)
	for {
		<-ticker.C

		evictedItems := []*kvItem{}
		c.lock.Lock()
		now := time.Now().UnixNano()
		for key, item := range c.items {
			if item.expireAt > 0 && item.expireAt < now {
				delete(c.items, key)
				evictedItems = append(evictedItems, &kvItem{
					key:   key,
					value: item.value,
				})
			}
		}
		c.lock.Unlock()

		if c.onEviction != nil {
			for _, kv := range evictedItems {
				c.onEviction(kv.key, kv.value)
			}
		}
	}
}
