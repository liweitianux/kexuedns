// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// DNS Trie based upon Crit-bit Tree
//

package dnstrie

import (
	"strings"

	"kexuedns/util/critbit"
)

// A table to speed up the transformation of DNS keys to lower case.
var keyXTable [256]byte

func init() {
	for i := 0; i < len(keyXTable); i++ {
		c := byte(i)
		if c >= byte('A') && c <= byte('Z') {
			c = c - byte('A') + byte('a')
		}
		keyXTable[i] = c
	}
}

// DNS trie for longest zone match.
//
// A zone "example.com" must match itself (i.e., "example.com") and any
// subdomains (e.g., "www.example.com", "abc.def.example.com"), but must not
// match another zone like "XXXexample.com".
//
// In order to archieve the above goal with the Critbit Tree, a zone like
// "example.com" is transformed to be "moc.elpmaxe." and then inserted into the
// Critbit Tree.  The domain to be matched is also similarly transformed to
// perform the matching operation.  In other words, a zone/domain is processed
// with the following steps:
//  1. remove the final dot if exists
//  2. convert to lower case
//  3. reverse the order
//  4. append a dot
//
// NOTE: Similar to critbit.Tree, it's the consumer's responsibility to
// protect concurrent accesses if it's needed.
type DNSTrie struct {
	tree critbit.Tree
}

// A key for trie match
type Key []byte

// Convert a DNS name into a trie lookup key.
// The input (dname) is decoded and in text format, but not needed to
// be normalized to lower case, e.g., "www.Example.COM."
func NewKey(dname string) Key {
	// 1. remove the final dot if exists
	dname = strings.TrimSuffix(dname, ".")

	// 2. convert to lower case
	// 3. reverse the order
	l := len(dname)
	key := make([]byte, l+1)
	for i, c := range []byte(dname) {
		key[l-i-1] = keyXTable[c]
	}

	// 4. append a dot
	key[l] = '.'

	return Key(key)
}

func (k Key) String() string {
	// Reverse it back for display.
	l := len(k)
	name := make([]byte, l)
	for i, b := range k {
		name[l-i-1] = b
	}
	return string(name[1:]) // exclude the appended dot
}

func (t *DNSTrie) AddZone(name string) {
	key := NewKey(name)
	t.tree.Set(key, name) // store the original name for Export()
}

func (t *DNSTrie) HasZone(name string) bool {
	key := NewKey(name)
	_, ok := t.tree.Get(key)
	return ok
}

func (t *DNSTrie) DeleteZone(name string) {
	key := NewKey(name)
	t.tree.Delete(key)
}

// Match the name to find the longest matched zone.
func (t *DNSTrie) Match(name string) (Key, bool) {
	key := NewKey(name)
	k, _, ok := t.tree.LongestPrefix(key)
	return k, ok
}

func (t *DNSTrie) Export() []string {
	zones := []string{}
	t.tree.Walk(func(_ []byte, value any) bool {
		zones = append(zones, value.(string))
		return true
	})
	return zones
}
