// SPDX-License-Identifier: MIT
//
// DNS Trie based upon Crit-bit Tree
//

package dnstrie

import (
	"bytes"
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

// DNS trie that combines a hash map and crit-bit tree to support both exact
// name match and longest zone match.
// NOTE: Similar to critbit.Tree, it's the consumer's responsibility to
// protect concurrent accesses if it's needed.
type DNSTrie struct {
	hash map[string]nullT
	tree critbit.Tree
}

type nullT struct{}

var null = nullT{}

// A key for trie match
type Key []byte

// Convert a DNS name into a trie lookup key.
// The input (dname) is decoded and in text format, but not needed to
// be normalized to lower case.
func NewKey(dname string) Key {
	if !strings.HasSuffix(dname, ".") {
		dname += "."
	}

	// Reverse the dname and normalize to lower case.
	l := len(dname)
	key := make([]byte, l)
	for i, c := range []byte(dname) {
		key[l-i-1] = keyXTable[c]
	}

	return Key(key)
}

func (k Key) String() string {
	// Reverse it back for display.
	l := len(k)
	name := make([]byte, l)
	for i, b := range k {
		name[l-i-1] = b
	}
	return string(name)
}

func (k Key) Equal(kk Key) bool {
	return bytes.Equal(k, kk)
}

// Add a name for exact match.
func (t *DNSTrie) AddName(name string) {
	key := NewKey(name)
	if t.hash == nil {
		t.hash = make(map[string]nullT)
	}
	t.hash[string(key)] = null
}

func (t *DNSTrie) HasName(name string) bool {
	key := NewKey(name)
	_, ok := t.hash[string(key)]
	return ok
}

func (t *DNSTrie) DeleteName(name string) {
	key := NewKey(name)
	delete(t.hash, string(key))
}

// Add a zone for longest zone match.
func (t *DNSTrie) AddZone(name string) {
	key := NewKey(name)
	t.tree.Set(key, null)
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

// Lookup the name to find a match.
// If found a match, return the key and a boolean indicating whether it was
// an exact match; otherwise, return nil and false.
func (t *DNSTrie) Match(name string) (Key, bool) {
	key := NewKey(name)
	if _, ok := t.hash[string(key)]; ok {
		return key, true
	}
	if k, _, ok := t.tree.LongestPrefix(key); ok {
		return k, false
	}
	return nil, false
}
