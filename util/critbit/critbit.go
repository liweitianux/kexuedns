// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Crit-bit Tree
//
// References:
// - https://cr.yp.to/critbit.html
// - Annotated crit-bit source
//   https://github.com/agl/critbit
//
// Credits:
// - https://dotat.at/prog/qp/README.html
// - https://github.com/tatsushid/go-critbit
// - https://github.com/k-sone/critbitgo
//
// TODO:
// - Implement a Set data structure that only store the keys, so that the
//   nodeExternal struct can be trimmed to save memory.
// - Is it possible to replace the iNode interface with tagged unsafe.Pointer()?
//   That would help reduce memory usage.
//

package critbit

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
)

type nodeKind int

const (
	nodeKindInternal nodeKind = iota
	nodeKindExternal
)

type iNode interface {
	kind() nodeKind
}

type nodeInternal struct {
	// NOTE: both are non-nil in a tree.
	children [2]iNode
	// The index of the differing byte.
	index int
	// The mask of the differing byte, all the bits except the critical bit
	// are ones.
	otherBits byte
}

func (n *nodeInternal) kind() nodeKind {
	return nodeKindInternal
}

func (n *nodeInternal) direction(key []byte) int {
	c := byte(0)
	if n.index < len(key) {
		c = key[n.index]
	}
	if n.otherBits|c == 0xFF {
		return 1 // critical bit is 1 => right
	} else {
		return 0 // critical bit is 0 => left
	}
}

type nodeExternal struct {
	key   []byte
	value any
}

func (n *nodeExternal) kind() nodeKind {
	return nodeKindExternal
}

func (n *nodeExternal) dump() string {
	keystr := fmt.Sprintf("%q", string(n.key))
	for _, c := range n.key {
		if !strconv.IsPrint(rune(c)) {
			keystr = "0x" + hex.EncodeToString(n.key)
			break
		}
	}

	return fmt.Sprintf("key=%s, value=%v", keystr, n.value)
}

// Crit-bit Tree
// NOTE: This code doesn't use any internal lock to protect concurrent
// accesses.  It's left for the consumer to choose the proper locks whenever
// concurrency is needed.
type Tree struct {
	root iNode
}

// Get the value for key (key).
// Return the value and a boolean indicating whether the key exists.
func (t *Tree) Get(key []byte) (any, bool) {
	node := t.root
	if node == nil {
		return nil, false // empty tree
	}

	// Walk the tree for the best memeber.
	for {
		if node.kind() != nodeKindInternal {
			break
		}
		nodeI := node.(*nodeInternal)
		node = nodeI.children[nodeI.direction(key)]
	}

	// Finally test the keys for equality.
	nodeE := node.(*nodeExternal)
	if bytes.Equal(nodeE.key, key) {
		return nodeE.value, true
	} else {
		return nil, false
	}
}

// Insert/update the key and value in the tree.
// If the key already exists and replace is true, the old value is replaced
// and returned.
func (t *Tree) insert(key []byte, value any, replace bool) (any, bool) {
	node := t.root
	if node == nil {
		// empty tree
		nodeE := &nodeExternal{
			key:   make([]byte, len(key)),
			value: value,
		}
		copy(nodeE.key, key)
		t.root = nodeE
		return nil, true
	}

	// Walk the tree for the best memeber.
	for {
		if node.kind() != nodeKindInternal {
			break
		}
		nodeI := node.(*nodeInternal)
		node = nodeI.children[nodeI.direction(key)]
	}

	// Find the differing byte.
	nodeE := node.(*nodeExternal)
	index := int(0)
	otherBits := byte(0)
	for index = 0; index < len(key); index++ {
		c := byte(0)
		if index < len(nodeE.key) {
			c = nodeE.key[index]
		}
		if c != key[index] {
			otherBits = c ^ key[index]
			goto NewNode
		}
	}
	if index < len(nodeE.key) {
		otherBits = nodeE.key[index]
		goto NewNode
	}

	if !bytes.Equal(nodeE.key, key) {
		panic("assertion failure")
	}
	if replace {
		oldValue := nodeE.value
		nodeE.value = value
		return oldValue, false // updated
	} else {
		return nil, false
	}

NewNode:
	// Find the differing bit (i.e., critical bit)
	// Here uses a SWAR algorithm instead of a loop.  Recursively fold the
	// upper bits into the lower bits to yield a byte (x) with all one bits
	// below the most significant bit (MSB); then (x & ~(x >> 1)) yields the
	// MSB.
	otherBits |= otherBits >> 1
	otherBits |= otherBits >> 2
	otherBits |= otherBits >> 4
	otherBits &^= otherBits >> 1 // MSB
	otherBits ^= 0xFF

	// Create new nodes.
	newNodeE := &nodeExternal{
		key:   make([]byte, len(key)),
		value: value,
	}
	copy(newNodeE.key, key)
	newNodeI := &nodeInternal{
		index:     index,
		otherBits: otherBits,
	}

	direction := newNodeI.direction(nodeE.key)
	newNodeI.children[1-direction] = newNodeE

	// Find the position to insert the new node.
	wherep := &t.root
	for {
		node := *wherep
		if node.kind() != nodeKindInternal {
			break
		}

		nodeI := node.(*nodeInternal)
		if nodeI.index > index {
			break
		}
		if nodeI.index == index && nodeI.otherBits > otherBits {
			break
		}

		wherep = &nodeI.children[nodeI.direction(key)]
	}

	// Insert the new node in the tree.
	newNodeI.children[direction] = *wherep
	*wherep = newNodeI

	if newNodeI.children[0] == nil || newNodeI.children[1] == nil {
		panic("newNodeI.children invalid")
	}

	return nil, true // inserted
}

// Insert the key (key) in the tree and associate it with the value (value).
// Return a boolean indicating whether the key has been inserted.
// If the key already exists, Insert() will not modify the tree and
// return false.
func (t *Tree) Insert(key []byte, value any) bool {
	_, ok := t.insert(key, value, false /* replace */)
	return ok
}

// Set the key (key) in the tree and update its value if it exists.
// Return (nil, true) if the key didn't exist yet; otherwise, return the old
// value and false.
func (t *Tree) Set(key []byte, value any) (any, bool) {
	return t.insert(key, value, true /* replace */)
}

// Delete the key (key) from the tree.
// Return the associated value and a boolean indicating whether the key exists.
func (t *Tree) Delete(key []byte) (any, bool) {
	if t.root == nil {
		return nil, false // empty tree
	}

	// Walk the tree for the best candidate to delete.
	wherep := &t.root       // in parent node
	var whereq *iNode       // in grandparent node
	var nodeI *nodeInternal // the parent node
	var direction int
	for {
		node := *wherep
		if node.kind() != nodeKindInternal {
			break
		}

		whereq = wherep
		nodeI = node.(*nodeInternal)
		direction = nodeI.direction(key)
		wherep = &nodeI.children[direction]
	}

	nodeE := (*wherep).(*nodeExternal) // the leaf node to delete
	if !bytes.Equal(nodeE.key, key) {
		return nil, false // key not exists
	}

	if whereq == nil {
		// tree only has one element
		t.root = nil
	} else {
		// Update the grandparent node to remove both nodeE and nodeI.
		*whereq = nodeI.children[1-direction]
		if *whereq == nil {
			panic("nodeI.children invalid")
		}
	}

	return nodeE.value, true
}

// Search the longest prefix for the given key (key).
//
// The keys in a crit-bit tree are lexicographically sorted, so the goal is to
// find the key that is:
//   - the largest one of those lexicographically less than or equal to the
//     given key (key);
//   - the prefix of the given key (key).
//
// Return the key and value of the matched node, and a boolean indicating
// whether there is a match.
//
// Credit: Claude Sonnet 4 (via https://claude.ai/chat/)
func (t *Tree) LongestPrefix(key []byte) ([]byte, any, bool) {
	node := t.root
	if node == nil {
		return nil, nil, false // empty tree
	}

	var last *nodeExternal
	for {
		if node.kind() == nodeKindExternal {
			// Check if this leaf is a prefix of the input key.
			nodeE := node.(*nodeExternal)
			if bytes.HasPrefix(key, nodeE.key) {
				last = nodeE
			}
			break
		}

		nodeI := node.(*nodeInternal)
		direction := nodeI.direction(key)

		if direction == 1 {
			// Before going right, check the left subtree (lexicographically
			// smaller) for smaller prefixes.
			// Find and check the rightmost leaf in the subtree.
			node = nodeI.children[0] // left
			for {
				if node.kind() != nodeKindInternal {
					break
				}
				nodeI := node.(*nodeInternal)
				node = nodeI.children[1] // always right
			}
			nodeE := node.(*nodeExternal)
			if bytes.HasPrefix(key, nodeE.key) {
				last = nodeE
			}
		}

		node = nodeI.children[direction]
	}

	if last != nil {
		return last.key, last.value, true
	} else {
		return nil, nil, false
	}
}

// NOTE: This is a recursive implementation.
func (t *Tree) LongestPrefixR(key []byte) ([]byte, any, bool) {
	return t.longestPrefixR(t.root, key)
}

func (t *Tree) longestPrefixR(node iNode, key []byte) ([]byte, any, bool) {
	switch n := node.(type) {
	case *nodeExternal:
		if bytes.HasPrefix(key, n.key) {
			return n.key, n.value, true
		}
	case *nodeInternal:
		direction := n.direction(key)
		if k, v, ok := t.longestPrefixR(n.children[direction], key); ok {
			return k, v, ok
		}
		// Also find the left subtree that's lexicographically smaller.
		if direction == 1 {
			return t.longestPrefixR(n.children[0], key)
		}
	}

	return nil, nil, false
}

// WalkFn is used at walking a tree.
// The walk process would terminate when it returns false.
type WalkFn func(key []byte, value any) bool

// Walk through the whole tree and call the function (fn) for each external
// node.  If the callback function (fn) returns false, the walk process
// would terminate.
// Return true if the walk finished without being terminated by the callback
// function (i.e., returned false); otherwise false.
func (t *Tree) Walk(fn WalkFn) bool {
	if t.root == nil {
		return true // empty tree
	}
	return t.walk(t.root, fn)
}

func (t *Tree) walk(node iNode, fn WalkFn) bool {
	switch n := node.(type) {
	case *nodeExternal:
		return fn(n.key, n.value)
	case *nodeInternal:
		if !t.walk(n.children[0], fn) {
			return false // terminate
		}
		if !t.walk(n.children[1], fn) {
			return false // terminate
		}
	}

	return true // continue
}

// Walk the tree under the given prefix (prefix) and call the function (fn) for
// every matched external node, whose key is prefixed with the given (prefix).
// If the callback function returns false, the walk process would terminate.
// Return true if the walk finished without being terminated by the callback
// function (i.e., returned false); otherwise false.
func (t *Tree) WalkPrefixed(prefix []byte, fn WalkFn) bool {
	node := t.root
	if node == nil {
		return true // empty tree
	}

	// Walk the tree and maintain the top pointer that points to the internal
	// node at the top of the subtree which contains exactly the subset of the
	// elements matching the given prefix.
	top := node
	for {
		if node.kind() != nodeKindInternal {
			break
		}
		nodeI := node.(*nodeInternal)
		node = nodeI.children[nodeI.direction(prefix)]
		// Since the crit-bit values are sorted, the wanted subtree can be
		// detected by checking for the crit-bit advancing beyond the length
		// of the prefix.
		if nodeI.index < len(prefix) {
			top = node
		}
	}

	// Check whether the prefix actually matches.
	nodeE := node.(*nodeExternal)
	if !bytes.HasPrefix(nodeE.key, prefix) {
		return true
	}

	// Traverse the subtree and call the function.
	return t.walkPrefixed(top, prefix, fn)
}

func (t *Tree) walkPrefixed(top iNode, prefix []byte, fn WalkFn) bool {
	switch n := top.(type) {
	case *nodeExternal:
		if !bytes.HasPrefix(n.key, prefix) {
			panic(fmt.Sprintf("wrongly matched node: key=%v, prefix=%v",
				n.key, prefix))
		}
		return fn(n.key, n.value)
	case *nodeInternal:
		if !t.walkPrefixed(n.children[0], prefix, fn) {
			return false // terminate
		}
		if !t.walkPrefixed(n.children[1], prefix, fn) {
			return false // terminate
		}
	}

	return true // continue
}

// Print the whole tree for debugging.
func (t *Tree) Dump(w io.Writer) {
	if t.root == nil {
		fmt.Fprintf(w, "(empty)\n")
		return
	}

	t.dump(w, t.root, false, "")
}

func (t *Tree) dump(w io.Writer, node iNode, right bool, prefix string) {
	mypreifx := prefix
	if right {
		mypreifx = prefix[:len(prefix)-1] + "`"
	}

	switch n := node.(type) {
	case *nodeExternal:
		fmt.Fprintf(w, "%s-- %s\n", mypreifx, n.dump())
	case *nodeInternal:
		fmt.Fprintf(w, "%s-- index=%d, otherBits=0b%08b(0x%02X)\n",
			mypreifx, n.index, n.otherBits, n.otherBits)
		t.dump(w, n.children[0], false, prefix+" |")
		t.dump(w, n.children[1], true, prefix+"  ")
	}
}
