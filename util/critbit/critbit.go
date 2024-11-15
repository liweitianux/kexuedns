// SPDX-License-Identifier: MIT
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
	keystr := string(n.key)
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

	return nil, true // inserted
}

// Insert the key (key) in the tree and associate it with the value (value).
// Return a boolean indicating whether the key has been inserted.
// If the key already exists, Insert() will not modify the tree and
// return false.
func (t *Tree) Insert(key []byte, value any) bool {
	_, ok := t.insert(key, value, false)
	return ok
}

// Set the key (key) in the tree and update its value if it exists.
// Return (nil, true) if the key didn't exist yet; otherwise, return the old
// value and false.
func (t *Tree) Set(key []byte, value any) (any, bool) {
	return t.insert(key, value, true)
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

	// Delete the nodes by updating the grandparent node.
	if whereq == nil {
		t.root = nil // tree only has one element
	} else {
		*whereq = nodeI.children[1-direction]
	}

	return nodeE.value, true
}

// Search for the longest prefix that matches the given string (s).
// Return the key and value of the matched node, and a boolean indicating
// whether there is a match.
func (t *Tree) LongestPrefix(s []byte) ([]byte, any, bool) {
	return t.longestPrefix(t.root, s)
}

// The keys in a crit-bit tree are lexicographically sorted, so the goal is to
// find the key that's:
//   - the largest one of those lexicographically less than or equal to the
//     given string (s);
//   - the prefix of the given string (s).
//
// It's possible to implement this without using recursion, but that would be
// much more complicated.
func (t *Tree) longestPrefix(node iNode, s []byte) ([]byte, any, bool) {
	if node == nil {
		return nil, nil, false
	}

	switch n := node.(type) {
	case *nodeExternal:
		if bytes.HasPrefix(s, n.key) {
			return n.key, n.value, true
		}
	case *nodeInternal:
		direction := n.direction(s)
		if k, v, ok := t.longestPrefix(n.children[direction], s); ok {
			return k, v, ok
		}
		// Also find the left subtree that's lexicographically smaller.
		if direction == 1 {
			return t.longestPrefix(n.children[0], s)
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
	return t.walk(t.root, fn)
}

func (t *Tree) walk(node iNode, fn WalkFn) bool {
	if node == nil {
		return true // continue
	}

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
		// detected by  checking for the crit-bit advancing beyond the length
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
	if top == nil {
		return true // continue
	}

	switch n := top.(type) {
	case *nodeExternal:
		if !bytes.HasPrefix(n.key, prefix) {
			panic("unmatched node")
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
		fmt.Fprintf(w, "(empty)")
		return
	}

	t.dump(w, t.root, false, "")
}

func (t *Tree) dump(w io.Writer, node iNode, right bool, prefix string) {
	if node == nil {
		return
	}

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
