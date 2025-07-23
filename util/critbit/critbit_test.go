// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Crit-bit Tree - tests
//

package critbit

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmpty1(t *testing.T) {
	tree := &Tree{}

	t.Run("get", func(t *testing.T) {
		v, ok := tree.Get([]byte("key"))
		if ok || v != nil {
			t.Errorf(`Get() = (%q, %t); want (nil, false)`, v, ok)
		}
	})

	t.Run("delete", func(t *testing.T) {
		v, ok := tree.Delete([]byte("key"))
		if ok || v != nil {
			t.Errorf(`Delete() = (%q, %t); want (nil, false)`, v, ok)
		}
	})

	t.Run("longest_prefix", func(t *testing.T) {
		k, v, ok := tree.LongestPrefix([]byte("key"))
		if ok || v != nil || len(k) != 0 {
			t.Errorf(`LongestPrefix() = (%q, %q, %t); want (nil, nil, false)`, k, v, ok)
		}
	})

	t.Run("walk", func(t *testing.T) {
		n := 0
		tree.Walk(func(key []byte, value any) bool { n++; return true })
		if n != 0 {
			t.Errorf(`Walk() = %d; want 0`, n)
		}
	})

	t.Run("walk_prefixed", func(t *testing.T) {
		n := 0
		tree.WalkPrefixed(
			[]byte("prefix"),
			func(key []byte, value any) bool { n++; return true },
		)
		if n != 0 {
			t.Errorf(`WalkPrefixed() = %d; want 0`, n)
		}
	})
}

func TestInsert1(t *testing.T) {
	tree := &Tree{}

	kvlist := []struct {
		key   string
		value int
	}{
		{key: "", value: 1},
		{key: "hello", value: 2},
		{key: "ho", value: 3},
		{key: "hoho", value: 4},
		{key: "yoho", value: 5},
		{key: "yoyo", value: 6},
	}

	// Inserting unique keys must return true.
	t.Run("insert_unique", func(t *testing.T) {
		for _, kv := range kvlist {
			ok := tree.Insert([]byte(kv.key), kv.value)
			if !ok {
				t.Errorf(`Insert(%q) = %t; want true`, kv.key, ok)
			}
		}
	})

	// Get back and check the value.
	t.Run("get1", func(t *testing.T) {
		for _, kv := range kvlist {
			v, ok := tree.Get([]byte(kv.key))
			if !ok || v != kv.value {
				t.Errorf(`Get(%q) = (%q, %t); want (%q, true)`,
					kv.key, v, ok, kv.value)
			}
		}
	})

	// Inserting duplicate keys must return false.
	t.Run("insert_duplicate", func(t *testing.T) {
		for _, kv := range kvlist {
			ok := tree.Insert([]byte(kv.key), int(42))
			if ok {
				t.Errorf(`Insert(%q) = %t; want false`, kv.key, ok)
			}
		}
	})

	// Inserting duplicate keys must not change original values.
	t.Run("get2", func(t *testing.T) {
		for _, kv := range kvlist {
			v, ok := tree.Get([]byte(kv.key))
			if !ok || v != kv.value {
				t.Errorf(`Get(%q) = (%q, %t); want (%q, true)`,
					kv.key, v, ok, kv.value)
			}
		}
	})
}

func TestSet1(t *testing.T) {
	tree := &Tree{}

	items := []struct {
		key       string
		value     int
		duplicate bool
		oldValue  int
	}{
		{key: "hello", value: 1},
		{key: "yo", value: 2},
		{key: "hello", value: 3, duplicate: true, oldValue: 1},
		{key: "hoho", value: 4},
		{key: "hoho", value: 5, duplicate: true, oldValue: 4},
	}
	for _, item := range items {
		old, ok := tree.Set([]byte(item.key), item.value)
		if item.duplicate {
			if ok || old != item.oldValue {
				t.Errorf(`Set(%q, %q) = (%q, %t); want (%q, false)`,
					item.key, item.value, old, ok, item.oldValue)
			}
		} else {
			if !ok || old != nil {
				t.Errorf(`Set(%q, %q) = (%q, %t); want (nil, true)`,
					item.key, item.value, old, ok)
			}
		}
	}

	kvlist := []struct {
		key   string
		value int
	}{
		{key: "hello", value: 3},
		{key: "yo", value: 2},
		{key: "hoho", value: 5},
	}
	for _, kv := range kvlist {
		v, ok := tree.Get([]byte(kv.key))
		if !ok || v != kv.value {
			t.Errorf(`Get(%q) = (%q, %t); want (%q, true)`, kv.key, v, ok, kv.value)
		}
	}
}

func TestDelete1(t *testing.T) {
	tree := &Tree{}
	kvlist := []struct {
		key   string
		value int
	}{
		{key: "hello", value: 2},
		{key: "ho", value: 3},
		{key: "hoho", value: 5},
	}
	for _, kv := range kvlist {
		tree.Insert([]byte(kv.key), kv.value)
	}

	key, value := "ho", int(3)

	t.Run("exist", func(t *testing.T) {
		v, ok := tree.Delete([]byte(key))
		if !ok || v != value {
			t.Errorf(`Delete(%q) = (%q, %t); want (%q, true)`, key, v, ok, value)
		}
	})

	t.Run("get", func(t *testing.T) {
		v, ok := tree.Get([]byte(key))
		if ok || v != nil {
			t.Errorf(`Get() = (%q, %t); want (nil, false)`, v, ok)
		}
	})

	t.Run("nonexist", func(t *testing.T) {
		v, ok := tree.Delete([]byte(key))
		if ok || v != nil {
			t.Errorf(`Delete(%q) = (%q, %t); want (nil, false)`, key, v, ok)
		}
	})
}

func TestLongestPrefix1(t *testing.T) {
	tree := &Tree{}
	tree.Insert([]byte(""), 1)

	keys := []string{"", "a", "abc", "xyz", "123"}
	for _, key := range keys {
		mk, mv, ok := tree.LongestPrefixR([]byte(key))
		if !ok || string(mk) != "" || mv != 1 {
			t.Errorf(`LongestPrefixR(%q) = (%q, %v, %t); want ("", 1, true)`,
				key, string(mk), mv, ok)
		}
		mk2, mv2, ok2 := tree.LongestPrefix([]byte(key))
		if !bytes.Equal(mk2, mk) || mv2 != mv || ok2 != ok {
			t.Errorf(`LongestPrefix(%q) = (%q, %v, %t); want (%q, %v, %t)`,
				key, string(mk2), mv2, ok2, string(mk), mv, ok)
		}
	}
}

func TestLongestPrefix2(t *testing.T) {
	tree := &Tree{}
	kvlist := []struct {
		key   string
		value int
	}{
		{key: "abc", value: 1},
		{key: "abc.def", value: 2},
		{key: "abc.def.ghi", value: 3},
		{key: "ABC.def", value: 4},
		{key: "xyz.123", value: 5},
		{key: "XYZ.123", value: 6},
	}
	for _, kv := range kvlist {
		tree.Insert([]byte(kv.key), kv.value)
	}

	items := []struct {
		key    string
		match  bool
		mKey   string
		mValue int
	}{
		{key: "a"},
		{key: "abc"},
		{key: "abcd"},
		{key: "abc.def123"},
		{key: "abc.def.ghi.12345"},
		{key: "abd"},
		{key: "ABC"},
	}
	// fill the reamining fields: match, mKey, mValue
	for i := range items {
		item := &items[i]
		for _, kv := range kvlist {
			if strings.HasPrefix(item.key, kv.key) {
				if !item.match {
					item.match = true
					item.mKey = kv.key
					item.mValue = kv.value
				} else if len(item.mKey) < len(kv.key) {
					item.mKey = kv.key
					item.mValue = kv.value
				}
			}
		}
	}
	t.Logf("items:\n%+v", items)

	for _, item := range items {
		mk, mv, ok := tree.LongestPrefixR([]byte(item.key))
		if item.match {
			if !ok || string(mk) != item.mKey || mv != item.mValue {
				t.Errorf(`LongestPrefixR(%q) = (%q, %v, %t); want (%q, %v, true)`,
					item.key, string(mk), mv, ok, item.mKey, item.mValue)
			}
		} else {
			if ok || len(mk) != 0 || mv != nil {
				t.Errorf(`LongestPrefixR(%q) = (%q, %v, %t); want (nil, nil, false)`,
					item.key, string(mk), mv, ok)
			}
		}
		mk2, mv2, ok2 := tree.LongestPrefix([]byte(item.key))
		if !bytes.Equal(mk2, mk) || mv2 != mv || ok2 != ok {
			t.Errorf(`LongestPrefix(%q) = (%q, %v, %t); want (%q, %v, %t)`,
				item.key, string(mk2), mv2, ok2, string(mk), mv, ok)
		}
	}
}

func TestWalk1(t *testing.T) {
	tree := &Tree{}
	kvlist := []struct {
		key   []byte
		value any
	}{
		{key: []byte(""), value: 1},
		{key: []byte("hello"), value: 2},
		{key: []byte("ho"), value: 3},
		{key: []byte("hoho"), value: 4},
		{key: []byte("yoho"), value: 5},
		{key: []byte("yoyo"), value: 6},
		{key: []byte{0x1, 0x2, 0x3}, value: "abc"},
	}
	for _, kv := range kvlist {
		tree.Insert(kv.key, kv.value)
	}

	t.Run("walk1", func(t *testing.T) {
		n := 0
		v := tree.Walk(func(key []byte, value any) bool {
			n++
			return true
		})
		if n != len(kvlist) {
			t.Errorf(`Walked %d nodes; want %d`, n, len(kvlist))
		}
		if !v {
			t.Errorf(`Walk() = %t; want true`, v)
		}
	})

	t.Run("walk2", func(t *testing.T) {
		n := 0
		v := tree.Walk(func(key []byte, value any) bool {
			n++
			return n <= 3 // terminate the walk if n > 3
		})
		if n <= 3 {
			t.Errorf(`Walked %d nodes; want >%d`, n, 3)
		}
		if v {
			t.Errorf(`Walk() = %t; want false`, v)
		}
	})

	t.Run("walk_prefixed1", func(t *testing.T) {
		prefix := []byte("")
		c := 0
		for _, kv := range kvlist {
			if bytes.HasPrefix(kv.key, prefix) {
				c++
			}
		}

		n := 0
		tree.WalkPrefixed(
			prefix,
			func(key []byte, value any) bool { n++; return true },
		)
		if n != c {
			t.Errorf(`Walked %d nodes; want %d`, n, c)
		}
	})

	t.Run("walk_prefixed2", func(t *testing.T) {
		prefix := []byte("ho")
		c := 0
		for _, kv := range kvlist {
			if bytes.HasPrefix(kv.key, prefix) {
				c++
			}
		}

		n := 0
		tree.WalkPrefixed(
			prefix,
			func(key []byte, value any) bool { n++; return true },
		)
		if n != c {
			t.Errorf(`Walked %d nodes; want %d`, n, c)
		}
	})

	t.Run("walk_prefixed3", func(t *testing.T) {
		prefix := []byte("hohoho")
		c := 0
		for _, kv := range kvlist {
			if bytes.HasPrefix(kv.key, prefix) {
				c++
			}
		}

		n := 0
		tree.WalkPrefixed(
			prefix,
			func(key []byte, value any) bool { n++; return true },
		)
		if n != c {
			t.Errorf(`Walked %d nodes; want %d`, n, c)
		}
	})

	t.Run("walk_prefixed4", func(t *testing.T) {
		prefix := []byte{0x1, 0x2}
		c := 0
		for _, kv := range kvlist {
			if bytes.HasPrefix(kv.key, prefix) {
				c++
			}
		}

		n := 0
		tree.WalkPrefixed(
			prefix,
			func(key []byte, value any) bool { n++; return true },
		)
		if n != c {
			t.Errorf(`Walked %d nodes; want %d`, n, c)
		}
	})

	t.Run("walk_prefixed5", func(t *testing.T) {
		prefix := []byte{0xA, 0xB, 0xC}
		c := 0
		for _, kv := range kvlist {
			if bytes.HasPrefix(kv.key, prefix) {
				c++
			}
		}

		n := 0
		tree.WalkPrefixed(
			prefix,
			func(key []byte, value any) bool { n++; return true },
		)
		if n != c {
			t.Errorf(`Walked %d nodes; want %d`, n, c)
		}
	})
}

func TestDump1(t *testing.T) {
	tree := &Tree{}

	buf := &bytes.Buffer{}
	tree.Dump(buf)
	t.Logf("dump:\n%s", buf.String())

	kvlist := []struct {
		key   []byte
		value any
	}{
		{key: []byte(""), value: 1},
		{key: []byte("hello"), value: 2},
		{key: []byte("ho"), value: 3},
		{key: []byte("hoho"), value: 4},
		{key: []byte("yoho"), value: 5},
		{key: []byte("yoyo"), value: 6},
		{key: []byte{0x1, 0x2, 0x3}, value: "abc"},
	}
	for _, kv := range kvlist {
		tree.Insert(kv.key, kv.value)
	}

	buf.Reset()
	tree.Dump(buf)
	t.Logf("dump:\n%s", buf.String())
}
