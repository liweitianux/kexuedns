// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// DNS Trie - tests
//

package dnstrie

import (
	"bytes"
	"slices"
	"testing"
)

func TestKey1(t *testing.T) {
	items := []struct {
		name string
		key  string
		str  string
	}{
		{name: "", key: ".", str: ""},
		{name: ".", key: ".", str: ""},
		{name: "..", key: "..", str: "."},
		{name: "com", key: "moc.", str: "com"},
		{name: "com.", key: "moc.", str: "com"},
		{name: ".com", key: "moc..", str: ".com"},
		{name: ".com.", key: "moc..", str: ".com"},
		{name: "..com", key: "moc...", str: "..com"},
		{name: ".cOM", key: "moc..", str: ".com"},
		{name: "example.com", key: "moc.elpmaxe.", str: "example.com"},
		{name: "example.com.", key: "moc.elpmaxe.", str: "example.com"},
		{name: ".example.com", key: "moc.elpmaxe..", str: ".example.com"},
		{name: "ExamPle.com", key: "moc.elpmaxe.", str: "example.com"},
		{name: "123.ABC.com", key: "moc.cba.321.", str: "123.abc.com"},
		{name: "987.XYZ.com", key: "moc.zyx.789.", str: "987.xyz.com"},
		{name: "_-[].com", key: "moc.][-_.", str: "_-[].com"},
	}
	for _, item := range items {
		key := NewKey(item.name)
		if k := string(key); k != item.key {
			t.Errorf(`NewKey(%q) = %q; want %q`, item.name, k, item.key)
		}
		if s := key.String(); s != item.str {
			t.Errorf(`NewKey(%q).String() = %q; want %q`, item.name, s, item.str)
		}
	}
}

func TestZone1(t *testing.T) {
	trie := &DNSTrie{}
	zone := "abc.com"

	// Empty trie should just work.
	trie.DeleteZone(zone)
	if ok := trie.HasZone(zone); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone, ok)
	}

	trie.AddZone(zone)
	if ok := trie.HasZone(zone); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone, ok)
	}

	// Duplicate additions are ok.
	trie.AddZone(zone)
	if ok := trie.HasZone(zone); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone, ok)
	}

	trie.DeleteZone(zone)
	if ok := trie.HasZone(zone); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone, ok)
	}

	// Duplicate deletions are ok.
	trie.DeleteZone(zone)
	if ok := trie.HasZone(zone); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone, ok)
	}
}

func TestZone2(t *testing.T) {
	trie := &DNSTrie{}
	zone1 := "abc.com"
	zone2 := "xyz.com"

	trie.AddZone(zone1)
	if ok := trie.HasZone(zone1); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone1, ok)
	}
	if ok := trie.HasZone(zone2); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone2, ok)
	}

	trie.AddZone(zone2)
	if ok := trie.HasZone(zone1); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone1, ok)
	}
	if ok := trie.HasZone(zone2); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone2, ok)
	}

	trie.DeleteZone(zone1)
	if ok := trie.HasZone(zone1); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone1, ok)
	}
	if ok := trie.HasZone(zone2); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone2, ok)
	}
}

func TestMatch1(t *testing.T) {
	trie := &DNSTrie{}

	// Empty trie should just work.
	names := []string{"", ".", "com", "abc.com", "www.abc.com"}
	for _, name := range names {
		if key, ok := trie.Match(name); key != nil || ok {
			t.Errorf(`Match(%q) = (%q, %t); want (nil, false)`,
				name, key.String(), ok)
		}
	}
}

func TestMatch2(t *testing.T) {
	trie := &DNSTrie{}

	zones := []string{"com", "xyz.", "abc.com", "xyz.net"}
	for _, zone := range zones {
		trie.AddZone(zone)
	}

	items := []struct {
		name       string
		matchedKey Key
	}{
		{name: "", matchedKey: nil},
		{name: ".", matchedKey: nil},
		{name: "net", matchedKey: nil},
		{name: ".net", matchedKey: nil},
		{name: ".xyz", matchedKey: NewKey("xyz")},
		{name: ".org", matchedKey: nil},
		{name: "com", matchedKey: NewKey("com")},
		{name: "COM.", matchedKey: NewKey("com")},
		{name: ".com", matchedKey: NewKey("com")},
		{name: "cccom", matchedKey: nil},
		{name: ".cccom", matchedKey: nil},
		{name: "abc.net", matchedKey: nil},
		{name: ".abc.net", matchedKey: nil},
		{name: "xyz.com", matchedKey: NewKey("com")},
		{name: "XYZ.COM.", matchedKey: NewKey("com")},
		{name: ".XYZ.COM.", matchedKey: NewKey("com")},
		{name: "abcxyz.com", matchedKey: NewKey("com")},
		{name: "xyz.net", matchedKey: NewKey("xyz.net")},
		{name: "abcxyz.net", matchedKey: nil},
		{name: "abc.COM", matchedKey: NewKey("abc.com")},
		{name: "ABC.com.", matchedKey: NewKey("abc.com")},
		{name: "abcabc.com", matchedKey: NewKey("com")},
		{name: "www.abc.com.", matchedKey: NewKey("abc.com")},
		{name: "wwwxyz.abc.com", matchedKey: NewKey("abc.com")},
		{name: "xyz.WWW.abc.com.", matchedKey: NewKey("abc.com")},
	}
	for _, item := range items {
		expected := (item.matchedKey != nil)
		key, ok := trie.Match(item.name)
		if !bytes.Equal(item.matchedKey, key) || ok != expected {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, %t)`,
				item.name, key.String(), ok, item.matchedKey.String(), expected)
		}
	}
}

func TestExport(t *testing.T) {
	trie := &DNSTrie{}

	if zones := trie.Export(); len(zones) != 0 {
		t.Errorf(`Export() = %q; want []`, zones)
	}

	zones := []string{".", "com", "xyz.", "abc.com", "xyz.net", "www.abc.com"}
	zonesExpected := make([]string, len(zones))
	for i, z := range zones {
		zonesExpected[i] = NewKey(z).String()
		trie.AddZone(z)
	}

	zonesGot := trie.Export()
	t.Logf("Export() = %+v", zonesGot)

	if len(zonesGot) != len(zonesExpected) {
		t.Errorf(`Export() => %d zones; want %d`, len(zonesGot), len(zonesExpected))
	}

	slices.Sort(zonesGot)
	slices.Sort(zonesExpected)
	if !slices.Equal(zonesGot, zonesExpected) {
		t.Errorf(`Export() = %+v; want %+v`, zonesGot, zonesExpected)
	}
}
