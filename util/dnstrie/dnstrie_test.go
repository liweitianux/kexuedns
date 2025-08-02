// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// DNS Trie - tests
//

package dnstrie

import (
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
	value1, value2 := 42, 43

	// Empty trie should just work.
	if v, deleted := trie.DeleteZone(zone); v != nil || deleted {
		t.Errorf(`DeleteZone(%q) = (%v, %t); want (nil, false)`, zone, v, deleted)
	}
	if v, ok := trie.GetZone(zone); v != nil || ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (nil, false)`, zone, v, ok)
	}

	if v, updated := trie.AddZone(zone, value1); v != nil || updated {
		t.Errorf(`AddZone(%q) = (%v, %t); want (nil, false)`, zone, v, updated)
	}
	if v, ok := trie.GetZone(zone); v == nil || !ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (%q, true)`, zone, v, ok, value1)
	}

	// Duplicate additions are ok.
	if v, updated := trie.AddZone(zone, value2); v != value1 || !updated {
		t.Errorf(`AddZone(%q) = (%v, %t); want (%v, true)`, zone, v, updated, value1)
	}
	if v, ok := trie.GetZone(zone); v == nil || !ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (%q, true)`, zone, v, ok, value2)
	}

	if v, deleted := trie.DeleteZone(zone); v == nil || !deleted {
		t.Errorf(`DeleteZone(%q) = (%v, %t); want (%q, true)`, zone, v, deleted, value2)
	}
	if v, ok := trie.GetZone(zone); v != nil || ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (nil, false)`, zone, v, ok)
	}

	// Duplicate deletions are ok.
	if v, deleted := trie.DeleteZone(zone); v != nil || deleted {
		t.Errorf(`DeleteZone(%q) = (%v, %t); want (nil, false)`, zone, v, deleted)
	}
	if v, ok := trie.GetZone(zone); v != nil || ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (nil, false)`, zone, v, ok)
	}
}

func TestZone2(t *testing.T) {
	trie := &DNSTrie{}
	zone1, value1 := "abc.com", 42
	zone2, value2 := "xyz.com", 43

	if v, updated := trie.AddZone(zone1, value1); v != nil || updated {
		t.Errorf(`AddZone(%q) = (%v, %t); want (nil, false)`, zone1, v, updated)
	}
	if v, ok := trie.GetZone(zone1); v == nil || !ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (%q, true)`, zone1, v, ok, value1)
	}
	if v, ok := trie.GetZone(zone2); v != nil || ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (nil, false)`, zone2, v, ok)
	}

	if v, updated := trie.AddZone(zone2, value2); v != nil || updated {
		t.Errorf(`AddZone(%q) = (%v, %t); want (nil, false)`, zone2, v, updated)
	}
	if v, ok := trie.GetZone(zone1); v == nil || !ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (%q, true)`, zone1, v, ok, value1)
	}
	if v, ok := trie.GetZone(zone2); v == nil || !ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (%q, true)`, zone2, v, ok, value2)
	}

	if v, deleted := trie.DeleteZone(zone1); v == nil || !deleted {
		t.Errorf(`DeleteZone(%q) = (%v, %t); want (%q, true)`, zone1, v, deleted, value1)
	}
	if v, ok := trie.GetZone(zone1); v != nil || ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (nil, false)`, zone1, v, ok)
	}
	if v, ok := trie.GetZone(zone2); v == nil || !ok {
		t.Errorf(`GetZone(%q) = (%v, %t); want (%q, true)`, zone2, v, ok, value2)
	}
}

func TestMatch1(t *testing.T) {
	trie := &DNSTrie{}

	// Empty trie should just work.
	names := []string{"", ".", "com", "abc.com", "www.abc.com"}
	for _, name := range names {
		if v, ok := trie.Match(name); v != nil || ok {
			t.Errorf(`Match(%q) = (%v, %t); want (nil, false)`, name, v, ok)
		}
	}
}

func TestMatch2(t *testing.T) {
	trie := &DNSTrie{}

	zones := []struct {
		name  string
		value int
	}{
		{name: "com", value: 1},
		{name: "xyz.", value: 2},
		{name: "abc.com", value: 3},
		{name: "xyz.net", value: 4},
	}
	for _, z := range zones {
		trie.AddZone(z.name, z.value)
	}

	items := []struct {
		name    string
		matched bool
		value   int
	}{
		{name: "", matched: false},
		{name: ".", matched: false},
		{name: "net", matched: false},
		{name: ".net", matched: false},
		{name: ".xyz", matched: true, value: 2},
		{name: ".org", matched: false},
		{name: "com", matched: true, value: 1},
		{name: "COM.", matched: true, value: 1},
		{name: ".com", matched: true, value: 1},
		{name: "cccom", matched: false},
		{name: ".cccom", matched: false},
		{name: "abc.net", matched: false},
		{name: ".abc.net", matched: false},
		{name: "xyz.com", matched: true, value: 1},
		{name: "XYZ.COM.", matched: true, value: 1},
		{name: ".XYZ.COM.", matched: true, value: 1},
		{name: "abcxyz.com", matched: true, value: 1},
		{name: "xyz.net", matched: true, value: 4},
		{name: "abcxyz.net", matched: false},
		{name: "abc.COM", matched: true, value: 3},
		{name: "ABC.com.", matched: true, value: 3},
		{name: "abcabc.com", matched: true, value: 1},
		{name: "www.abc.com.", matched: true, value: 3},
		{name: "wwwxyz.abc.com", matched: true, value: 3},
		{name: "xyz.WWW.abc.com.", matched: true, value: 3},
	}
	for _, item := range items {
		v, ok := trie.Match(item.name)
		if item.matched {
			if !ok || v != item.value {
				t.Errorf(`Match(%q) = (%v, %t); want (%v, true)`,
					item.name, v, ok, item.value)
			}
		} else {
			if ok || v != nil {
				t.Errorf(`Match(%q) = (%v, %t); want (nil, false)`,
					item.name, v, ok)
			}
		}
	}
}

func TestExport(t *testing.T) {
	trie := &DNSTrie{}

	if zones := trie.Export(); len(zones) != 0 {
		t.Errorf(`Export() = %q; want []`, zones)
	}

	zones := []struct {
		name  string
		value int
	}{
		{name: ".", value: 1},
		{name: "Com", value: 2},
		{name: "xyz.", value: 3},
		{name: "ABC.com", value: 4},
		{name: "xyz.net", value: 5},
		{name: "www.ABC.com", value: 6},
	}
	for _, z := range zones {
		trie.AddZone(z.name, z.value)
	}

	zonesGot := trie.Export()
	t.Logf("Export() = %+v", zonesGot)
	if len(zonesGot) != len(zones) {
		t.Errorf(`Export() => %d zones; want %d`, len(zonesGot), len(zones))
	}

	for _, z := range zones {
		v, ok := zonesGot[z.name]
		if !ok {
			t.Errorf(`Export() missing zone %q`, z.name)
		} else if v != z.value {
			t.Errorf(`Export() zone %q wrong value %v; want %v`, z.name, v, z.value)
		}
	}
}
