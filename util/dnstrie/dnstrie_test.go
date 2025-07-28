// SPDX-License-Identifier: MIT
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
		{name: "", key: ".", str: "."},
		{name: ".", key: ".", str: "."},
		{name: "com", key: ".moc", str: "com."},
		{name: ".com", key: ".moc.", str: ".com."},
		{name: ".cOM", key: ".moc.", str: ".com."},
		{name: "example.com", key: ".moc.elpmaxe", str: "example.com."},
		{name: "ExamPle.com", key: ".moc.elpmaxe", str: "example.com."},
		{name: "123.ABC.com", key: ".moc.cba.321", str: "123.abc.com."},
		{name: "987.XYZ.com", key: ".moc.zyx.789", str: "987.xyz.com."},
		{name: "_-[].com", key: ".moc.][-_", str: "_-[].com."},
	}
	for _, item := range items {
		key := NewKey(item.name)
		t.Logf(`NewKey(%q) = %q (%q)`, item.name, string(key), key.String())
		if k := string(key); k != item.key {
			t.Errorf(`NewKey(%q) = %q; want %q`, item.name, k, item.key)
		}
		if s := key.String(); s != item.str {
			t.Errorf(`NewKey(%q).String() = %q; want %q`, item.name, s, item.str)
		}
	}
}

func TestName1(t *testing.T) {
	trie := &DNSTrie{}
	name := "www.abc.com"

	// Empty trie should just work.
	trie.DeleteName(name)
	trie.DeleteZone(name)
	if ok := trie.HasName(name); ok {
		t.Errorf(`HasName(%q) = %t; want false`, name, ok)
	}
	if ok := trie.HasZone(name); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, name, ok)
	}

	trie.AddName(name)
	if ok := trie.HasName(name); !ok {
		t.Errorf(`HasName(%q) = %t; want true`, name, ok)
	}
	if ok := trie.HasZone(name); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, name, ok)
	}

	// Duplicate additions are ok.
	trie.AddName(name)

	trie.DeleteName(name)
	if ok := trie.HasName(name); ok {
		t.Errorf(`HasName(%q) = %t; want false`, name, ok)
	}

	// Duplicate deletions are ok.
	trie.DeleteName(name)
}

func TestName2(t *testing.T) {
	trie := &DNSTrie{}
	name1 := "www.abc.com"
	name2 := "xyz.abc.com"

	trie.AddName(name1)
	if ok := trie.HasName(name1); !ok {
		t.Errorf(`HasName(%q) = %t; want true`, name1, ok)
	}
	if ok := trie.HasName(name2); ok {
		t.Errorf(`HasName(%q) = %t; want false`, name2, ok)
	}
}

func TestZone1(t *testing.T) {
	trie := &DNSTrie{}
	zone := "abc.com"

	// Empty trie should just work.
	trie.DeleteZone(zone)
	trie.DeleteName(zone)
	if ok := trie.HasName(zone); ok {
		t.Errorf(`HasName(%q) = %t; want false`, zone, ok)
	}
	if ok := trie.HasZone(zone); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone, ok)
	}

	trie.AddZone(zone)
	if ok := trie.HasZone(zone); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone, ok)
	}
	if ok := trie.HasName(zone); ok {
		t.Errorf(`HasName(%q) = %t; want false`, zone, ok)
	}

	// Duplicate additions are ok.
	trie.AddZone(zone)

	trie.DeleteZone(zone)
	if ok := trie.HasZone(zone); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone, ok)
	}

	// Duplicate deletions are ok.
	trie.DeleteZone(zone)
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
}

func TestAdd1(t *testing.T) {
	trie := &DNSTrie{}

	name := "www.abc.com"
	zone := "abc.com"
	trie.AddName(name)
	trie.AddZone(zone)

	if ok := trie.HasName(name); !ok {
		t.Errorf(`HasName(%q) = %t; want true`, name, ok)
	}
	if ok := trie.HasZone(zone); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone, ok)
	}

	if ok := trie.HasName(zone); ok {
		t.Errorf(`HasName(%q) = %t; want true`, zone, ok)
	}
	if ok := trie.HasZone(name); ok {
		t.Errorf(`HasZone(%q) = %t; want true`, name, ok)
	}

	trie.DeleteName(zone)
	trie.DeleteZone(name)
	if ok := trie.HasName(name); !ok {
		t.Errorf(`HasName(%q) = %t; want true`, name, ok)
	}
	if ok := trie.HasZone(zone); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, zone, ok)
	}

	trie.DeleteName(name)
	trie.DeleteZone(zone)
	if ok := trie.HasName(name); ok {
		t.Errorf(`HasName(%q) = %t; want false`, name, ok)
	}
	if ok := trie.HasZone(zone); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, zone, ok)
	}
}

func TestAdd2(t *testing.T) {
	trie := &DNSTrie{}

	name := "abc.com"
	trie.AddName(name)
	trie.AddZone(name)

	if ok := trie.HasName(name); !ok {
		t.Errorf(`HasName(%q) = %t; want true`, name, ok)
	}
	if ok := trie.HasZone(name); !ok {
		t.Errorf(`HasZone(%q) = %t; want true`, name, ok)
	}

	trie.DeleteZone(name)
	if ok := trie.HasName(name); !ok {
		t.Errorf(`HasName(%q) = %t; want true`, name, ok)
	}
	if ok := trie.HasZone(name); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, name, ok)
	}

	trie.DeleteName(name)
	if ok := trie.HasName(name); ok {
		t.Errorf(`HasName(%q) = %t; want false`, name, ok)
	}
	if ok := trie.HasZone(name); ok {
		t.Errorf(`HasZone(%q) = %t; want false`, name, ok)
	}
}

func TestAdd3(t *testing.T) {
	trie := &DNSTrie{}

	name := "abc.com"
	trie.AddName(name)
	trie.AddZone(name)

	names := []string{"ABC.com", "abc.com.", "abc.COM"}
	for _, name := range names {
		if ok := trie.HasName(name); !ok {
			t.Errorf(`HasName(%q) = %t; want true`, name, ok)
		}
		if ok := trie.HasZone(name); !ok {
			t.Errorf(`HasZone(%q) = %t; want true`, name, ok)
		}
	}

	names = []string{".", "com", ".abc.com", "abc.net", "xyz.abc.com"}
	for _, name := range names {
		if ok := trie.HasName(name); ok {
			t.Errorf(`HasName(%q) = %t; want false`, name, ok)
		}
		if ok := trie.HasZone(name); ok {
			t.Errorf(`HasZone(%q) = %t; want false`, name, ok)
		}
	}
}

func TestMatch1(t *testing.T) {
	trie := &DNSTrie{}

	// Empty trie should just work.
	names := []string{"", "abc.com", "www.abc.com"}
	for _, name := range names {
		if key, exact := trie.Match(name); key != nil || exact {
			t.Errorf(`Match(%q) = (%q, %t); want (nil, false)`,
				name, key.String(), exact)
		}
	}
}

func TestMatch2(t *testing.T) {
	trie := &DNSTrie{}

	names := []string{"", "com.", "abc.com.", "www.abc.com"}
	for _, name := range names {
		trie.AddName(name)
	}

	for _, name := range names {
		if key, exact := trie.Match(name); key == nil || !exact {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, true)`,
				name, key.String(), exact, name)
		}
	}

	names = []string{".", "COM", "Com.", "ABC.com", "WWW.abc.com."}
	for _, name := range names {
		if key, exact := trie.Match(name); key == nil || !exact {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, true)`,
				name, key.String(), exact, name)
		}
	}

	names = []string{"net", "example.com", "abcd.com", "bc.com", "ww.abc.com"}
	for _, name := range names {
		if key, exact := trie.Match(name); key != nil || exact {
			t.Errorf(`Match(%q) = (%q, %t); want (nil, false)`,
				name, key.String(), exact)
		}
	}

	names = []string{"com", "www.abc.com"}
	for _, name := range names {
		trie.DeleteName(name)
	}

	names = []string{"com.", "COM", "www.ABC.COM.", "WWW.abc.com"}
	for _, name := range names {
		if key, exact := trie.Match(name); key != nil || exact {
			t.Errorf(`Match(%q) = (%q, %t); want (nil, false)`,
				name, key.String(), exact)
		}
	}
}

func TestMatch3(t *testing.T) {
	trie := &DNSTrie{}

	zones := []string{"com", "abc.com"}
	for _, zone := range zones {
		trie.AddZone(zone)
	}

	items := []struct {
		name       string
		matchedKey Key
	}{
		{name: "", matchedKey: nil},
		{name: "net", matchedKey: nil},
		{name: ".net", matchedKey: nil},
		{name: "abc.net", matchedKey: nil},
		{name: "com", matchedKey: NewKey("com.")},
		{name: "COM.", matchedKey: NewKey("com.")},
		{name: "xyz.com", matchedKey: NewKey("com.")},
		{name: "XYZ.COM.", matchedKey: NewKey("com.")},
		{name: "abc.COM", matchedKey: NewKey("abc.com.")},
		{name: "ABC.com.", matchedKey: NewKey("abc.com.")},
		{name: "www.abc.com.", matchedKey: NewKey("abc.com.")},
		{name: "xyz.WWW.abc.com.", matchedKey: NewKey("abc.com.")},
	}
	for _, item := range items {
		key, exact := trie.Match(item.name)
		if !key.Equal(item.matchedKey) || exact {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, false)`,
				item.name, key.String(), exact, item.matchedKey.String())
		}
	}

	trie.AddZone(".")
	matchedKey := NewKey(".")
	for _, item := range items {
		if item.matchedKey != nil {
			continue
		}
		key, exact := trie.Match(item.name)
		if !key.Equal(matchedKey) || exact {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, false)`,
				item.name, key.String(), exact, matchedKey.String())
		}
	}

	trie.DeleteZone("com.")
	zoneKey := NewKey("com.")
	for _, item := range items {
		if !item.matchedKey.Equal(zoneKey) {
			continue
		}
		key, exact := trie.Match(item.name)
		if !key.Equal(matchedKey) || exact {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, false)`,
				item.name, key.String(), exact, matchedKey.String())
		}
	}
}

func TestMatch4(t *testing.T) {
	trie := &DNSTrie{}

	name := "abc.com"
	trie.AddName(name)
	trie.AddZone(name)

	items := []struct {
		name       string
		matchedKey Key
		exact      bool
	}{
		{name: "", matchedKey: nil},
		{name: "net", matchedKey: nil},
		{name: "com", matchedKey: nil},
		{name: "abc.net", matchedKey: nil},
		{name: "abc.com", matchedKey: NewKey("abc.com."), exact: true},
		{name: "ABC.com.", matchedKey: NewKey("abc.com."), exact: true},
		{name: "www.abc.com.", matchedKey: NewKey("abc.com."), exact: false},
		{name: "xyz.WWW.abc.com.", matchedKey: NewKey("abc.com."), exact: false},
	}
	for _, item := range items {
		key, exact := trie.Match(item.name)
		if !key.Equal(item.matchedKey) || exact != item.exact {
			t.Errorf(`Match(%q) = (%q, %t); want (%q, %t)`,
				item.name, key.String(), exact, item.matchedKey.String(), item.exact)
		}
	}
}
