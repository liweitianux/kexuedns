// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025-2026 Aaron LI
//
// DNS message - tests
//

package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestRawMsg1(t *testing.T) {
	qid := uint16(0x1234)
	qtype := dnsmessage.TypeA
	qname := "www.example.com."
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: qid},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(qname),
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	buf, _ := msg.Pack()
	rmsg := RawMsg(buf)

	if id := rmsg.GetID(); id != qid {
		t.Errorf(`GetID() = 0x%x; want 0x%x`, id, qid)
	}

	sessionKey := fmt.Sprintf("%d:%s:%s", qid, qtype, qname)
	if skey, err := rmsg.SessionKey(); err != nil || skey != sessionKey {
		t.Errorf(`SessionKey() = (%q, %v); want (%q, nil)`,
			skey, err, sessionKey)
	}

	qid = uint16(0x4321)
	rmsg.SetID(qid)
	if id := rmsg.GetID(); id != qid {
		t.Errorf(`GetID() = 0x%x; want 0x%x`, id, qid)
	}
}

func TestQueryMsg1(t *testing.T) {
	// Nil message must not panic.
	if q, err := NewQueryMsg(nil); q != nil || err == nil {
		t.Errorf(`NewQueryMsg(nil) = (%v, %v); want (nil, !nil)`, q, err)
	}

	// Too short message must not panic.
	msg := []byte{0x1, 0x2, 0x3, 0x4}
	if q, err := NewQueryMsg(msg); q != nil || err == nil {
		t.Errorf(`NewQueryMsg(1) = (%v, %v); want (nil, !nil)`, q, err)
	}

	// Header only message
	dmsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1234},
	}
	msg, _ = dmsg.Pack()
	if q, err := NewQueryMsg(msg); q != nil || err == nil {
		t.Errorf(`NewQueryMsg(2) = (%v, %v); want (nil, !nil)`, q, err)
	}
}

func TestQueryMsg2(t *testing.T) {
	qid := uint16(0x1234)
	qtype := dnsmessage.TypeA
	qname := "www.example.com."
	dmsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: qid},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(qname),
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	msg, _ := dmsg.Pack()

	q, err := NewQueryMsg(msg)
	if q == nil || err != nil {
		t.Errorf(`NewQueryMsg() = (%v, %v); want (!nil, nil)`, q, err)
	}

	sessionKey := fmt.Sprintf("%d:%s:%s", qid, qtype, qname)
	if skey := q.SessionKey(); skey != sessionKey {
		t.Errorf(`SessionKey() = %q; want %q`, skey, sessionKey)
	}
}

func TestQueryMsg3(t *testing.T) {
	resOPT1 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeOPT,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.OPTResource{
			Options: []dnsmessage.Option{
				{
					Code: 1,
					Data: []byte{1, 2, 3},
				},
			},
		},
	}
	resOPT2 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeOPT,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.OPTResource{
			Options: []dnsmessage.Option{
				{
					Code: 2,
					Data: []byte{3, 2, 1},
				},
				{
					Code: 8,
					Data: []byte{0, 1, 0, 1, 0, 1},
				},
			},
		},
	}
	resA1 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("www.example.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.AResource{
			A: [4]byte{1, 2, 3, 4},
		},
	}
	resTXT1 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("www.example.com."),
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.TXTResource{
			TXT: []string{"hello", "world"},
		},
	}

	header := dnsmessage.Header{ID: uint16(0x1234)}
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	tests := []struct {
		dmsg     *dnsmessage.Message
		optOpLen int
	}{
		{
			dmsg: &dnsmessage.Message{
				Header:    header,
				Questions: []dnsmessage.Question{question},
			},
			optOpLen: 0,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resOPT1},
			},
			optOpLen: 1,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resOPT1, resOPT2},
			},
			optOpLen: 1,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resOPT2, resOPT1},
			},
			optOpLen: 2,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resA1},
			},
			optOpLen: 0,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resA1, resTXT1},
			},
			optOpLen: 0,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resA1, resOPT1},
			},
			optOpLen: 1,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resOPT1, resTXT1},
			},
			optOpLen: 1,
		},
		{
			dmsg: &dnsmessage.Message{
				Header:      header,
				Questions:   []dnsmessage.Question{question},
				Additionals: []dnsmessage.Resource{resA1, resOPT2, resTXT1},
			},
			optOpLen: 2,
		},
	}

	for i, tc := range tests {
		msg, _ := tc.dmsg.Pack()
		q, err := NewQueryMsg(msg)
		if q == nil || err != nil {
			t.Errorf(`[%d] NewQueryMsg() = (%v, %v); want (!nil, nil)`, i, q, err)
		}
		if oplen := tc.optOpLen; oplen == 0 {
			if q.OPT.Header != nil {
				t.Errorf(`[%d] OPT.Header = %v; want nil`, i, q.OPT.Header)
			}
			if l := len(q.OPT.Options); l != 0 {
				t.Errorf(`[%d] len(OPT.Options) = %d; want 0`, i, l)
			}
		} else {
			if q.OPT.Header == nil {
				t.Errorf(`[%d] OPT.Header = nil; want !nil`, i)
			}
			if l := len(q.OPT.Options); l != oplen {
				t.Errorf(`[%d] len(OPT.Options) = %d; want %d`, i, l, oplen)
			}
		}
	}
}

func TestQueryMsg4(t *testing.T) {
	// Invalid packet and has a bogus RR body length.
	msg := []byte{69, 103, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 107, 112, 109, 103, 3, 99, 111, 109, 0, 0, 255, 0, 1, 0, 0, 41, 255, 255, 0, 0, 0, 0, 0, 0}

	var m dnsmessage.Message
	if err := m.Unpack(msg); err == nil {
		t.Errorf(`dnsmessage.Message.Unpack() = ni; want error`)
	}

	if _, err := NewQueryMsg(msg); err == nil {
		t.Errorf(`NewQueryMsg() = ni; want error`)
	}
}

func TestSetEdnsSubnet1(t *testing.T) {
	qmsg := &QueryMsg{
		Header: dnsmessage.Header{ID: uint16(0x1234)},
		Question: dnsmessage.Question{
			Name:  dnsmessage.MustNewName("www.example.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		},
		// OPT: empty
	}
	if _, err := qmsg.Build(); err != nil {
		t.Errorf(`QueryMsg.Build() failed: %v`, err)
	}

	newIP := func(s string) *netip.Addr {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			panic(err)
		}
		return &addr
	}

	tests := []struct {
		ip       *netip.Addr
		plen     int
		expected string
	}{
		{ip: nil, plen: 0, expected: ""},
		{ip: newIP("1.2.3.4"), plen: 0, expected: "1.2.3.0/24"},
		{ip: newIP("1.2.3.4"), plen: 24, expected: "1.2.3.0/24"},
		{ip: newIP("1.2.3.4"), plen: 32, expected: "1.2.3.4/32"},
		{ip: newIP("1.2.3.4"), plen: 16, expected: "1.2.0.0/16"},
		{ip: newIP("1.2.255.0"), plen: 20, expected: "1.2.240.0/20"},
		{ip: newIP("fd00:11:22:33:1:2:3:4"), plen: 0, expected: "fd00:11:22::/56"},
		{ip: newIP("fd00:11:22:33:1:2:3:4"), plen: 64, expected: "fd00:11:22:33::/64"},
		{ip: newIP("fd00:11:22:33:1:2:3:4"), plen: 80, expected: "fd00:11:22:33:1::/80"},
		{ip: newIP("fd00:11:22:33:1:2:3:4"), plen: 128, expected: "fd00:11:22:33:1:2:3:4/128"},
	}
	for _, tc := range tests {
		if tc.ip != nil {
			err := qmsg.SetEdnsSubnet(*tc.ip, tc.plen)
			if err != nil {
				t.Errorf(`QueryMsg.SetEdnsSubnet() failed: %v`, err)
			}
		}
		if msg, err := qmsg.Build(); err != nil {
			t.Errorf(`QueryMsg.Build() failed: %v`, err)
		} else {
			ecs, err := getEdnsSubnet(msg)
			if err != nil || ecs != tc.expected {
				t.Errorf(`QueryMsg.SetEdnsSubnet() => ECS (%q, %v); want %q`,
					ecs, err, tc.expected)
			}
		}
	}
}

func getEdnsSubnet(msg []byte) (string, error) {
	var dmsg dnsmessage.Message
	if err := dmsg.Unpack(msg); err != nil {
		return "", err
	}

	var opECS *dnsmessage.Option
	for _, r := range dmsg.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			options := r.Body.(*dnsmessage.OPTResource).Options
			for i := 0; i < len(options); i++ {
				if options[i].Code == optionCodeSubnet {
					opECS = &options[i]
					break
				}
			}
		}
		if opECS != nil {
			break
		}
	}
	if opECS == nil {
		return "", nil
	}

	ecsData := opECS.Data
	if len(ecsData) < 4 {
		return "", errors.New("invalid ECS data")
	}

	family := binary.BigEndian.Uint16(ecsData)
	sourcePlen := int(ecsData[2])

	var addr netip.Addr
	switch family {
	case uint16(1): // IPv4
		var ip [4]byte
		copy(ip[:], ecsData[4:])
		addr = netip.AddrFrom4(ip)
	case uint16(2): // IPv6
		var ip [16]byte
		copy(ip[:], ecsData[4:])
		addr = netip.AddrFrom16(ip)
	default:
		return "", fmt.Errorf("invalid ECS family (%d)", family)
	}

	ecs := fmt.Sprintf("%s/%d", addr.String(), sourcePlen)
	return ecs, nil
}
