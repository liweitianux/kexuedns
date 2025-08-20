package dnsmsg

import (
	"fmt"
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

// TODO: SetEdnsSubnet()
