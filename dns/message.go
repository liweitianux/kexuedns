// SPDX-License-Identifier: MIT
//
// DNS message parsing and manipulations.
//

package dns

import (
	"encoding/binary"
	"errors"
	"net"

	"golang.org/x/net/dns/dnsmessage"

	"kexuedns/log"
)

const (
	// UDP payload size. EDNS(0), RFC 6891
	maxPayloadSize = 1232

	// EDNS client subnet, RFC 7871
	// Option code for client subnet.
	optionCodeSubnet = 8
	// Default source prefix length for IPv4 and IPv6.
	ipv4PrefixLength = 24
	ipv6PrefixLength = 56
)

type QueryMsg struct {
	Header   dnsmessage.Header
	Question dnsmessage.Question
	// EDNS pseudo resource
	OPT struct {
		Header  *dnsmessage.ResourceHeader
		Options []dnsmessage.Option
	}
}

func ParseQuery(msg []byte) (*QueryMsg, error) {
	qmsg := &QueryMsg{}

	var err error
	var p dnsmessage.Parser

	qmsg.Header, err = p.Start(msg)
	if err != nil {
		log.Errorf("failed to parse message: %v", err)
		return nil, err
	}

	// Parse the question section.
	qmsg.Question, err = p.Question()
	if err != nil {
		log.Errorf("failed to parse question: %v", err)
		return nil, err
	}
	// Ignore possible other questions.
	err = p.SkipAllQuestions()
	if err != nil {
		log.Errorf("failed to skip questions: %v", err)
		return nil, err
	}

	// Skip answer and authority sections.
	err = p.SkipAllAnswers()
	if err != nil {
		log.Errorf("failed to skip answers: %v", err)
		return nil, err
	}
	err = p.SkipAllAuthorities()
	if err != nil {
		log.Errorf("failed to skip authorities: %v", err)
		return nil, err
	}

	// Finally check for EDNS.
	for {
		h, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			log.Errorf("failed to parse additional header: %v", err)
			return nil, err
		}
		if h.Type != dnsmessage.TypeOPT {
			continue
		}

		r, err := p.OPTResource()
		if err != nil {
			log.Errorf("failed to parse OPT resource: %v", err)
			return nil, err
		}

		qmsg.OPT.Header = &h
		qmsg.OPT.Options = r.Options
	}

	return qmsg, nil
}

func (m *QueryMsg) SetEdnsSubnet(ip net.IP, prefixLen int) error {
	rh := dnsmessage.ResourceHeader{}
	err := rh.SetEDNS0(maxPayloadSize, dnsmessage.RCodeSuccess, false)
	if err != nil {
		log.Errorf("failed to set EDNS0 for header")
		return err
	}
	if m.OPT.Header != nil {
		log.Debugf("overriding existing EDNS header")
	}
	m.OPT.Header = &rh

	// Client Subnet (RFC 7871)
	family := uint16(0)
	address := []byte{}
	if ip.To4() != nil {
		family = uint16(1)
		if prefixLen <= 0 || prefixLen > 32 {
			prefixLen = ipv4PrefixLength
		}
		mask := net.CIDRMask(prefixLen, 32)
		ip4 := ip.Mask(mask).To4() // to 4-byte representation
		address = []byte(ip4)[:((prefixLen + 7) / 8)]
	} else if ip.To16() != nil {
		family = uint16(2)
		if prefixLen <= 0 || prefixLen > 128 {
			prefixLen = ipv6PrefixLength
		}
		mask := net.CIDRMask(prefixLen, 128)
		ip16 := ip.Mask(mask).To16()
		address = []byte(ip16)[:((prefixLen + 7) / 8)]
	} else {
		log.Errorf("invalid IP address: %v", ip)
		return errors.New("invalid IP address")
	}

	// Option data format:
	// - family (2B)
	// - source-prefix-length (1B)
	// - scope-prefix-length (1B)
	// - address (variable; cut to source-prefix-length)
	buf := []byte{}
	buf = binary.BigEndian.AppendUint16(buf, family)
	buf = append(buf, byte(prefixLen)) // source prefix length
	buf = append(buf, byte(0))         // scope prefix length
	buf = append(buf, address...)
	option := dnsmessage.Option{
		Code: optionCodeSubnet,
		Data: buf,
	}

	exists := false
	for i := 0; i < len(m.OPT.Options); i++ {
		op := &m.OPT.Options[i]
		if op.Code == option.Code {
			log.Debugf("overriding existing EDNS subnet option")
			op.Data = option.Data
			exists = true
			break
		}
	}
	if !exists {
		m.OPT.Options = append(m.OPT.Options, option)
	}

	return nil
}
