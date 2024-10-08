// SPDX-License-Identifier: MIT
//
// DNS message parsing and manipulations.
//

package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

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

// Session info to track and distinguish one specific query and response.
type QuerySession struct {
	ID   uint16
	Type dnsmessage.Type
	Name string // lower-cased
}

func (s *QuerySession) String() string {
	return fmt.Sprintf("%d:%s:%s", s.ID, s.Type, s.Name)
}

type RawMsg []byte

// Parse the raw message (should be a response) and compose the session key
// to locate the session for replying.
func (m RawMsg) SessionKey() (string, error) {
	// Only need to parse the header and first question.
	var p dnsmessage.Parser
	header, err := p.Start(m)
	if err != nil {
		log.Errorf("failed to parse message: %v", err)
		return "", err
	}
	// Parse the question section and get the first one.
	question, err := p.Question()
	if err != nil {
		log.Errorf("failed to parse question: %v", err)
		return "", err
	}

	s := &QuerySession{
		ID:   header.ID,
		Type: question.Type,
		Name: strings.ToLower(question.Name.String()),
	}
	return s.String(), nil
}

type QueryMsg struct {
	Header   dnsmessage.Header
	Question dnsmessage.Question
	// EDNS pseudo resource
	OPT struct {
		Header  *dnsmessage.ResourceHeader
		Options []dnsmessage.Option
	}
}

func NewQueryMsg(msg RawMsg) (*QueryMsg, error) {
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

func (m *QueryMsg) QType() dnsmessage.Type {
	return m.Question.Type
}

// Get the query name.
// Note: characters inside the labels are not escaped in any way.
// e.g., www.Example.COM.
func (m *QueryMsg) QName() string {
	return m.Question.Name.String()
}

// Compose the session key.
func (m *QueryMsg) SessionKey() string {
	s := &QuerySession{
		ID:   m.Header.ID,
		Type: m.QType(),
		Name: strings.ToLower(m.QName()),
	}
	return s.String()
}

func (m *QueryMsg) SetEdnsSubnet(ip netip.Addr, prefixLen int) error {
	if !ip.IsValid() || ip.IsUnspecified() {
		log.Errorf("invalid/unspecified IP address: %v", ip.String())
		return errors.New("invalid/unspecified IP address")
	}

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
	if ip.Is4() {
		family = uint16(1)
		if prefixLen <= 0 || prefixLen > 32 {
			prefixLen = ipv4PrefixLength
		}
		prefix, _ := ip.Prefix(prefixLen)
		a4 := prefix.Addr().As4()
		address = a4[:((prefixLen + 7) / 8)]
	} else {
		family = uint16(2)
		if prefixLen <= 0 || prefixLen > 128 {
			prefixLen = ipv6PrefixLength
		}
		prefix, _ := ip.Prefix(prefixLen)
		a16 := prefix.Addr().As16()
		address = a16[:((prefixLen + 7) / 8)]
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

func (m *QueryMsg) Build() (RawMsg, error) {
	msg := dnsmessage.Message{
		Header:    m.Header,
		Questions: []dnsmessage.Question{m.Question},
	}
	if m.OPT.Header != nil {
		r := dnsmessage.Resource{
			Header: *m.OPT.Header,
			Body:   &dnsmessage.OPTResource{Options: m.OPT.Options},
		}
		msg.Additionals = []dnsmessage.Resource{r}
	}

	return msg.Pack()
}
