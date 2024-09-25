// SPDX-License-Identifier: MIT
//
// DNS message parsing and manipulations.
//

package dns

import (
	"golang.org/x/net/dns/dnsmessage"

	"kexuedns/log"
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
