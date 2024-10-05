// SPDX-License-Identifier: MIT
//
// Forward DNS queries and responses.
//

package dns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kexuedns/config"
	"kexuedns/log"
)

const (
	queryTimeout = 15 * time.Second
)

// TODO: router
// TODO: cache
type Forwarder struct {
	resolvers []*Resolver
	responses chan RawMsg
	sessions  map[string]*Session // key: "QID:QType:QName"
}

type Session struct {
	client   net.Addr
	response chan RawMsg
}

func NewForwarder() *Forwarder {
	return &Forwarder{
		resolvers: []*Resolver{},
		responses: make(chan RawMsg),
		sessions:  make(map[string]*Session),
	}
}

func (f *Forwarder) AddResolver(r *Resolver) {
	f.resolvers = append(f.resolvers, r)
	go r.Receive(f.responses)
}

func (f *Forwarder) Query(client net.Addr, msg RawMsg) (RawMsg, error) {
	query, err := NewQueryMsg(msg)
	if err != nil {
		log.Errorf("failed to parse query: %v", err)
		return nil, err
	}

	if query.QType() == dnsmessage.TypeAAAA {
		addr, ok := config.MyIP.GetV6()
		if ok {
			query.SetEdnsSubnet(addr, 0)
		}
	} else {
		// Default to IPv4
		addr, ok := config.MyIP.GetV4()
		if ok {
			query.SetEdnsSubnet(addr, 0)
		}
	}
	log.Debugf("query: %+v", query)

	msg, err = query.Build()
	if err != nil {
		log.Errorf("failed to build query: %v", err)
		return nil, err
	}

	r := f.resolvers[0] // TODO: router
	if err := r.Query(msg); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%d:%s:%s", query.Header.ID,
		query.QType(), strings.ToLower(query.QName()))
	session := &Session{
		client:   client,
		response: make(chan RawMsg, 1),
	}
	f.sessions[key] = session
	log.Debugf("added session with key: %s", key)

	select {
	case resp := <-session.response:
		log.Debugf("session [%s] succeeded (len=%d)", key, len(resp))
		return resp, nil
	case <-time.After(queryTimeout):
		break
	}

	log.Warnf("session [%s] timed out", key)
	return nil, errors.New("query timed out")
}
