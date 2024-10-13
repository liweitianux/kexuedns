// SPDX-License-Identifier: MIT
//
// Forward DNS queries and responses.
//

package dns

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kexuedns/config"
	"kexuedns/log"
)

const (
	maxQuerySize = 1024 // bytes

	queryTimeout   = 15 * time.Second
	sessionTimeout = 30 * time.Second

	cleanInternval = 5 * time.Second
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
	expireAt time.Time
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

func (f *Forwarder) ListenAndServe(address string) error {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		log.Errorf("failed to listen UDP at [%s]: %v", address, err)
		return err
	}
	defer pc.Close()

	go f.receive()
	go f.clean()

	for {
		buf := make([]byte, maxQuerySize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Warnf("failed to read packet: %v", err)
			continue
		}

		go f.serve(pc, addr, buf[:n])
	}
}

func (f *Forwarder) serve(pc net.PacketConn, addr net.Addr, buf []byte) {
	resp, err := f.query(addr, buf)
	if err != nil {
		return
	}
	_, err = pc.WriteTo(resp, addr)
	if err != nil {
		log.Warnf("failed to write packet: %v", err)
	}
}

func (f *Forwarder) query(client net.Addr, msg RawMsg) (RawMsg, error) {
	query, err := NewQueryMsg(msg)
	if err != nil {
		log.Errorf("failed to parse query: %v", err)
		return nil, err
	}

	myIP := config.GetMyIP()
	if query.QType() == dnsmessage.TypeAAAA {
		addr, ok := myIP.GetV6()
		if ok {
			query.SetEdnsSubnet(addr, 0)
		}
	} else {
		// Default to IPv4
		addr, ok := myIP.GetV4()
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

	key := query.SessionKey()
	session := &Session{
		client:   client,
		response: make(chan RawMsg, 1),
		expireAt: time.Now().Add(sessionTimeout),
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

func (f *Forwarder) receive() {
	for {
		resp := <-f.responses
		key, err := resp.SessionKey()
		if err != nil {
			continue
		}
		session, exists := f.sessions[key]
		if !exists {
			log.Warnf("session [%s] not found", key)
			continue
		}
		session.response <- resp
		delete(f.sessions, key)
	}
}

func (f *Forwarder) clean() {
	ticker := time.NewTicker(cleanInternval)
	for {
		<-ticker.C
		now := time.Now()
		// TODO: rwlock
		for k, v := range f.sessions {
			if now.After(v.expireAt) {
				log.Debugf("clean expired session [%s]", k)
				delete(f.sessions, k)
			}
		}
	}
}
