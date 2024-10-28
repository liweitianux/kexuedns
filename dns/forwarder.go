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

	queryTimeout   = 5 * time.Second
	sessionTimeout = 10 * time.Second

	cleanInternval = 5 * time.Second
)

var (
	errQueryTimeout     = errors.New("query timed out")
	errQueryInvalid     = errors.New("query invalid")
	errResolverNotFound = errors.New("resolver not found")
)

// TODO: router
// TODO: cache
type Forwarder struct {
	resolver  *Resolver // TODO: => resolver router
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
		responses: make(chan RawMsg),
		sessions:  make(map[string]*Session),
	}
}

func (f *Forwarder) SetResolver(r *Resolver) {
	f.resolver = r
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
	if errors.Is(err, errQueryInvalid) {
		// Unable to make a sensible reply; just drop it.
		return
	}
	if err != nil {
		// Reply with ServFail.
		resp = buf
		resp[2] |= 0x80 // Set QR bit
		resp[3] |= 0x02 // Set RCode to ServFail
	}
	_, err = pc.WriteTo(resp, addr)
	if err != nil {
		log.Warnf("failed to write packet: %v", err)
	}
}

func (f *Forwarder) query(client net.Addr, msg RawMsg) (RawMsg, error) {
	query, err := NewQueryMsg(msg)
	if err != nil {
		return nil, errQueryInvalid
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

	if f.resolver == nil {
		log.Debugf("no resolver available")
		return nil, errResolverNotFound
	}
	if err := f.resolver.Query(msg); err != nil {
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
	return nil, errQueryTimeout
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
		// OK to close the channel since it's buffered (i.e., has size).
		close(session.response)
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
				close(v.response)
				delete(f.sessions, k)
			}
		}
	}
}
