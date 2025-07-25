// SPDX-License-Identifier: MIT
//
// Forward DNS queries and responses.
//

package dns

import (
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kexuedns/config"
	"kexuedns/log"
	"kexuedns/util/ttlcache"
)

const (
	maxQuerySize = 1024 // bytes

	queryTimeout   = 5 * time.Second
	sessionTimeout = 10 * time.Second
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
	// key: "QID:QType:QName"
	// value: *Session
	sessions *ttlcache.Cache
	conn     net.PacketConn
	wg       *sync.WaitGroup
}

type Session struct {
	client   net.Addr
	response chan RawMsg
}

func NewForwarder() *Forwarder {
	sessions := ttlcache.New(sessionTimeout, 0, func(key string, value any) {
		s := value.(*Session)
		close(s.response)
		log.Debugf("cleaned expired session [%s]", key)
	})
	return &Forwarder{
		sessions: sessions,
		wg:       &sync.WaitGroup{},
	}
}

func (f *Forwarder) SetResolver(r *Resolver) {
	if f.resolver != nil {
		f.resolver.Close()
	}

	f.resolver = r
}

func (f *Forwarder) Stop() {
	f.conn.Close()
	f.conn = nil

	if f.resolver != nil {
		f.resolver.Close()
		f.resolver = nil
	}

	close(f.responses)
	f.wg.Wait()

	log.Infof("forwarder stopped")
}

// Listen at the given address and return the connection for Serve().
// NOTE: Splitting Listen() and Serve() helps the caller better handle the
// error.
func (f *Forwarder) Listen(address string) (net.PacketConn, error) {
	return net.ListenPacket("udp", address)
}

// NOTE: This function blocks until Stop() is called.
func (f *Forwarder) Serve(pc net.PacketConn) {
	f.conn = pc
	f.responses = make(chan RawMsg)
	f.wg.Add(1)
	go f.receive()

	for {
		buf := make([]byte, maxQuerySize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Infof("connection closed; stopping ...")
				return
			}
			log.Warnf("failed to read packet: %v", err)
			continue
		}

		go f.handle(pc, addr, buf[:n])
	}
}

func (f *Forwarder) handle(pc net.PacketConn, addr net.Addr, buf []byte) {
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
	}
	f.sessions.Set(key, session, ttlcache.DefaultTTL)
	log.Debugf("added session with key: %s", key)

	select {
	case resp := <-session.response:
		log.Debugf("session [%s] succeeded (len=%d)", key, len(resp))
		return resp, nil
	case <-time.After(queryTimeout):
		break
	}
	log.Warnf("session [%s] timed out", key)
	f.sessions.Delete(key)
	return nil, errQueryTimeout
}

func (f *Forwarder) receive() {
	go f.resolver.Receive(f.responses)

	for {
		resp, ok := <-f.responses
		if !ok {
			log.Debugf("responses channel closed")
			break
		}

		key, err := resp.SessionKey()
		if err != nil {
			continue
		}

		if v, ok := f.sessions.Pop(key); !ok {
			log.Warnf("session [%s] not found or expired", key)
		} else {
			session := v.(*Session)
			session.response <- resp
			// OK to close the channel since it's buffered
			// (i.e., created with size).
			close(session.response)
		}
	}

	f.wg.Done()
}
