// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
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
	"kexuedns/util/dnsmsg"
	"kexuedns/util/ttlcache"
)

const (
	maxQuerySize = 512 // bytes
	minQuerySize = 12  // bytes (header length)

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
	responses chan []byte
	sessions  *ttlcache.Cache // dnsmsg.SessionKey() => *Session
	conn      net.PacketConn
	wg        *sync.WaitGroup
}

type Session struct {
	client net.Addr
	query  []byte // original query packet
}

func NewForwarder() *Forwarder {
	return &Forwarder{
		sessions: ttlcache.New(sessionTimeout, 0, nil),
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
	f.responses = make(chan []byte)
	f.wg.Add(1)
	go f.receive()

	buf := make([]byte, maxQuerySize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Infof("connection closed; stopping ...")
				return
			}
			log.Warnf("failed to read packet: %v", err)
			continue
		}
		if n <= minQuerySize {
			log.Debugf("malformatted query: n=%d", n)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go f.handle(data, addr)
	}
}

func (f *Forwarder) handle(msg []byte, client net.Addr) {
	query, err := dnsmsg.NewQueryMsg(msg)
	if err != nil {
		log.Debugf("invalid query packet: %v", err)
		return // Unable to make a sensible reply; just drop it.
	}

	key := query.SessionKey()
	session := &Session{
		client: client,
		query:  msg,
	}
	f.sessions.Set(key, session, ttlcache.DefaultTTL)
	log.Debugf("added session with key: %s", key)

	if err := f.query(query); err != nil {
		f.sessions.Delete(key)
		f.reply(session, nil)
		return
	}

	time.AfterFunc(queryTimeout, func() {
		log.Infof("session [%s] timed out", key)
		f.sessions.Delete(key)
		f.reply(session, nil)
	})
}

// Query the backend resolver.
// NOTE: The response is handled asynchronously by receive().
func (f *Forwarder) query(query *dnsmsg.QueryMsg) error {
	if f.resolver == nil {
		log.Debugf("no resolver available")
		return errResolverNotFound
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

	msg, err := query.Build()
	if err != nil {
		log.Errorf("failed to build query: %v", err)
		return err
	}

	return f.resolver.Query(msg)
}

// Receive responses from the backend resolver and dispatch to clients.
func (f *Forwarder) receive() {
	go f.resolver.Receive(f.responses)

	for {
		resp, ok := <-f.responses
		if !ok {
			log.Debugf("responses channel closed")
			break
		}

		key, err := dnsmsg.RawMsg(resp).SessionKey()
		if err != nil {
			log.Warnf("invalid response: %v", err)
			continue
		}

		if v, ok := f.sessions.Pop(key); ok {
			f.reply(v.(*Session), resp)
		} else {
			log.Warnf("session [%s] not found or expired", key)
		}
	}

	f.wg.Done()
}

// Reply the client with the response.
func (f *Forwarder) reply(session *Session, resp []byte) {
	if len(resp) == 0 {
		// Reply with ServFail.
		resp = session.query
		resp[2] |= 0x80 // Set QR bit
		resp[3] |= 0x02 // Set RCode to ServFail
	}

	_, err := f.conn.WriteTo(resp, session.client)
	if err != nil {
		log.Warnf("failed to write packet: %v", err)
	}
}
