// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Forward DNS queries and responses.
//

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	Listen *ListenConfig // UDP+TCP protocols

	resolver  *Resolver // TODO: => resolver router
	responses chan []byte
	sessions  *ttlcache.Cache // dnsmsg.SessionKey() => *Session

	cancel context.CancelFunc // cancel listners to stop the forwarder
	wg     sync.WaitGroup     // wait for shutdown to complete
}

type ListenConfig struct {
	Address netip.AddrPort
}

type Session struct {
	conn   *net.UDPConn
	client net.Addr
	query  []byte      // original query packet
	timer  *time.Timer // query timeout timer
}

// Set the address of UDP+TCP listeners.
func (f *Forwarder) SetListen(ip string, port uint16) error {
	if port == 0 {
		port = 53
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address [%s]: %v", ip, err)
	}

	f.Listen = &ListenConfig{
		Address: netip.AddrPortFrom(addr, port),
	}
	return nil
}

func (f *Forwarder) SetResolver(r *Resolver) {
	if f.resolver != nil {
		f.resolver.Close()
	}

	f.resolver = r
}

func (f *Forwarder) Stop() {
	f.cancel()

	if f.resolver != nil {
		f.resolver.Close()
	}

	if f.responses != nil {
		close(f.responses)
		f.responses = nil
	}

	f.wg.Wait()
	log.Infof("forwarder stopped")
}

// Start the forwarder at the given address (address).
// This function starts a goroutine to serve the queries so it doesn't block.
func (f *Forwarder) Start() error {
	if f.sessions == nil {
		f.sessions = ttlcache.New(sessionTimeout, 0, nil)
	}

	if f.Listen == nil {
		log.Infof("no listen address configured")
		return nil
	}

	addr := net.UDPAddrFromAddrPort(f.Listen.Address)
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Errorf("failed to listen at: %s, error: %v", addr.String(), err)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	f.wg.Add(1)
	go f.serve(ctx, conn)
	log.Infof("started UDP forwarder at: %s", addr.String())

	f.wg.Add(1)
	go f.receive()

	return nil
}

// NOTE: This function blocks until Stop() is called.
func (f *Forwarder) serve(ctx context.Context, conn *net.UDPConn) {
	go func() {
		// Wait for cancellation from Stop().
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, maxQuerySize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Infof("connection closed; stop UDP forwarder")
				f.wg.Done()
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
		go f.handle(data, conn, addr)
	}
}

func (f *Forwarder) handle(msg []byte, conn *net.UDPConn, client net.Addr) {
	query, err := dnsmsg.NewQueryMsg(msg)
	if err != nil {
		log.Debugf("invalid query packet: %v", err)
		return // Unable to make a sensible reply; just drop it.
	}

	key := query.SessionKey()
	session := &Session{
		conn:   conn,
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

	session.timer = time.AfterFunc(queryTimeout, func() {
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
	f.responses = make(chan []byte)

	if f.resolver != nil {
		go f.resolver.Receive(f.responses)
	}

	for {
		resp, ok := <-f.responses
		if !ok {
			log.Debugf("channel closed")
			f.wg.Done()
			return
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
}

// Reply the client with the response.
func (f *Forwarder) reply(session *Session, resp []byte) {
	if session.timer != nil {
		session.timer.Stop()
	}

	if len(resp) == 0 {
		// Reply with ServFail.
		resp = session.query
		resp[2] |= 0x80 // Set QR bit
		resp[3] |= 0x02 // Set RCode to ServFail
	}

	_, err := session.conn.WriteTo(resp, session.client)
	if err != nil {
		log.Warnf("failed to write packet: %v", err)
	}
}
