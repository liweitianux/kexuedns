// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Forward DNS queries and responses.
//

package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

type dnsProto int

const (
	dnsProtoUDP dnsProto = iota
	dnsProtoTCP
	dnsProtoDoT // DNS-over-TLS
	dnsProtoDoH // DNS-over-HTTPS
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
	proto   dnsProto
	udpConn *net.UDPConn
	tcpConn *net.TCPConn
	client  net.Addr
	query   []byte      // original query packet
	timer   *time.Timer // query timeout timer
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
	if f.cancel != nil {
		f.cancel()
	}

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
func (f *Forwarder) Start() (err error) {
	if f.sessions == nil {
		f.sessions = ttlcache.New(sessionTimeout, 0, nil)
	}

	if f.Listen == nil {
		log.Infof("no listen address configured")
		return
	}

	var closers []io.Closer // all opened connection/listeners
	defer func() {
		if err != nil {
			for _, c := range closers {
				c.Close()
			}
		}
	}()

	udpAddr := net.UDPAddrFromAddrPort(f.Listen.Address)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Errorf("failed to listen UDP at: %s, error: %v", udpAddr, err)
		return
	}
	closers = append(closers, udpConn)
	log.Infof("bound UDP forwarder at: %s", udpAddr)

	tcpAddr := net.TCPAddrFromAddrPort(f.Listen.Address)
	tcpLn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Errorf("failed to listen TCP at: %s, error: %v", tcpAddr, err)
		return
	}
	closers = append(closers, tcpLn)
	log.Infof("bound TCP forwarder at: %s", tcpAddr)

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	f.wg.Add(1)
	go f.serveUDP(ctx, udpConn)

	f.wg.Add(1)
	go f.serveTCP(ctx, tcpLn)

	f.wg.Add(1)
	go f.receive()

	return
}

// NOTE: This function blocks until Stop() is called.
func (f *Forwarder) serveUDP(ctx context.Context, conn *net.UDPConn) {
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

		msg := make([]byte, n)
		copy(msg, buf[:n])
		session := &Session{
			proto:   dnsProtoUDP,
			udpConn: conn,
			client:  addr,
			query:   msg,
		}
		log.Debugf("handle UDP query from %s", addr)
		go f.handleQuery(session)
	}
}

// NOTE: This function blocks until Stop() is called.
func (f *Forwarder) serveTCP(ctx context.Context, ln *net.TCPListener) {
	go func() {
		// Wait for cancellation from Stop().
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Infof("listener closed; stop TCP forwarder")
				f.wg.Done()
				return
			}

			log.Warnf("failed to read packet: %v", err)
			continue
		}

		go f.handleTCP(ctx, conn)
	}
}

func (f *Forwarder) handleTCP(ctx context.Context, conn *net.TCPConn) {
	log.Debugf("handle TCP queries from %s", conn.RemoteAddr())
	defer conn.Close()

	for {
		// read query length
		lbuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lbuf); err != nil {
			if errors.Is(err, io.EOF) {
				log.Debugf("remote closed connection")
			} else if errors.Is(err, net.ErrClosed) {
				log.Debugf("connection closed")
			} else {
				log.Errorf("failed to read query length: %v", err)
			}
			return
		}
		// read query content
		length := binary.BigEndian.Uint16(lbuf)
		msg := make([]byte, length)
		if _, err := io.ReadFull(conn, msg); err != nil {
			log.Errorf("failed to read query content: %v", err)
			return
		}

		session := &Session{
			proto:   dnsProtoTCP,
			tcpConn: conn,
			query:   msg,
		}
		go f.handleQuery(session)
	}
}

func (f *Forwarder) handleQuery(session *Session) {
	if n := len(session.query); n <= minQuerySize {
		log.Debugf("malformatted query: length=%d", n)
		return // Unable to make a sensible reply; just drop it.
	}

	query, err := dnsmsg.NewQueryMsg(session.query)
	if err != nil {
		log.Debugf("invalid query packet: %v", err)
		return // Drop as well.
	}

	key := query.SessionKey()
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
			go f.reply(v.(*Session), resp)
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

	var err error
	switch session.proto {
	case dnsProtoUDP:
		_, err = session.udpConn.WriteTo(resp, session.client)
	case dnsProtoTCP:
		lbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lbuf, uint16(len(resp)))
		_, err = session.tcpConn.Write(append(lbuf, resp...))
	default:
		panic(fmt.Sprintf("unknown protocol: %v", session.proto))
	}
	if err != nil {
		log.Warnf("failed to send packet: %v", err)
	}
}
