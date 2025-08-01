// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Forward DNS queries and responses.
//

package dns

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

	dohURI         = "/dns-query"
	dohContentType = "application/dns-message"
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
	Listen    *ListenConfig // UDP+TCP protocols
	ListenDoT *ListenConfig // DoT protocol
	ListenDoH *ListenConfig // DoH protocol

	resolver  *Resolver // TODO: => resolver router
	responses chan []byte
	sessions  *ttlcache.Cache // dnsmsg.SessionKey() => *Session

	cancel context.CancelFunc // cancel listners to stop the forwarder
	wg     sync.WaitGroup     // wait for shutdown to complete
}

type ListenConfig struct {
	Address     netip.AddrPort
	Certificate *tls.Certificate
}

func (lc *ListenConfig) listen(proto dnsProto) (io.Closer, error) {
	switch proto {
	case dnsProtoUDP:
		addr := net.UDPAddrFromAddrPort(lc.Address)
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			log.Errorf("failed to listen UDP at: %s, error: %v", addr, err)
			return nil, err
		}
		log.Infof("bound UDP forwarder at: %s", addr)
		return conn, nil
	case dnsProtoTCP:
		ln, err := net.Listen("tcp", lc.Address.String())
		if err != nil {
			log.Errorf("failed to listen TCP at: %s, error: %v", lc.Address, err)
			return nil, err
		}
		log.Infof("bound TCP forwarder at: %s", lc.Address)
		return ln, nil
	case dnsProtoDoT, dnsProtoDoH:
		config := &tls.Config{
			Certificates: []tls.Certificate{*lc.Certificate},
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				log.Debugf("TLS connection from %s with ServerName=[%s]",
					chi.Conn.RemoteAddr(), chi.ServerName)
				return nil, nil
			},
		}
		if proto == dnsProtoDoH {
			config.NextProtos = []string{"h2"} // enable HTTP/2
		}
		ln, err := tls.Listen("tcp", lc.Address.String(), config)
		if err != nil {
			log.Errorf("failed to listen DoT/DoH at: %s, error: %v", lc.Address, err)
			return nil, err
		}
		log.Infof("bound DoT/DoH forwarder at: %s", lc.Address)
		return ln, nil
	default:
		panic(fmt.Sprintf("unknown protocol: %v", proto))
	}
}

type Session struct {
	proto    dnsProto
	udpConn  *net.UDPConn
	tcpConn  net.Conn // *net.TCPConn, *tls.Conn
	client   net.Addr
	query    []byte      // original query packet
	response chan []byte // pipe response to DoH handler
	timer    *time.Timer // query timeout timer
}

// Set the address of UDP+TCP listeners.
func (f *Forwarder) SetListen(ip string, port uint16) error {
	if ip == "" {
		f.Listen = nil
		return nil
	}

	if port == 0 {
		port = 53
	}
	lc, err := f.makeListenConfig(ip, port, "", "")
	if err != nil {
		return err
	}

	f.Listen = lc
	return nil
}

// Set the address and certificate of DoT listener.
func (f *Forwarder) SetListenDoT(ip string, port uint16, certFile, keyFile string) error {
	if ip == "" {
		f.ListenDoT = nil
		return nil
	}

	if port == 0 {
		port = 853
	}
	lc, err := f.makeListenConfig(ip, port, certFile, keyFile)
	if err != nil {
		return err
	}

	f.ListenDoT = lc
	return nil
}

// Set the address and certificate of DoH listener.
func (f *Forwarder) SetListenDoH(ip string, port uint16, certFile, keyFile string) error {
	if ip == "" {
		f.ListenDoH = nil
		return nil
	}

	if port == 0 {
		port = 443
	}
	lc, err := f.makeListenConfig(ip, port, certFile, keyFile)
	if err != nil {
		return err
	}

	f.ListenDoH = lc
	return nil
}

func (f *Forwarder) makeListenConfig(
	ip string, port uint16, certFile, keyFile string,
) (*ListenConfig, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address [%s]: %v", ip, err)
	}

	lc := &ListenConfig{
		Address: netip.AddrPortFrom(addr, port),
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert/key pair: %v", err)
		}

		lc.Certificate = &cert
	}

	return lc, nil
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

	listenConfigs := map[dnsProto]*ListenConfig{
		dnsProtoUDP: f.Listen,
		dnsProtoTCP: f.Listen,
		dnsProtoDoT: f.ListenDoT,
		dnsProtoDoH: f.ListenDoH,
	}

	// all opened connection/listeners
	closers := map[dnsProto]io.Closer{}
	defer func() {
		if err != nil {
			for _, c := range closers {
				c.Close()
			}
		}
	}()

	for proto, lc := range listenConfigs {
		if lc == nil {
			continue
		}
		var ln io.Closer
		ln, err = lc.listen(proto)
		if err != nil {
			return
		}
		closers[proto] = ln
	}
	if len(closers) == 0 {
		log.Infof("no listen address configured")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel

	for proto, ln := range closers {
		switch proto {
		case dnsProtoUDP:
			f.wg.Add(1)
			go f.serveUDP(ctx, ln.(*net.UDPConn))
		case dnsProtoTCP, dnsProtoDoT:
			f.wg.Add(1)
			go f.serveTCP(ctx, ln.(net.Listener))
		case dnsProtoDoH:
			f.wg.Add(1)
			go f.serveDoH(ctx, ln.(net.Listener))
		default:
			panic(fmt.Sprintf("unknown protocol: %v", proto))
		}
	}

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

// Serve TCP and DoT connections.
// NOTE: This function blocks until Stop() is called.
func (f *Forwarder) serveTCP(ctx context.Context, ln net.Listener) {
	go func() {
		// Wait for cancellation from Stop().
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Infof("listener closed; stop TCP/DoT forwarder")
				f.wg.Done()
				return
			}

			log.Warnf("failed to read packet: %v", err)
			continue
		}

		go f.handleTCP(ctx, conn)
	}
}

func (f *Forwarder) serveDoH(ctx context.Context, ln net.Listener) {
	server := &http.Server{
		Handler: http.HandlerFunc(f.handleDoH),
	}

	go func() {
		// Wait for cancellation from Stop().
		<-ctx.Done()
		server.Close()
	}()

	err := server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		log.Infof("server closed; stop DoH forwarder")
	} else {
		log.Errorf("DoH forwarder failed: %v", err)
	}
	f.wg.Done()
}

func (f *Forwarder) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != dohURI {
		http.Error(w, "400 bad request: uri invalid", http.StatusBadRequest)
		return
	}

	log.Debugf("handle DoH query from %s, method=%s", r.RemoteAddr, r.Method)

	var query []byte
	switch r.Method {
	case http.MethodGet:
		v := r.FormValue("dns")
		if v == "" {
			http.Error(w, "400 bad request: dns missing", http.StatusBadRequest)
			return
		}
		log.Debugf("dns-message: %s", v)
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || len(b) == 0 {
			http.Error(w, "400 bad request: dns invalid", http.StatusBadRequest)
			return
		}
		query = b
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dohContentType {
			http.Error(w, "400 bad request: content-type invalid", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) == 0 {
			http.Error(w, "400 bad request: body", http.StatusBadRequest)
			return
		}
		query = body
	default:
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := &Session{
		proto:    dnsProtoDoH,
		query:    query,
		response: make(chan []byte, 1),
	}
	if ok := f.handleQuery(session); !ok {
		http.Error(w, "400 bad request: query invalid", http.StatusBadRequest)
		return
	}

	resp := <-session.response

	w.Header().Set("Content-Type", dohContentType)
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (f *Forwarder) handleTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	for {
		proto, protoName := dnsProtoTCP, "TCP"
		if _, ok := conn.(*tls.Conn); ok {
			proto, protoName = dnsProtoDoT, "DoT"
		}
		log.Debugf("handle %s query from %s", protoName, conn.RemoteAddr())
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
			proto:   proto,
			tcpConn: conn,
			query:   msg,
		}
		go f.handleQuery(session)
	}
}

// NOTE: This function is reused in handleDoH() and thus needs to return
// a boolean indicating whether there is a reply.
func (f *Forwarder) handleQuery(session *Session) bool {
	if n := len(session.query); n <= minQuerySize {
		log.Debugf("malformatted query: length=%d", n)
		return false // Unable to make a sensible reply; just drop it.
	}

	query, err := dnsmsg.NewQueryMsg(session.query)
	if err != nil {
		log.Debugf("invalid query packet: %v", err)
		return false // Drop as well.
	}

	key := query.SessionKey()
	f.sessions.Set(key, session, ttlcache.DefaultTTL)
	log.Debugf("added session with key: %s", key)

	if err := f.query(query); err != nil {
		f.sessions.Delete(key)
		f.reply(session, nil)
	} else {
		session.timer = time.AfterFunc(queryTimeout, func() {
			log.Infof("session [%s] timed out", key)
			f.sessions.Delete(key)
			f.reply(session, nil)
		})
	}

	return true // Has a reply regardless of success or failure.
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
		msg := dnsmsg.RawMsg(session.query)
		msg.SetRCode(dnsmessage.RCodeServerFailure)
		resp = []byte(msg)
	}

	var err error
	switch session.proto {
	case dnsProtoUDP:
		_, err = session.udpConn.WriteTo(resp, session.client)
	case dnsProtoTCP, dnsProtoDoT:
		lbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lbuf, uint16(len(resp)))
		_, err = session.tcpConn.Write(append(lbuf, resp...))
	case dnsProtoDoH:
		session.response <- resp
		// OK to close since it's buffered (i.e., created with size).
		close(session.response)
	default:
		panic(fmt.Sprintf("unknown protocol: %v", session.proto))
	}
	if err != nil {
		log.Warnf("failed to send packet: %v", err)
	}
}
