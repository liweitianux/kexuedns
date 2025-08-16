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
)

const (
	maxQuerySize = 512 // bytes
	minQuerySize = 12  // bytes (header length)

	queryTimeout    = 4 * time.Second // less than dig's default (5s)
	tcpReadTimeout  = 5 * time.Second // read timeout for TCP/DoT queries
	tcpWriteTimeout = 5 * time.Second // write timeout for TCP/DoT queries

	dohPath        = "/dns-query"
	dohContentType = "application/dns-message"
)

type dnsProto int

const (
	dnsProtoUDP dnsProto = iota
	dnsProtoTCP
	dnsProtoDoT // DNS-over-TLS
	dnsProtoDoH // DNS-over-HTTPS
)

// TODO: cache
type Forwarder struct {
	Router Router // Resolver routing

	Listen    *ListenConfig // UDP+TCP protocols
	ListenDoT *ListenConfig // DoT protocol
	ListenDoH *ListenConfig // DoH protocol

	cancel context.CancelFunc // cancel listners to stop the forwarder
	wg     sync.WaitGroup     // wait for shutdown to complete

	udpPool sync.Pool // Pool for UDP message buffers.
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

func (f *Forwarder) Stop() {
	f.Router.Close()

	if f.cancel != nil {
		f.cancel()
	}

	f.wg.Wait()
	log.Infof("forwarder stopped")
}

// Start the forwarder at the given address (address).
// This function starts a goroutine to serve the queries so it doesn't block.
func (f *Forwarder) Start() (err error) {
	f.udpPool.New = func() any {
		return make([]byte, maxQuerySize)
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

	return
}

func (f *Forwarder) serveUDP(ctx context.Context, conn *net.UDPConn) {
	go func() {
		// Wait for cancellation from Stop().
		<-ctx.Done()
		conn.Close()
	}()

	for {
		buf := f.udpPool.Get().([]byte)
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

		f.wg.Add(1)
		go func(buf []byte, n int, addr net.Addr) {
			log.Debugf("handle UDP query from %s", addr)
			resp, _ := f.handleQuery(buf[:n], true)
			if resp != nil {
				_, err = conn.WriteTo(resp, addr)
				if err != nil {
					log.Warnf("failed to send packet: %v", err)
				}
			}

			f.udpPool.Put(buf)
			f.wg.Done()
		}(buf, n, addr)
	}
}

// Serve TCP and DoT connections.
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

		f.wg.Add(1)
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
	if r.URL.Path != dohPath {
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

	resp, err := f.handleQuery(query, false)
	if resp == nil {
		http.Error(w, "400 bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", dohContentType)
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (f *Forwarder) handleTCP(ctx context.Context, conn net.Conn) {
	defer f.wg.Done()
	defer conn.Close() // ensure exactly one close

	// Create per-connection context.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		// Watch for parent context cancellation or this handler exiting.
		<-connCtx.Done()
		// Set a past time to unblock IO.
		conn.SetDeadline(time.Unix(1, 0))
	}()

	lbuf := make([]byte, 2)
	for {
		proto := "TCP"
		if _, ok := conn.(*tls.Conn); ok {
			proto = "DoT"
		}
		log.Debugf("handle %s query from %s", proto, conn.RemoteAddr())

		conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
		// Read query length.
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
		// Read query content.
		length := binary.BigEndian.Uint16(lbuf)
		query := make([]byte, length)
		if _, err := io.ReadFull(conn, query); err != nil {
			log.Errorf("failed to read query content: %v", err)
			return
		}

		resp, _ := f.handleQuery(query, false)
		if resp != nil {
			conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
			// Prepend response length and send.
			binary.BigEndian.PutUint16(lbuf, uint16(len(resp)))
			_, err := conn.Write(append(lbuf, resp...))
			if err != nil {
				log.Warnf("failed to send packet: %v", err)
				return
			}
		}
	}
}

func (f *Forwarder) handleQuery(qmsg []byte, isUDP bool) ([]byte, error) {
	if n := len(qmsg); n <= minQuerySize {
		log.Debugf("junk packet: length=%d", n)
		// Unable to make a sensible reply; just drop it.
		// Dropping also prevents from abusing for amplification attacks.
		return nil, errors.New("junk packet")
	} else if n > maxQuerySize {
		return nil, errors.New("packet too large")
	}

	query, err := dnsmsg.NewQueryMsg(qmsg)
	if err != nil {
		log.Debugf("invalid query packet: %v", err)
		return nil, errors.New("invalid query")
	}

	// Make a fallback reply with RCode=ServFail.
	rquery := dnsmsg.RawMsg(qmsg)
	rquery.SetRCode(dnsmessage.RCodeServerFailure)
	rresp := []byte(rquery)

	qname := query.QName()
	resolver, _ := f.Router.GetResolver(qname)
	if resolver == nil {
		log.Debugf("no resolver found for qname [%s]", qname)
		return rresp, errors.New("resolver not found")
	}

	myIP := config.GetMyIP()
	addr, ok := myIP.GetV4()
	if query.QType() == dnsmessage.TypeAAAA {
		addr, ok = myIP.GetV6()
	}
	if ok {
		query.SetEdnsSubnet(addr, 0)
	}
	log.Debugf("query: %+v", query)

	msg, err := query.Build()
	if err != nil {
		log.Errorf("failed to build query: %v", err)
		return rresp, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	resp, err := resolver.Query(ctx, msg, isUDP)
	if err != nil {
		return rresp, err
	}

	return resp, nil
}
