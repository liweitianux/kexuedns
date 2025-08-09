// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Resolvers to process the forwarded queries.
//

package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"kexuedns/config"
	"kexuedns/log"
	"kexuedns/util/dnsmsg"
)

var defaultTimeouts = struct {
	Read      time.Duration
	Write     time.Duration
	Dial      time.Duration
	Handshake time.Duration
}{
	Read:      15 * time.Second,
	Write:     5 * time.Second,
	Dial:      5 * time.Second,
	Handshake: 5 * time.Second,
}

var defaultPoolSize = struct {
	MaxConns  int
	IdleConns int
}{
	MaxConns:  20,
	IdleConns: 10,
}

var defaultKeepAlive = net.KeepAliveConfig{
	Enable:   true,
	Idle:     15 * time.Second,
	Interval: 15 * time.Second,
	Count:    3,
}

const (
	ResolverProtocolDefault = "default" // UDP+TCP
	ResolverProtocolUDP     = "udp"
	ResolverProtocolTCP     = "tcp"
	ResolverProtocolDoT     = "dot" // DNS-over-TLS
	ResolverProtocolDoH     = "doh" // DNS-over-HTTPS
)

const (
	maxResponseSize = 4096 // bytes (consider EDNS0)
	udpChannelSize  = 1024 // max number of in-flight UDP queries
)

type DNSResolver interface {
	Export() *ResolverExport
	Close()
	Query(ctx context.Context, msg []byte, isUDP bool) ([]byte, error)
}

type ResolverExport struct {
	// Name to identify in log messages
	Name string `json:"name"`
	// Resolver protocol: default, dot, doh
	Protocol string `json:"protocol"`
	// Resolver address: "[ipv4]:port", "[ipv6]:port"
	Address string `json:"address"`
	// Server name (SNI) to verify the TLS certificate
	ServerName string `json:"server_name"` // DoT/DoH only

	// TCP pool size: max total connections
	PoolMaxConns int `json:"pool_max_conns"`
	// TCP pool size: max idel connections
	PoolIdleConns int `json:"pool_idle_conns"`

	// TCP dial timeout (seconds)
	DialTimeout int `json:"dial_timeout"`
	// TLS handshake timeout (seconds)
	HandshakeTimeout int `json:"handshake_timeout"`

	// TCP keepalive settings
	KeepaliveEnable   bool `json:"keepalive_enable"`
	KeepaliveIdle     int  `json:"keepalive_idle"`     // seconds
	KeepaliveInterval int  `json:"keepalive_interval"` // seconds
	KeepaliveCount    int  `json:"keepalive_count"`
}

// Validate and normalize the fields.
func (re *ResolverExport) Validate() error {
	addrport, err := netip.ParseAddrPort(re.Address)
	if err != nil {
		log.Errorf("invalid address (%s): %v", re.Address, err)
		return err
	}

	if re.Name == "" {
		if re.ServerName != "" {
			re.Name = re.ServerName
		} else {
			re.Name = addrport.String()
		}
	}

	if re.PoolMaxConns == 0 {
		re.PoolMaxConns = defaultPoolSize.MaxConns
	}
	if re.PoolIdleConns == 0 {
		re.PoolIdleConns = defaultPoolSize.IdleConns
	}

	if re.DialTimeout == 0 {
		re.DialTimeout = int(defaultTimeouts.Dial.Seconds())
	}
	if re.HandshakeTimeout == 0 {
		re.HandshakeTimeout = int(defaultTimeouts.Handshake.Seconds())
	}

	if re.KeepaliveEnable {
		if re.KeepaliveIdle == 0 {
			re.KeepaliveIdle = int(defaultKeepAlive.Idle.Seconds())
		}
		if re.KeepaliveInterval == 0 {
			re.KeepaliveInterval = int(defaultKeepAlive.Interval.Seconds())
		}
		if re.KeepaliveCount == 0 {
			re.KeepaliveIdle = defaultKeepAlive.Count
		}
	}

	return nil
}

// TODO: DoH (HTTPS) with auth (basic, bearer)
func NewResolverFromExport(re *ResolverExport) (DNSResolver, error) {
	switch re.Protocol {
	case ResolverProtocolDefault, "":
		return NewResolverUT(re)
	case ResolverProtocolUDP:
		return NewResolverUDP(re)
	case ResolverProtocolTCP:
		return NewResolverTCP(re)
	case ResolverProtocolDoT:
		return NewResolverDoT(re)
	default:
		// TODO ResolverProtocolDefault
		// TODO: ResolverProtocolDoH
		return nil, fmt.Errorf("unknown resolver protocol: %s", re.Protocol)
	}
}

// ----------------------------------------------------------

type ResolverUT struct {
	*ResolverTCP
	udp *ResolverUDP
}

func NewResolverUT(re *ResolverExport) (*ResolverUT, error) {
	tcpResolver, err := NewResolverTCP(re)
	if err != nil {
		return nil, err
	}
	udpResolver, err := NewResolverUDP(re)
	if err != nil {
		return nil, err
	}

	r := &ResolverUT{
		ResolverTCP: tcpResolver,
		udp:         udpResolver,
	}

	return r, nil
}

func (r *ResolverUT) Export() *ResolverExport {
	re := r.ResolverTCP.Export()
	re.Protocol = ResolverProtocolDefault
	return re
}

func (r *ResolverUT) Close() {
	r.ResolverTCP.Close()
	r.udp.Close()
	log.Infof("[%s] stopped", r.name)
}

func (r *ResolverUT) Query(ctx context.Context, msg []byte, isUDP bool) ([]byte, error) {
	if isUDP {
		return r.udp.Query(ctx, msg, true)
	}
	// If the query was not sent via UDP, don't forward it to the UDP backend,
	// avoiding unnecessary truncation cases.
	return r.ResolverTCP.Query(ctx, msg, false)
}

// ----------------------------------------------------------

type ResolverUDP struct {
	name    string
	address netip.AddrPort

	queries  chan []byte
	sessions sync.Map // uint16(queryID) => *udpSession
	rand     *rand.Rand

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type udpSession struct {
	response chan []byte
}

func NewResolverUDP(re *ResolverExport) (*ResolverUDP, error) {
	if err := re.Validate(); err != nil {
		return nil, err
	}

	addrport, _ := netip.ParseAddrPort(re.Address)
	ctx, cancel := context.WithCancel(context.Background())

	r := &ResolverUDP{
		name:    re.Name,
		address: addrport,
		queries: make(chan []byte, udpChannelSize),
		rand:    rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0)),
		cancel:  cancel,
	}

	r.wg.Add(1)
	go r.worker(ctx)

	return r, nil
}

func (r *ResolverUDP) Export() *ResolverExport {
	return &ResolverExport{
		Name:     r.name,
		Protocol: ResolverProtocolUDP,
		Address:  r.address.String(),
	}
}

func (r *ResolverUDP) Query(ctx context.Context, msg []byte, _ bool) ([]byte, error) {
	r.wg.Add(1)
	defer r.wg.Done()

	// Regenerate a random ID for the query to be forwarded, avoiding conflicts
	// from multiple clients.
	qmsg := dnsmsg.RawMsg(msg)
	oldQID := qmsg.GetID()
	newQID := uint16(r.rand.IntN(1 << 16))
	qmsg.SetID(newQID)

	respCh := make(chan []byte, 1)
	r.sessions.Store(newQID, &udpSession{
		response: respCh,
	})
	defer func() {
		r.sessions.Delete(newQID)
		close(respCh)
	}()

	select {
	case r.queries <- []byte(qmsg):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case resp := <-respCh:
		dnsmsg.RawMsg(resp).SetID(oldQID) // Recover the query ID.
		return resp, nil
	case <-ctx.Done():
		log.Warnf("[%s] query timed out", r.name)
		return nil, ctx.Err()
	}
}

func (r *ResolverUDP) Close() {
	r.cancel()
	r.wg.Wait()
	log.Infof("[%s] closed", r.name)
}

func (r *ResolverUDP) worker(ctx context.Context) {
	defer r.wg.Done()

	var conn *net.UDPConn
	var (
		backoffBase = 100 * time.Millisecond
		backoffCap  = 1000 * time.Millisecond
		backoff     = backoffBase
	)

	for {
		select {
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
			log.Infof("[%s] stopped worker", r.name)
			return

		case query := <-r.queries:
			if conn == nil {
				var err error
				conn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(r.address))
				if err != nil {
					log.Errorf("[%s] failed to dial UDP to %s", r.name, r.address)
					time.Sleep(backoff)
					backoff = min(backoff*2, backoffCap)
					// Requeue the query for retry.
					go func(q []byte) {
						r.queries <- q
					}(query)
					continue
				}

				log.Debugf("[%s] UDP connected to %s", r.name, r.address)
				backoff = backoffBase

				r.wg.Add(1)
				go r.receive(conn)
			}

			if _, err := conn.Write(query); err != nil {
				log.Errorf("[%s] failed to send query: %v", r.name, err)
				conn.Close()
				conn = nil
				// Requeue the query for retry.
				go func(q []byte) {
					r.queries <- q
				}(query)
			}
		}
	}
}

func (r *ResolverUDP) receive(conn *net.UDPConn) {
	defer r.wg.Done()

	buf := make([]byte, maxResponseSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Debugf("[%s] UDP connection closed; stop receiving", r.name)
			} else {
				log.Errorf("[%s] failed to read response: %v", r.name, err)
			}
			return
		}

		resp := make([]byte, n)
		copy(resp, buf[:n])
		queryID := dnsmsg.RawMsg(resp).GetID()
		if v, ok := r.sessions.Load(queryID); ok {
			session := v.(*udpSession)
			select {
			case session.response <- resp:
			default:
				// Drop if no one is waiting.
			}
		}
	}
}

// ----------------------------------------------------------

type ResolverTCP struct {
	name    string
	address netip.AddrPort

	keepAlive   net.KeepAliveConfig
	dialTimeout time.Duration

	poolMaxConns  int
	poolIdleConns int
	connPool      ConnPool

	wg sync.WaitGroup
}

func NewResolverTCP(re *ResolverExport) (*ResolverTCP, error) {
	if err := re.Validate(); err != nil {
		return nil, err
	}

	addrport, _ := netip.ParseAddrPort(re.Address)

	r := &ResolverTCP{
		name:    re.Name,
		address: addrport,
		keepAlive: net.KeepAliveConfig{
			Enable:   re.KeepaliveEnable,
			Idle:     time.Duration(re.KeepaliveIdle) * time.Second,
			Interval: time.Duration(re.KeepaliveInterval) * time.Second,
			Count:    re.KeepaliveCount,
		},
		poolMaxConns:  re.PoolMaxConns,
		poolIdleConns: re.PoolIdleConns,
	}
	r.connPool = NewConnPool(addrport, r.poolMaxConns, r.poolIdleConns,
		r.dialTimeout, r.keepAlive)

	return r, nil
}

func (r *ResolverTCP) Export() *ResolverExport {
	return &ResolverExport{
		Name:     r.name,
		Protocol: ResolverProtocolTCP,
		Address:  r.address.String(),

		PoolMaxConns:  r.poolMaxConns,
		PoolIdleConns: r.poolIdleConns,

		DialTimeout: int(r.dialTimeout.Seconds()),

		KeepaliveEnable:   r.keepAlive.Enable,
		KeepaliveIdle:     int(r.keepAlive.Idle.Seconds()),
		KeepaliveInterval: int(r.keepAlive.Interval.Seconds()),
		KeepaliveCount:    r.keepAlive.Count,
	}
}

func (r *ResolverTCP) Query(ctx context.Context, msg []byte, _ bool) ([]byte, error) {
	r.wg.Add(1)
	defer r.wg.Done()

	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)

	var conn net.Conn
	var err error
	defer func() {
		if conn != nil {
			r.connPool.Put(conn, err != nil) // discard connection on error
		}
	}()

	for try := 0; try < 2; try++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if conn != nil {
			r.connPool.Put(conn, true) // discard previous broken connection
			conn = nil                 // just be safe
		}

		conn, err = r.connPool.Get()
		if err != nil {
			log.Errorf("[%s] failed to get a connection: %v", r.name, err)
			break
		}

		// Apply deadline from context.
		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		} else {
			conn.SetWriteDeadline(time.Now().Add(defaultTimeouts.Write))
			conn.SetReadDeadline(time.Now().Add(defaultTimeouts.Read))
		}

		// Send query packet.
		_, err = conn.Write(buf)
		if err != nil {
			if errors.Is(err, syscall.EPIPE) {
				log.Debugf("[%s] connection already closed", r.name)
			} else {
				log.Errorf("[%s] failed to send query: %v", r.name, err)
			}
			continue // retry
		}
		log.Debugf("[%s] sent query", r.name)

		// Read response length.
		lbuf := make([]byte, 2)
		_, err = io.ReadFull(conn, lbuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debugf("[%s] remote closed socket", r.name)
			} else if errors.Is(err, net.ErrClosed) {
				log.Debugf("[%s] socket closed", r.name)
			} else {
				log.Errorf("[%s] failed to read response length: %v", r.name, err)
			}
			continue // retry
		}

		// Read response content.
		rlength := binary.BigEndian.Uint16(lbuf)
		resp := make([]byte, rlength)
		_, err = io.ReadFull(conn, resp)
		if err != nil {
			log.Errorf("[%s] failed to read response content: %v", r.name, err)
			break // length already read; cannot retry
		}

		log.Debugf("[%s] received response (len=2+%d)", r.name, rlength)
		return resp, nil
	}

	return nil, err
}

func (r *ResolverTCP) Close() {
	r.connPool.Close()
	r.wg.Wait()
	log.Infof("[%s] closed", r.name)
}

// ----------------------------------------------------------

type ResolverDoT struct {
	*ResolverTCP
	tlsConfig        *tls.Config
	handshakeTimeout time.Duration
}

func NewResolverDoT(re *ResolverExport) (*ResolverDoT, error) {
	resolver, err := NewResolverTCP(re)
	if err != nil {
		return nil, err
	}

	r := &ResolverDoT{
		ResolverTCP: resolver,
		tlsConfig: &tls.Config{
			RootCAs:    config.Get().CaPool,
			ServerName: re.ServerName,
		},
		handshakeTimeout: time.Duration(re.HandshakeTimeout) * time.Second,
	}
	r.connPool = NewConnPoolTLS(r.connPool.(*ConnPoolTCP),
		r.tlsConfig, r.handshakeTimeout)

	return r, nil
}

func (r *ResolverDoT) Export() *ResolverExport {
	re := r.ResolverTCP.Export()
	re.Protocol = ResolverProtocolDoT
	re.ServerName = r.tlsConfig.ServerName
	re.HandshakeTimeout = int(r.handshakeTimeout.Seconds())
	return re
}
