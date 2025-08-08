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
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"kexuedns/config"
	"kexuedns/log"
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
	ResolverProtocolDoT     = "dot"     // DNS-over-TLS
	ResolverProtocolDoH     = "doh"     // DNS-over-HTTPS
)

type DNSResolver interface {
	Export() *ResolverExport
	Close()
	Query(ctx context.Context, msg []byte) ([]byte, error)
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
	case ResolverProtocolDoT:
		return NewResolverDoT(re)
	default:
		// TODO ResolverProtocolDefault
		// TODO: ResolverProtocolDoH
		return nil, fmt.Errorf("unknown resolver protocol: %s", re.Protocol)
	}
}

// ----------------------------------------------------------

type ResolverDoT struct {
	name    string
	address netip.AddrPort

	tlsConfig        *tls.Config
	keepAlive        net.KeepAliveConfig
	dialTimeout      time.Duration
	handshakeTimeout time.Duration

	poolMaxConns  int
	poolIdleConns int
	connPool      *ConnPoolTLS

	wg sync.WaitGroup
}

func NewResolverDoT(re *ResolverExport) (*ResolverDoT, error) {
	if err := re.Validate(); err != nil {
		return nil, err
	}

	addrport, _ := netip.ParseAddrPort(re.Address)

	r := &ResolverDoT{
		name:    re.Name,
		address: addrport,
		tlsConfig: &tls.Config{
			RootCAs:    config.Get().CaPool,
			ServerName: re.ServerName,
		},
		keepAlive: net.KeepAliveConfig{
			Enable:   re.KeepaliveEnable,
			Idle:     time.Duration(re.KeepaliveIdle) * time.Second,
			Interval: time.Duration(re.KeepaliveInterval) * time.Second,
			Count:    re.KeepaliveCount,
		},
		dialTimeout:      time.Duration(re.DialTimeout) * time.Second,
		handshakeTimeout: time.Duration(re.HandshakeTimeout) * time.Second,
		poolMaxConns:     re.PoolMaxConns,
		poolIdleConns:    re.PoolIdleConns,
	}

	pool := NewConnPool(addrport, r.poolMaxConns, r.poolIdleConns,
		r.dialTimeout, r.keepAlive)
	r.connPool = NewConnPoolTLS(pool, r.tlsConfig, r.handshakeTimeout)

	return r, nil
}

func (r *ResolverDoT) Export() *ResolverExport {
	return &ResolverExport{
		Name:       r.name,
		Protocol:   ResolverProtocolDoT,
		Address:    r.address.String(),
		ServerName: r.tlsConfig.ServerName,

		PoolMaxConns:  r.poolMaxConns,
		PoolIdleConns: r.poolIdleConns,

		DialTimeout:      int(r.dialTimeout.Seconds()),
		HandshakeTimeout: int(r.handshakeTimeout.Seconds()),

		KeepaliveEnable:   r.keepAlive.Enable,
		KeepaliveIdle:     int(r.keepAlive.Idle.Seconds()),
		KeepaliveInterval: int(r.keepAlive.Interval.Seconds()),
		KeepaliveCount:    r.keepAlive.Count,
	}
}

func (r *ResolverDoT) Query(ctx context.Context, msg []byte) ([]byte, error) {
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

func (r *ResolverDoT) Close() {
	r.connPool.Close()
	r.wg.Wait()
	log.Infof("[%s] closed", r.name)
}
