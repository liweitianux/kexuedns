// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Aaron LI
//
// TCP & TLS connection pool.
//

package dns

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"kexuedns/log"
)

type ConnPool interface {
	Get() (net.Conn, error)
	Put(conn net.Conn, discard bool)
	Close()
}

// ConnPool manages a pool of TCP connections.
type ConnPoolTCP struct {
	address     netip.AddrPort      // resolver address
	maxConns    int                 // max total connections
	idleConns   int                 // max idle connections
	dialTimeout time.Duration       // connection dial timeout
	keepAlive   net.KeepAliveConfig // keepalive configs

	conns  chan *pooledConn // idle connections
	active atomic.Int32     // number of active connections (checked out + idle)
}

// pooledConn wraps a net.Conn with last-used timestamp.
type pooledConn struct {
	conn     net.Conn
	lastUsed time.Time
}

// NewConnPool initializes a new connection pool.
func NewConnPool(
	address netip.AddrPort,
	maxConns, idleConns int,
	dialTimeout time.Duration,
	keepAlive net.KeepAliveConfig,
) *ConnPoolTCP {
	if idleConns > maxConns {
		idleConns = maxConns
	}
	return &ConnPoolTCP{
		address:     address,
		maxConns:    maxConns,
		idleConns:   idleConns,
		dialTimeout: dialTimeout,
		keepAlive:   keepAlive,
		conns:       make(chan *pooledConn, idleConns),
	}
}

// dial creates a new TCP connection with keepalive.
func (p *ConnPoolTCP) dial() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.address.String(), p.dialTimeout)
	if err != nil {
		return nil, err
	}

	// NOTE: Require Go 1.23.0+
	tcpConn := conn.(*net.TCPConn)
	if err := tcpConn.SetKeepAliveConfig(p.keepAlive); err != nil {
		log.Warnf("failed to set keepalive: %v", err)
	}

	return conn, nil
}

// Get fetches a healthy connection from the pool (creates one if needed).
func (p *ConnPoolTCP) Get() (conn net.Conn, err error) {
	for {
		select {
		case pc := <-p.conns:
			conn = pc.conn

		default:
			if int(p.active.Load()) >= p.maxConns {
				// Wait for an existing connection to be reused/discarded.
				pc := <-p.conns
				conn = pc.conn
				break
			}

			// Create a new one.
			p.active.Add(1)
			conn, err = p.dial()
			if err != nil {
				log.Errorf("failed to connect to %s, error: %v", p.address, err)
				p.active.Add(-1)
				return nil, err
			}

			log.Debugf("created new connection to %s", p.address)
			return conn, nil
		}

		// Check connection health before reuse.
		if p.isConnAlive(conn) {
			log.Debugf("reuse idle connection to %s", p.address)
			return conn, nil
		}

		log.Debugf("close broken connection to %s", p.address)
		conn.Close()
		p.active.Add(-1)
	}
}

// Put returns a connection back to the pool, or closes it if idle pool full,
// or discards it.
func (p *ConnPoolTCP) Put(conn net.Conn, discard bool) {
	if discard {
		conn.Close()
		p.active.Add(-1)
		log.Debugf("discarded connection to %s", p.address)
		return
	}

	pc := &pooledConn{
		conn:     conn,
		lastUsed: time.Now(),
	}
	select {
	case p.conns <- pc:
		// ok
	default:
		// Pool is full, close the connection.
		conn.Close()
		p.active.Add(-1)
		log.Debugf("pool full; closed connection to %s", p.address)
	}
}

// Close shuts down the pool and all idle connections.
func (p *ConnPoolTCP) Close() {
	close(p.conns)
	for pc := range p.conns {
		pc.conn.Close()
	}
}

// isConnAlive performs simple health check.
//
// NOTE: We could also perform a non-blocking read check to peek for EOF, but
// that would consume at least 1 byte data, which might be unacceptable (e.g.,
// TCP pipelining).  Generally speaking, the connection is only known to be
// healthy by actually using it.  Therefore, it's simpler and more robust for
// the caller to retry if the connection is broken.
func (p *ConnPoolTCP) isConnAlive(conn net.Conn) bool {
	// Zero-byte write check
	conn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	_, err := conn.Write([]byte{})
	conn.SetWriteDeadline(time.Time{}) // clear
	return err == nil
}

// ----------------------------------------------------------

type ConnPoolTLS struct {
	pool             *ConnPoolTCP
	tlsConfig        *tls.Config
	handshakeTimeout time.Duration
}

func NewConnPoolTLS(
	pool *ConnPoolTCP,
	config *tls.Config,
	handshakeTimeout time.Duration,
) *ConnPoolTLS {
	return &ConnPoolTLS{
		pool:             pool,
		tlsConfig:        config,
		handshakeTimeout: handshakeTimeout,
	}
}

func (p *ConnPoolTLS) Get() (net.Conn, error) {
	conn, err := p.pool.Get()
	if err != nil {
		return nil, err
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		return tlsConn, nil
	}

	// New TCP connection, wrap in TLS and do handshake.
	tlsConn := tls.Client(conn, p.tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), p.handshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Errorf("TLS handshake failed: %v", err)
		p.pool.Put(conn, true)
		return nil, err
	}

	cs := tlsConn.ConnectionState()
	log.Debugf("TLS connected: Version=%s, CipherSuite=%s, ServerName=%s, ALPN=%s",
		tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite),
		cs.ServerName, cs.NegotiatedProtocol)
	return tlsConn, nil
}

func (p *ConnPoolTLS) Put(conn net.Conn, discard bool) {
	p.pool.Put(conn, discard)
}

func (p *ConnPoolTLS) Close() {
	p.pool.Close()
}
