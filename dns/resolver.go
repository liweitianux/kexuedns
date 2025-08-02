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
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"kexuedns/config"
	"kexuedns/log"
)

const (
	dotPort     = 853 // default DoT port
	channelSize = 100

	readTimeout  = 15 * time.Second
	writeTimeout = 5 * time.Second

	keepaliveIdle     = 25 * time.Second
	keepaliveInterval = 25 * time.Second
	keepaliveCount    = 3
)

// NOTE: Only support DoT (DNS-over-TLS) protocol for security and simplicity.
type Resolver struct {
	name     string // name to identify in log messages
	ip       netip.Addr
	port     uint16
	hostname string // name to verify the TLS certificate

	client     *tls.Conn
	clientLock sync.Mutex // protect concurrent connect()/disconnect()

	responses chan []byte
	running   bool
	reading   bool

	cancel context.CancelFunc // stop the resolver
	wg     sync.WaitGroup
	lock   sync.Mutex // protect concurrent Start()/Stop()
}

func NewResolver(ip string, port uint16, hostname string) (*Resolver, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		log.Errorf("invalid IP address (%s): %v", ip, addr)
		return nil, err
	}
	if port <= 0 {
		port = dotPort
	}
	name := hostname
	if name == "" {
		addrport := netip.AddrPortFrom(addr, port)
		name = addrport.String()
	}
	r := &Resolver{
		name:     name,
		ip:       addr,
		port:     port,
		hostname: hostname,
	}
	// Perform the connection to catch the possible errors early.
	if err := r.connect(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Resolver) Query(msg []byte) error {
	length := len(msg)
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf, uint16(length))
	copy(buf[2:], msg)

	retrying := false
Lretry:
	if err := r.connect(); err != nil {
		return err
	}
	r.client.SetWriteDeadline(time.Now().Add(writeTimeout))
	n, err := r.client.Write(buf)
	if err != nil || n != 2+length {
		if err == nil {
			err = errors.New("write incomplete")
		} else if errors.Is(err, syscall.EPIPE) {
			log.Debugf("[%s] connection already closed", r.name)
		} else {
			log.Errorf("[%s] failed to send query: %v", r.name, err)
		}
		r.disconnect()

		if !retrying {
			log.Warnf("[%s] retrying the query", r.name)
			retrying = true
			goto Lretry
		}

		return err
	}

	// start reading response
	go r.read()

	log.Debugf("[%s] sent query (len=2+%d)", r.name, length)
	return nil
}

func (r *Resolver) Start(forwarder chan []byte) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.running {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	r.wg.Add(1)
	go r.relay(ctx, forwarder)

	r.cancel = cancel
	r.running = true
	log.Infof("[%s] started", r.name)
}

func (r *Resolver) Stop() {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.running {
		return
	}

	r.cancel()
	r.disconnect()
	r.wg.Wait()

	r.running = false
	log.Infof("[%s] stopped", r.name)
}

// Relay the responses to the forwarder.
func (r *Resolver) relay(ctx context.Context, forwarder chan []byte) {
	log.Debugf("[%s] started relaying", r.name)
	r.responses = make(chan []byte, channelSize)

	for {
		select {
		case <-ctx.Done():
			close(r.responses)
			log.Debugf("[%s] stop relaying", r.name)
			r.wg.Done()
			return
		case msg := <-r.responses:
			forwarder <- msg
		}
	}
}

func (r *Resolver) disconnect() {
	r.clientLock.Lock()
	defer r.clientLock.Unlock()

	if r.client == nil {
		return
	}

	r.client.Close()
	r.client = nil
	log.Infof("[%s] disconnected", r.name)
}

// Connect to the resolver and perform TLS handshake.
func (r *Resolver) connect() error {
	r.clientLock.Lock()
	defer r.clientLock.Unlock()

	if r.client != nil {
		return nil
	}

	raddr := net.TCPAddr{
		IP:   net.IP(r.ip.AsSlice()),
		Port: int(r.port),
	}
	tconn, err := net.DialTCP("tcp", nil, &raddr)
	if err != nil {
		log.Errorf("[%s] tcp dial failed: %v", r.name, err)
		return err
	}

	// NOTE: Require Go 1.23.0+
	err = tconn.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     keepaliveIdle,
		Interval: keepaliveInterval,
		Count:    keepaliveCount,
	})
	if err != nil {
		log.Errorf("[%s] failed to set keepalive: %v", r.name, err)
		return err
	}

	// TLS connection and handshake
	conn := tls.Client(tconn, &tls.Config{
		RootCAs:    config.Get().CaPool,
		ServerName: r.hostname,
	})
	// Set deadlines to prevent indefinite blocking.
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	err = conn.Handshake()
	if err != nil {
		log.Errorf("[%s] tls handshake failure: %v", r.name, err)
		return err
	}
	conn.SetDeadline(time.Time{}) // Reset the deadline.

	cs := conn.ConnectionState()
	log.Infof("[%s] connected: Version=%s, CipherSuite=%s, ServerName=%s, ALPN=%s",
		r.name, tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite),
		cs.ServerName, cs.NegotiatedProtocol)

	r.client = conn
	return nil
}

// Read responses from resolver.
// NOTE: Close the connection would break the reading.
func (r *Resolver) read() {
	if r.client == nil {
		panic("not connected yet")
	}
	if r.reading {
		return
	}

	r.wg.Add(1)
	r.reading = true
	log.Debugf("[%s] started reading", r.name)

	for {
		// read response length
		lbuf := make([]byte, 2)
		if _, err := io.ReadFull(r.client, lbuf); err != nil {
			if errors.Is(err, io.EOF) {
				log.Debugf("[%s] remote closed socket", r.name)
			} else if errors.Is(err, net.ErrClosed) {
				log.Debugf("[%s] socket closed", r.name)
			} else {
				log.Errorf("[%s] failed to read response length: %v",
					r.name, err)
			}
			break
		}

		// read response content
		length := binary.BigEndian.Uint16(lbuf)
		resp := make([]byte, length)
		if _, err := io.ReadFull(r.client, resp); err != nil {
			log.Errorf("[%s] failed to read response content: %v", r.name, err)
			break
		}

		log.Debugf("[%s] received response (len=2+%d)", r.name, length)
		r.responses <- resp
	}

	r.reading = false
	log.Debugf("[%s] stopped reading", r.name)

	r.disconnect()
	r.wg.Done()
}
