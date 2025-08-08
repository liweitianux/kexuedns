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
	readTimeout  = 15 * time.Second
	writeTimeout = 5 * time.Second

	keepaliveIdle     = 25 * time.Second
	keepaliveInterval = 25 * time.Second
	keepaliveCount    = 3
)

type DNSResolver interface {
	Export() *ResolverExport
	Start(forwarder chan []byte)
	Stop()
	Query(msg []byte) error
}

type ResolverExport struct {
	// Name to identify in log messages
	Name string `json:"name"`
	// Resolver address: "[ipv4]:port", "[ipv6]:port"
	Address string `json:"address"`
	// Name to verify the TLS certificate
	Hostname string `json:"hostname"`
}

// TODO: DoH (HTTPS) with auth (basic, bearer)
// TODO: UDP + TCP
func NewResolverFromExport(re *ResolverExport) (DNSResolver, error) {
	addrport, err := netip.ParseAddrPort(re.Address)
	if err != nil {
		log.Errorf("invalid address (%s): %v", re.Address, err)
		return nil, err
	}

	name := re.Name
	if name == "" {
		if re.Hostname != "" {
			name = re.Hostname
		} else {
			name = addrport.String()
		}
	}

	r := &ResolverDoT{
		name:     name,
		address:  addrport,
		hostname: re.Hostname,
	}
	return r, nil
}

type ResolverDoT struct {
	name     string
	address  netip.AddrPort
	hostname string

	client      *tls.Conn
	clientLock  sync.Mutex    // protect concurrent connect()/disconnect()
	connections chan struct{} // notify new connections

	running bool
	cancel  context.CancelFunc // stop the resolver
	wg      sync.WaitGroup
	lock    sync.Mutex // protect concurrent Start()/Stop()
}

func (r *ResolverDoT) Export() *ResolverExport {
	return &ResolverExport{
		Name:     r.name,
		Address:  r.address.String(),
		Hostname: r.hostname,
	}
}

func (r *ResolverDoT) Query(msg []byte) error {
	length := len(msg)
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf, uint16(length))
	copy(buf[2:], msg)

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

		return err
	}

	log.Debugf("[%s] sent query (len=2+%d)", r.name, length)
	return nil
}

func (r *ResolverDoT) Start(forwarder chan []byte) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.running {
		return
	}

	if r.connections == nil {
		r.connections = make(chan struct{})
	}

	ctx, cancel := context.WithCancel(context.Background())

	r.wg.Add(1)
	go r.relay(ctx, forwarder)

	r.cancel = cancel
	r.running = true
	log.Infof("[%s] started", r.name)
}

func (r *ResolverDoT) Stop() {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.running {
		return
	}

	r.cancel()
	r.disconnect()

	// Empty the connections channel.
	select {
	case <-r.connections:
	default:
	}

	r.wg.Wait()
	r.running = false
	log.Infof("[%s] stopped", r.name)
}

func (r *ResolverDoT) disconnect() {
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
func (r *ResolverDoT) connect() error {
	r.clientLock.Lock()
	defer r.clientLock.Unlock()

	if r.client != nil {
		return nil
	}

	tconn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(r.address))
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
	r.connections <- struct{}{}

	return nil
}

// Relay the responses to the forwarder.
func (r *ResolverDoT) relay(ctx context.Context, forwarder chan []byte) {
	log.Debugf("[%s] started relaying", r.name)

	for {
		select {
		case <-ctx.Done():
			log.Debugf("[%s] stop relaying", r.name)
			r.wg.Done()
			return
		case <-r.connections:
			r.read(forwarder)
		}
	}
}

// Read responses from resolver and send to forwarder.
func (r *ResolverDoT) read(forwarder chan []byte) {
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
		forwarder <- resp
	}

	r.disconnect()
	log.Debugf("[%s] stopped reading", r.name)
}
