// SPDX-License-Identifier: MIT
//
// Resolvers to process the forwarded queries.
//

package dns

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"kexuedns/config"
	"kexuedns/log"
)

const (
	dotPort     = 853
	channelSize = 100

	readTimeout  = 15 * time.Second
	writeTimeout = 5 * time.Second

	keepaliveIdle     = 25 * time.Second
	keepaliveInterval = 25 * time.Second
	keepaliveCount    = 3
)

// NOTE: Only support DoT (DNS-over-TLS) protocol for security and simplicity.
type Resolver struct {
	name      string // name to identify in log messages
	ip        netip.Addr
	port      int
	hostname  string // name to verify the TLS certificate
	client    *tls.Conn
	responses chan RawMsg
	reading   bool
}

func NewResolver(ip string, port int, hostname string) (*Resolver, error) {
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
		if addr.Is4() {
			name = fmt.Sprintf("%s:%d", addr.String(), port)
		} else {
			name = fmt.Sprintf("[%s]:%d", addr.String(), port)
		}
	}
	r := &Resolver{
		name:      name,
		ip:        addr,
		port:      port,
		hostname:  hostname,
		responses: make(chan RawMsg, channelSize),
	}
	return r, nil
}

func (r *Resolver) Query(msg RawMsg) error {
	l := len(msg)
	buf := make([]byte, 2+l)
	buf[0] = byte(l >> 8)
	buf[1] = byte(l)
	copy(buf[2:], msg)

	retrying := false
Lretry:
	if r.client == nil {
		if err := r.connect(); err != nil {
			return err
		}
	}
	r.client.SetWriteDeadline(time.Now().Add(writeTimeout))
	n, err := r.client.Write(buf)
	if err != nil || n != 2+l {
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

	log.Debugf("[%s] sent query (len=2+%d)", r.name, l)
	return nil
}

func (r *Resolver) Receive(ch chan RawMsg) {
	for {
		msg, ok := <-r.responses
		if !ok {
			log.Infof("[%s] channel responses closed", r.name)
			return
		}
		ch <- msg
	}
}

// Disconnect and close channels.
func (r *Resolver) Close() {
	r.disconnect()
	close(r.responses)
	log.Infof("[%s] closed", r.name)
}

func (r *Resolver) disconnect() {
	if r.client == nil {
		log.Warnf("[%s] not connected yet", r.name)
		return
	}

	r.client.Close()
	r.client = nil
	log.Infof("[%s] disconnected", r.name)
}

// Connect to the resolver and perform TLS handshake.
func (r *Resolver) connect() error {
	if r.client != nil {
		panic("already connected")
	}

	raddr := net.TCPAddr{
		IP:   net.IP(r.ip.AsSlice()),
		Port: r.port,
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
		RootCAs:    config.RootCAs,
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

	r.client = conn
	log.Infof("[%s] connected", r.name)
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

	r.reading = true
	log.Infof("[%s] started reading", r.name)

	for {
		// read response length
		lbuf := make([]byte, 2)
		_, err := io.ReadFull(r.client, lbuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debugf("[%s] remote closed socket", r.name)
			} else {
				log.Errorf("[%s] failed to read response length: %v",
					r.name, err)
			}
			break
		}

		// read response content
		l := int(lbuf[0])<<8 | int(lbuf[1])
		mbuf := make([]byte, l)
		_, err = io.ReadFull(r.client, mbuf)
		if err != nil {
			log.Errorf("[%s] failed to read response content: %v", r.name, err)
			break
		}

		log.Debugf("[%s] received response (len=2+%d)", r.name, l)
		r.responses <- RawMsg(mbuf)
	}

	r.reading = false
	log.Infof("[%s] stopped reading", r.name)
}
