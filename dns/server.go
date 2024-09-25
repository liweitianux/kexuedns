// SPDX-License-Identifier: MIT
//
// DNS server that accepts and forward queries.
//

package dns

import (
	"net"

	"kexuedns/log"
)

const (
	maxQuerySize = 1024 // bytes
)

func ListenAndServe(address string) error {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		log.Errorf("failed to listen UDP at [%s]: %v", address, err)
		return err
	}
	defer pc.Close()

	for {
		buf := make([]byte, maxQuerySize)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Warnf("failed to read packet: %v", err)
			continue
		}

		go serve(pc, addr, buf[:n])
	}
}

func serve(pc net.PacketConn, addr net.Addr, buf []byte) {
	// TODO...
}
