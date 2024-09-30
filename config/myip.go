// SPDX-License-Identifier: MIT
//
// Configuration management.
//

package config

import (
	"fmt"
	"net/netip"
	"sync"
)

// My public IP address to be used in EDNS client subnet for better geolocation
// resolution, which is almost necessary for CDN sites.
type myIP struct {
	ipv4 netip.Addr
	ipv6 netip.Addr
	lock sync.RWMutex
}

func (x *myIP) GetV4() (netip.Addr, bool) {
	x.lock.RLock()
	defer x.lock.RUnlock()

	return x.ipv4, x.ipv4.IsValid()
}

func (x *myIP) GetV6() (netip.Addr, bool) {
	x.lock.RLock()
	defer x.lock.RUnlock()

	return x.ipv6, x.ipv6.IsValid()
}

func (x *myIP) SetV4(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("not IP address [%s]: %v", ip, err)
	}
	if !addr.Is4() {
		return fmt.Errorf("not IPv4 address [%s]", ip)
	}
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsMulticast() {
		return fmt.Errorf("not public IPv4 address [%s]", ip)
	}

	x.lock.Lock()
	defer x.lock.Unlock()

	x.ipv4 = addr
	return nil
}

func (x *myIP) SetV6(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("not IP address [%s]: %v", ip, err)
	}
	if !addr.Is6() {
		return fmt.Errorf("not IPv6 address [%s]", ip)
	}
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsMulticast() {
		return fmt.Errorf("not public IPv6 address [%s]", ip)
	}

	x.lock.Lock()
	defer x.lock.Unlock()

	x.ipv6 = addr
	return nil
}

var MyIP = myIP{
	lock: sync.RWMutex{},
}
