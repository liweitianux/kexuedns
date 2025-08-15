// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Aaron LI
//
// Resolver routing.
//

package dns

import (
	"errors"
	"sync"

	"kexuedns/log"
	"kexuedns/util/dnstrie"
)

// Maximum number of routes supported in a router.
// Valid route index is: [1, MaxRoutes-1]
// Smaller index means higher priority.
const MaxRoutes = 10

var (
	ErrRouteIndexInvalid = errors.New("route index invalid")
)

type Router struct {
	resolver Resolver // default resolver
	routes   [MaxRoutes]*Route
	lock     sync.RWMutex
}

// TODO: resolver group & dispatch policy
type Route struct {
	name     string
	resolver Resolver
	trie     *dnstrie.DNSTrie
}

// Export struct for external interactions, e.g., with the API.
type RouterExport struct {
	Resolver *ResolverExport `json:"resolver"`
	Routes   []*RouteExport  `json:"routes"`
}

type RouteExport struct {
	Index    int             `json:"index"`
	Name     string          `json:"name"`
	Resolver *ResolverExport `json:"resolver"`
	Zones    []string        `json:"zones"`
}

// Create the router from exported configs.
func NewRouterFromExport(re *RouterExport) (*Router, error) {
	// TODO
	return nil, nil
}

// Export the router configs for external interactions.
func (r *Router) Export() *RouterExport {
	r.lock.RLock()
	defer r.lock.RUnlock()

	re := &RouterExport{}
	if r.resolver != nil {
		re.Resolver = r.resolver.Export()
	}
	for i, rr := range r.routes {
		route := &RouteExport{
			Index: i + 1,
			Name:  rr.name,
		}
		if rr.resolver != nil {
			route.Resolver = rr.resolver.Export()
		}
		if rr.trie != nil {
			zones := rr.trie.Export()
			route.Zones = make([]string, 0, len(zones))
			for z := range zones {
				route.Zones = append(route.Zones, z)
			}
		}
		re.Routes = append(re.Routes, route)
	}
	return re
}

// Set the default resolver.
func (r *Router) SetResolver(re *ResolverExport) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	resolver, err := NewResolverFromExport(re)
	if err != nil {
		log.Errorf("failed to create resolver: %+v, error: %v", re, err)
		return err
	}

	if r.resolver != nil {
		r.resolver.Close()
	}

	r.resolver = resolver
	log.Infof("set default resolver: %+v", re)

	return nil
}

// Get the best-matched resolver for the query name.
func (r *Router) GetResolver(name string) (Resolver, int) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	for i, rr := range r.routes {
		if rr == nil {
			continue
		}
		if _, ok := rr.trie.Match(name); ok {
			return rr.resolver, i
		}
	}

	return r.resolver, -1
}

// Close all resolvers.
func (r *Router) Close() {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.resolver != nil {
		r.resolver.Close()
	}

	for _, rr := range r.routes {
		if rr != nil && rr.resolver != nil {
			rr.resolver.Close()
		}
	}
}
