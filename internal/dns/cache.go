package dns

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type cacheEntry struct {
	value      any
	expiresAt  time.Time
}

type Resolver struct {
	mu             sync.RWMutex
	cache          map[string]cacheEntry
	cacheTTL       time.Duration
	maxCacheSize   int
	maxLookups     int
}

func NewResolver(cacheTTL time.Duration, maxCacheSize, maxLookups int) *Resolver {
	return &Resolver{
		cache:        make(map[string]cacheEntry),
		cacheTTL:     cacheTTL,
		maxCacheSize: maxCacheSize,
		maxLookups:   maxLookups,
	}
}

func (r *Resolver) LookupHost(host string) ([]string, error) {
	res, err := r.lookup("host:"+host, func() (any, error) {
		return net.LookupHost(host)
	})
	if err != nil {
		return nil, err
	}
	addrs, ok := res.([]string)
	if !ok {
		return nil, fmt.Errorf("unexpected type for host lookup: %T", res)
	}
	return addrs, nil
}

func (r *Resolver) LookupTXT(name string) ([]string, error) {
	res, err := r.lookup("txt:"+name, func() (any, error) {
		return net.LookupTXT(name)
	})
	if err != nil {
		return nil, err
	}
	txts, ok := res.([]string)
	if !ok {
		return nil, fmt.Errorf("unexpected type for TXT lookup: %T", res)
	}
	return txts, nil
}

func (r *Resolver) LookupMX(name string) ([]*net.MX, error) {
	res, err := r.lookup("mx:"+name, func() (any, error) {
		return net.LookupMX(name)
	})
	if err != nil {
		return nil, err
	}
	mxs, ok := res.([]*net.MX)
	if !ok {
		return nil, fmt.Errorf("unexpected type for MX lookup: %T", res)
	}
	return mxs, nil
}

func (r *Resolver) lookup(key string, fn func() (any, error)) (any, error) {
	r.mu.RLock()
	entry, found := r.cache[key]
	r.mu.RUnlock()
	if found && time.Now().Before(entry.expiresAt) {
		switch v := entry.value.(type) {
		case error:
			return nil, v
		default:
			return v, nil
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check after locking
	entry, found = r.cache[key]
	if found && time.Now().Before(entry.expiresAt) {
		switch v := entry.value.(type) {
		case error:
			return nil, v
		default:
			return v, nil
		}
	}

	if len(r.cache) >= r.maxCacheSize {
		// Simple eviction: remove one random entry (could be improved)
		for k := range r.cache {
			delete(r.cache, k)
			break
		}
	}

	val, err := fn()
	r.cache[key] = cacheEntry{value: val, expiresAt: time.Now().Add(r.cacheTTL)}
	if err != nil {
		r.cache[key] = cacheEntry{value: err, expiresAt: time.Now().Add(r.cacheTTL)}
		return nil, err
	}
	return val, nil
}
