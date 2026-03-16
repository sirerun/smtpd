package dmarc

import (
	"context"
	"github.com/sirerun/smtpd/internal/dns"
)

type cachingResolver struct {
	cache *dns.Resolver
}

func (cr *cachingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return cr.cache.LookupTXT(name)
}
