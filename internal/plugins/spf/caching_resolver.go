package spf

import (
	"context"
	"github.com/mailtive/smtpd/internal/dns"
	"github.com/mailtive/smtpd/internal/logging"
)

type cachingResolver struct {
	cache *dns.Resolver
}

func (cr *cachingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return cr.cache.LookupTXT(name)
}

// NewCachingSPFChecker creates an SPFChecker using a DNS cache.
func NewCachingSPFChecker(logger *logging.Logger, cache *dns.Resolver) *SPFChecker {
	if logger == nil {
		logger = logging.Default()
	}
	return &SPFChecker{
		resolver: &cachingResolver{cache: cache},
		logger:   logger.WithFields(map[string]interface{}{"plugin": "spf"}),
	}
}
