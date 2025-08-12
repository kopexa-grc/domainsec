package scan

import (
	"context"

	"github.com/kopexa-grc/domainsec/inventory"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Chain(ctx context.Context, target string) ([]*inventory.HostEntry, error) {
	hosts, err := s.findHosts(ctx, target)
	if err != nil {
		return nil, err
	}

	// Run HTTPX on the found hosts
	if err = s.probehosts(ctx, hosts); err != nil {
		return nil, err
	}

	// Run Naabu to scan for open ports
	if err = s.ports(ctx, hosts); err != nil {
		return nil, err
	}

	return hosts, nil
}
