// Copyright (c) Kopexa GmbH
// SPDX-License-Identifier: BUSL-1.1

package scan

import (
	"context"

	"github.com/kopexa-grc/domainsec/inventory"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func (s *Scanner) findHosts(ctx context.Context, eTLD string) ([]*inventory.HostEntry, error) {
	results := make([]*inventory.HostEntry, 0)

	subfinderOpts := &runner.Options{
		Stdin:              false,
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		ResultCallback: func(result *resolve.HostEntry) {
			if result == nil || result.Host == "" {
				return
			}
			results = append(results, &inventory.HostEntry{
				Host:   result.Host,
				Domain: result.Domain,
				Source: result.Source,
			})
		},
		// ProviderConfig: "your_provider_config.yaml",
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, err
	}

	_, err = subfinder.EnumerateSingleDomainWithCtx(ctx, eTLD, nil)
	if err != nil {
		return nil, err
	}

	return results, nil
}
