package scan

import (
	"context"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/kopexa-grc/domainsec/inventory"
)

func TestFindHosts(t *testing.T) {

	scanner := NewScanner()
	ctx := context.Background()

	hosts := []*inventory.HostEntry{
		{Host: "knk.de"},
		//{Host: "kopexa.com"},
	}

	for _, host := range hosts {
		results, err := scanner.Chain(ctx, host.Host)
		if err != nil {
			t.Fatalf("Scan failed for host %s: %v", host.Host, err)
		}

		spew.Dump(results)
	}

}
