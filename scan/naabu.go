// Copyright (c) Kopexa GmbH
// SPDX-License-Identifier: BUSL-1.1

package scan

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/kopexa-grc/domainsec/inventory"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// We scan for the following ports by default:
// Databases:
// - 3306, 5432, 1433, 1521, 27017
// FTP: 21, 69, 989, 990
// ICS: 502, 102, 20000 (disabled)
// VPN: 500, 1701, 1723, 4500, 1194, 51820
// Remote Access: 22, 3389, 5900, 3128 ( Critically for NIS2! )
// Mail: 25, 110, 143, 465, 587, 993, 995
// Web: 80, 443, 8080, 8443, 9443, 10443
// ports scans A/AAAA targets with naabu and merges open ports back into the corresponding HostEntry(ies).
func (s *Scanner) ports(ctx context.Context, hosts []*inventory.HostEntry) error {
	rawTargets := make([]string, 0, len(hosts))
	ipToHosts := make(map[string][]*inventory.HostEntry, len(hosts)*2)
	nameToHost := make(map[string]*inventory.HostEntry, len(hosts))

	for _, h := range hosts {
		hn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h.GetHost())), ".")
		if hn != "" {
			nameToHost[hn] = h
		}
		for _, ip := range h.GetARecords() {
			ip = strings.TrimSpace(ip)
			if ip == "" || !isIP(ip) {
				continue
			}
			rawTargets = append(rawTargets, ip)
			ipToHosts[ip] = append(ipToHosts[ip], h)
		}
		for _, ip := range h.GetAaaaRecords() {
			ip = strings.TrimSpace(ip)
			if ip == "" || !isIP(ip) {
				continue
			}
			rawTargets = append(rawTargets, ip)
			ipToHosts[ip] = append(ipToHosts[ip], h)
		}
	}

	if len(rawTargets) == 0 {
		log.Println("No hosts found for port scanning")
		return nil
	}

	var mu sync.Mutex
	seenPortKey := make(map[*inventory.HostEntry]map[string]struct{})

	appendPort := func(h *inventory.HostEntry, p *port.Port) {
		if h == nil || p == nil || p.Port <= 0 {
			return
		}
		proto := protocolToString(p.Protocol) // <-- Enum → string
		key := proto + "/" + strconv.Itoa(p.Port)

		mu.Lock()
		defer mu.Unlock()

		if seenPortKey[h] == nil {
			seenPortKey[h] = make(map[string]struct{}, 8)
		}
		if _, ok := seenPortKey[h][key]; ok {
			return
		}
		seenPortKey[h][key] = struct{}{}

		h.Ports = append(h.Ports, &inventory.Port{
			Port:     int64(p.Port),
			Protocol: proto,
			Tls:      inferTLS(p), // <-- nutzt Service-Hinweise + Fallback
		})
	}

	// Initialize Naabu with default options
	naabuOpts := &runner.Options{
		DisableStdin: true,
		Silent:       true,
		Stdin:        false,
		//Ports:            "80,443,8080,8443,9443,10443,25,110,143,465,587,993,995,22,3389,5900,3128,21,69,989,990,500,1701,1723,4500,1194,51820,3306,5432,1433,1521,27017", // Scan all ports
		Threads:          10,
		Verify:           true,
		Retries:          1,
		Timeout:          30,
		ServiceDiscovery: true,
		ServiceVersion:   true,
		Host:             goflags.StringSlice(rawTargets),
		Ping:             true,
		ExcludeCDN:       true,
		OnResult: func(r *result.HostResult) {
			// Kandidaten per IP
			var candidates []*inventory.HostEntry
			if ip := strings.TrimSpace(r.IP); ip != "" && isIP(ip) {
				candidates = append(candidates, ipToHosts[ip]...)
			}
			// Optional zusätzlich per Hostname (naabu liefert Host ggf. mit)
			if host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Host)), "."); host != "" {
				if h, ok := nameToHost[host]; ok {
					candidates = append(candidates, h)
				}
			}
			if len(candidates) == 0 {
				return
			}

			for _, p := range r.Ports {
				if p == nil {
					continue
				}
				for _, h := range candidates {
					appendPort(h, p)
				}
			}
		},
	}

	// Create a new Naabu runner
	naabuRunner, err := runner.NewRunner(naabuOpts)
	if err != nil {
		return err
	}
	defer func() {
		if err := naabuRunner.Close(); err != nil {
			log.Printf("could not close naabu runner: %s\n", err)
		}
	}()

	err = naabuRunner.RunEnumeration(ctx)
	if err != nil {
		return err
	}

	return nil
}

func protocolToString(p protocol.Protocol) string {
	// adjust if your enum names differ
	switch p {
	case protocol.TCP:
		return "tcp"
	case protocol.UDP:
		return "udp"
	default:
		return strings.ToLower(p.String())
	}
}

func guessTLSByPort(n int) bool {
	switch n {
	case 443, 8443, 9443, 10443, 6443, 4443, 4433, 853, 993, 995, 465, 587, 636:
		return true
	default:
		return false
	}
}

// inferTLS prefers service signals, falls back to deprecated p.TLS, then to port heuristics.
func inferTLS(p *port.Port) bool {
	// If your Service struct exposes TLS, ALPN, or certificate info, check here.
	if p.Service != nil {
		// try to infer from service name / metadata if available
		name := strings.ToLower(p.Service.Name) // if Name exists; adjust to your struct
		if strings.Contains(name, "tls") || strings.Contains(name, "ssl") || strings.Contains(name, "https") {
			return true
		}
		// if Service has a boolean like p.Service.TLS { return true }
	}
	if p.TLS {
		return true
	}
	return guessTLSByPort(p.Port)
}

// MergePortsIntoHostEntry merges the discovered ports into an inventory.HostEntry (deduping proto/port)
func MergePortsIntoHostEntry(
	dst *inventory.HostEntry,
	srcPorts []*port.Port,
) {
	if dst == nil || len(srcPorts) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(dst.Ports)+len(srcPorts))

	// seed existing
	for _, ip := range dst.Ports {
		if ip == nil {
			continue
		}
		k := strings.ToLower(ip.GetProtocol()) + "/" + strconv.FormatInt(ip.GetPort(), 10)
		seen[k] = struct{}{}
	}

	for _, sp := range srcPorts {
		if sp == nil || sp.Port <= 0 {
			continue
		}
		proto := protocolToString(sp.Protocol)
		k := proto + "/" + strconv.Itoa(sp.Port)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}

		dst.Ports = append(dst.Ports, &inventory.Port{
			Port:     int64(sp.Port),
			Protocol: proto,
			Tls:      inferTLS(sp),
		})
	}

}

// isIP returns true if s is a valid IPv4 or IPv6 address.
func isIP(s string) bool {
	return net.ParseIP(s) != nil
}
