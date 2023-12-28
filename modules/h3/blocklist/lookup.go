package blocklist

import (
	"context"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

// LookupIP performs a DNS lookup for the given host using the specified network and resolver.
// It filters out any blocked or localhost Host address from the results.
// If the host address is blocked or localhost, it returns an application error.
// It uses the given resolver and context for the DNS lookup of the host address.
// for all the ips returned by resolver, It filters out any blocked or localhost IP address from the results.
// If the IP address is blocked or locahost , it also returns an application error.
// Otherwise, it returns a slice of the valid IPs and nil for the error.
//
// Parameters:
// - resolver: The net.Resolver to use for the DNS lookup.
// - ctx: The context.Context to use for the DNS lookup.
// - network: The network to use for the DNS lookup ("ip", "ip4", "ip6").
// - host: The host to look up.
//
// Returns:
// - A slice of net.IP addresses for the host that are not blocked or localhost.
// - An error if all IPs are blocked or localhost, or if no IPs are found for the host.
func LookupIP(resolver *net.Resolver, ctx context.Context, network, host string) ([]net.IP, error) {
	if IsHostBlocked(host) || CheckLocalhost(host) {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_APPLICATION_ERROR,
			Err:    fmt.Errorf("host blocked %v", host),
		}
	}

	ips, err := resolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	var targets, blockedIPs []net.IP
	for _, nip := range ips {
		if IsIPBlocked(nip) || CheckLocalhostIP(nip) {
			blockedIPs = append(blockedIPs, nip)
		} else if nip == nil {
		} else {
			targets = append(targets, nip)
		}
	}

	if len(targets) == 0 && len(blockedIPs) > 0 {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_APPLICATION_ERROR,
			Err:    fmt.Errorf("IPs blocked for %v: %v", host, blockedIPs),
		}
	}
	if len(targets) == 0 {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_APPLICATION_ERROR,
			Err:    fmt.Errorf("no %v addresses for %v", network, host),
		}
	}
	return targets, nil
}
