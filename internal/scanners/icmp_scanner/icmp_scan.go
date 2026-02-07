package icmpscanner

import (
	"fmt"
	"net"
)

func DiscoveryScan(input string) ([]net.IP, error) {
	targets, err := ParseTargets(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse input for discovery scan: %w", err)
	}

	var hostsUp []net.IP

	for _, t := range targets {
		result, err := Ping(t)
		if err != nil {
			continue
		}
		if result {
			hostsUp = append(hostsUp, t)
		}
	}

	return hostsUp, nil
}
