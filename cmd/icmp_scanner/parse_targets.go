package icmpscanner

import (
	"fmt"
	"net"
	"strings"
)

func ParseTargets(input string) ([]net.IP, error) {
	splitInput := strings.Split(input, ",")
	for i := 0; i < len(splitInput); i++ {
		splitInput[i] = strings.TrimSpace(splitInput[i])
	}

	var start net.IP
	var end net.IP
	var scanIPs []net.IP

	for _, ipInput := range splitInput {
		_, ipNet, err := net.ParseCIDR(ipInput)
		if err == nil {
			start = ipNet.IP
			end = make(net.IP, len(ipNet.IP))
			copy(end, ipNet.IP)

			for i := range end {
				end[i] |= ^ipNet.Mask[i]
			}

		} else {
			start, end, err = ParseIPRange(ipInput)
			if err != nil {
				return nil, fmt.Errorf("unable to parse '%s': %w", input, err)
			}
		}

		if start == nil {
			scanIPs = append(scanIPs, end)
			continue
		}

		ipRange, err := GenerateIPRange(start, end)
		if err != nil {
			return nil, fmt.Errorf("failed to generate IP range from '%s' to '%s': %w", start, end, err)
		}

		scanIPs = append(scanIPs, ipRange...)
	}

	return scanIPs, nil
}
