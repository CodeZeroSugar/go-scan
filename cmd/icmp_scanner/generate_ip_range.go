package icmpscanner

import (
	"bytes"
	"net"
)

func GenerateIPRange(start, end net.IP) ([]net.IP, error) {
	var current net.IP
	var ipRange []net.IP
	current = start
	for bytes.Compare(current.To4(), end.To4()) <= 0 {
		ipRange = append(ipRange, current)
		result, err := incrementIP(current)
		if err != nil {
			return nil, err
		}
		current = result
	}

	return ipRange, nil
}
