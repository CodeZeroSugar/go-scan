package icmpscanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

func ParseIPRange(input string) (start, end net.IP, err error) {
	if !strings.Contains(input, "-") {
		ip := net.ParseIP(strings.TrimSpace(input))
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is an invalid IP", input)
		}
		return nil, ip, nil
	}
	splitIP := strings.SplitN(input, "-", 2)
	if len(splitIP) == 1 {
		ip := net.ParseIP(strings.TrimSpace(splitIP[0]))
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is an invalid IP", splitIP[0])
		}
		return nil, ip, nil
	}
	if len(splitIP) != 2 {
		return nil, nil, fmt.Errorf("invalid format for IP range")
	}
	left := strings.TrimSpace(splitIP[0])
	right := strings.TrimSpace(splitIP[1])

	start = net.ParseIP(left)
	if start == nil {
		return nil, nil, fmt.Errorf("'%s' is an invalid IP", start)
	}
	end = net.ParseIP(right)
	if end == nil {
		return nil, nil, fmt.Errorf("'%s' is an invalid IP", end)
	}
	if bytes.Compare(start, end) < 0 {
		return nil, nil, fmt.Errorf("start IP is after end IP")
	}
	return start, end, nil
}
